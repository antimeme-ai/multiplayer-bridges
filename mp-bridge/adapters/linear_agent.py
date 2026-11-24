"""Linear Agents API adapter (`actor=app`, `AgentSessionEvent`, `AgentActivity`).

Verifies Linear's `Linear-Signature` HMAC-SHA256 webhook header, returns a fast
`< 5s` HTTP 200 acknowledgement payload, wraps untrusted Linear issue/comment
text in a CSPRNG nonce provenance fence before forwarding to a `multiplayer.tech`
party/board via `mp-outpost`, and formats typed `AgentActivity` GraphQL mutations
with mandatory outbound secret refusal.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional, Sequence

try:
    from ..outpost_client import OutpostClient
    from ..security import (
        format_untrusted_envelope,
        refuse_secrets,
        sanitize_untrusted_text,
        validate_safe_id,
        verify_hmac_sha256_hex,
    )
except ImportError:
    from outpost_client import OutpostClient  # type: ignore[no-redef]
    from security import (  # type: ignore[no-redef]
        format_untrusted_envelope,
        refuse_secrets,
        sanitize_untrusted_text,
        validate_safe_id,
        verify_hmac_sha256_hex,
    )

VALID_ACTIVITY_TYPES = frozenset({"thought", "action", "elicitation", "response", "error"})
MAX_WEBHOOK_SKEW_MS = 300_000  # 5 minutes


@dataclass(frozen=True)
class LinearAckResult:
    status_code: int
    ack_body: dict[str, Any]
    dispatched: bool
    fenced_message: Optional[str] = None
    reason: Optional[str] = None


class LinearAgentAdapter:
    """Bridges Linear `AgentSessionEvent` webhooks <-> `mp-outpost` party/board."""

    def __init__(
        self,
        *,
        webhook_secret: str,
        party_id: int,
        outpost: Optional[OutpostClient] = None,
        allowed_org_ids: Optional[Sequence[str]] = None,
        allowed_team_ids: Optional[Sequence[str]] = None,
        board_scope: str = "board/linear",
    ) -> None:
        if not webhook_secret:
            raise ValueError("webhook_secret must be non-empty")
        self._secret = webhook_secret.encode("utf-8")
        self.party_id = validate_safe_id(party_id, "party_id")
        self.outpost = outpost
        self.allowed_org_ids = frozenset(allowed_org_ids) if allowed_org_ids else None
        self.allowed_team_ids = frozenset(allowed_team_ids) if allowed_team_ids else None
        self.board_scope = board_scope

    def verify_signature(self, raw_body: bytes, signature_header: Optional[str]) -> bool:
        if not signature_header:
            return False
        return verify_hmac_sha256_hex(self._secret, raw_body, signature_header)

    def handle_webhook(
        self,
        raw_body: bytes,
        headers: dict[str, str],
        *,
        now_ms: Optional[int] = None,
    ) -> LinearAckResult:
        """Verify HMAC-SHA256, check allowlists, dispatch fenced event, and return fast ACK."""
        lower_headers = {k.lower(): v for k, v in headers.items()}
        sig = lower_headers.get("linear-signature")
        if not self.verify_signature(raw_body, sig):
            return LinearAckResult(
                status_code=401,
                ack_body={"ok": False, "error": "invalid_signature"},
                dispatched=False,
                reason="invalid_signature",
            )

        try:
            event = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return LinearAckResult(
                status_code=400,
                ack_body={"ok": False, "error": "invalid_json"},
                dispatched=False,
                reason="invalid_json",
            )

        if not isinstance(event, dict):
            return LinearAckResult(
                status_code=400,
                ack_body={"ok": False, "error": "invalid_payload"},
                dispatched=False,
                reason="invalid_payload",
            )

        # Replay-window check when webhookTimestamp (Unix ms) is supplied
        ts = event.get("webhookTimestamp")
        if ts is not None:
            if not isinstance(ts, int) or isinstance(ts, bool):
                return LinearAckResult(
                    status_code=400,
                    ack_body={"ok": False, "error": "invalid_timestamp"},
                    dispatched=False,
                    reason="invalid_timestamp",
                )
            cur_ms = now_ms if now_ms is not None else int(time.time() * 1000)
            if abs(cur_ms - ts) > MAX_WEBHOOK_SKEW_MS:
                return LinearAckResult(
                    status_code=401,
                    ack_body={"ok": False, "error": "stale_webhook"},
                    dispatched=False,
                    reason="stale_webhook",
                )

        org_id = str(event.get("organizationId") or "")
        if self.allowed_org_ids is not None and org_id not in self.allowed_org_ids:
            return LinearAckResult(
                status_code=403,
                ack_body={"ok": False, "error": "org_not_allowed"},
                dispatched=False,
                reason="org_not_allowed",
            )

        event_type = str(event.get("type") or "")
        action = str(event.get("action") or "")
        if event_type != "AgentSessionEvent":
            return LinearAckResult(
                status_code=200,
                ack_body={"ok": True, "ignored": True},
                dispatched=False,
                reason=f"ignored_type:{event_type}",
            )

        session = event.get("agentSession")
        if not isinstance(session, dict):
            return LinearAckResult(
                status_code=400,
                ack_body={"ok": False, "error": "missing_agent_session"},
                dispatched=False,
                reason="missing_agent_session",
            )

        issue = session.get("issue") if isinstance(session.get("issue"), dict) else {}
        team = issue.get("team") if isinstance(issue.get("team"), dict) else {}
        team_id = str(team.get("id") or issue.get("teamId") or "")
        if self.allowed_team_ids is not None and team_id not in self.allowed_team_ids:
            return LinearAckResult(
                status_code=403,
                ack_body={"ok": False, "error": "team_not_allowed"},
                dispatched=False,
                reason="team_not_allowed",
            )

        session_id = str(session.get("id") or "")
        issue_ident = str(issue.get("identifier") or "UNSPECIFIED")
        issue_title = str(issue.get("title") or "")
        comment = session.get("comment") if isinstance(session.get("comment"), dict) else {}
        prompt_text = str(comment.get("body") or issue.get("description") or issue_title)
        actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
        sender_name = str(actor.get("name") or actor.get("id") or "linear-user")

        body_lines = [
            f"Linear AgentSessionEvent ({action}) on {issue_ident}: {issue_title}".strip(),
        ]
        if prompt_text and prompt_text != issue_title:
            body_lines.append("")
            body_lines.append(prompt_text)

        fenced = format_untrusted_envelope(
            "\n".join(body_lines),
            source="linear",
            sender=sender_name,
            metadata={
                "action": action or "created",
                "issue": issue_ident,
                "session_id": session_id,
                "org_id": org_id,
            },
        )
        # Refuse accidentally leaked secrets even before touching mp-outpost
        refuse_secrets(fenced, context="linear inbound payload")

        if self.outpost is not None:
            res = self.outpost.party_say(self.party_id, fenced, scope=self.board_scope)
            if not res.ok:
                return LinearAckResult(
                    status_code=502,
                    ack_body={"ok": False, "error": "outpost_dispatch_failed"},
                    dispatched=False,
                    fenced_message=fenced,
                    reason="outpost_dispatch_failed",
                )

        return LinearAckResult(
            status_code=200,
            ack_body={"ok": True, "accepted": True, "session_id": session_id},
            dispatched=True,
            fenced_message=fenced,
        )

    @staticmethod
    def format_agent_activity(
        *,
        agent_session_id: str,
        activity_type: str,
        body: str,
        action_name: Optional[str] = None,
        parameter: Optional[str] = None,
        result_summary: Optional[str] = None,
        ephemeral: bool = False,
    ) -> dict[str, Any]:
        """Build a Linear `agentActivityCreate` GraphQL payload with strict secret refusal."""
        if not agent_session_id or not agent_session_id.strip():
            raise ValueError("agent_session_id must be non-empty")
        if activity_type not in VALID_ACTIVITY_TYPES:
            raise ValueError(f"activity_type must be one of {sorted(VALID_ACTIVITY_TYPES)}")

        refuse_secrets(body, context="linear agent activity body")
        if parameter:
            refuse_secrets(parameter, context="linear agent activity parameter")
        if result_summary:
            refuse_secrets(result_summary, context="linear agent activity result")

        content: dict[str, Any] = {"type": activity_type}
        if activity_type == "action":
            content["action"] = sanitize_untrusted_text(
                action_name or "tool", max_chars=128, single_line=True
            )
            content["parameter"] = (parameter or body)[:1024]
            if result_summary is not None:
                content["result"] = result_summary[:2048]
        else:
            content["body"] = body[:4096]

        return {
            "query": (
                "mutation AgentActivityCreate($input: AgentActivityCreateInput!) { "
                "agentActivityCreate(input: $input) { success } }"
            ),
            "variables": {
                "input": {
                    "agentSessionId": agent_session_id.strip(),
                    "content": content,
                    "ephemeral": bool(ephemeral),
                }
            },
        }
