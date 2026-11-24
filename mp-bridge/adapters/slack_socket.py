"""Slack AI Apps & Socket Mode adapter (`assistant_thread_started`, `app_mention`, `setStatus`).

Handles Socket Mode envelopes (zero public inbound port) and optional Events API
HTTP signature checks (`X-Slack-Signature: v0=...` + `X-Slack-Request-Timestamp`),
enforces channel/user allowlists, fences untrusted Slack messages with CSPRNG
nonces before forwarding to `mp-outpost`, and formats native AI App API calls
(`assistant.threads.setStatus`, `assistant.threads.setSuggestedPrompts`,
`chat.postMessage`) with mandatory outbound secret refusal.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional, Sequence

try:
    from ..outpost_client import OutpostClient
    from ..security import (
        format_untrusted_envelope,
        refuse_secrets,
        validate_safe_id,
        verify_hmac_sha256_hex,
    )
except ImportError:
    from outpost_client import OutpostClient  # type: ignore[no-redef]
    from security import (  # type: ignore[no-redef]
        format_untrusted_envelope,
        refuse_secrets,
        validate_safe_id,
        verify_hmac_sha256_hex,
    )

MAX_SLACK_SKEW_SEC = 300
DEFAULT_SUGGESTED_PROMPTS: tuple[dict[str, str], ...] = (
    {"title": "Check party status", "message": "Check active multiplayer.tech party status and connected peers."},
    {"title": "Summarize failing CI", "message": "Summarize the latest CI build or test handoff on the party board."},
    {"title": "Triage latest inbox item", "message": "Read the latest unread party board updates and propose next steps."},
)


@dataclass(frozen=True)
class SlackEnvelopeOutcome:
    ack_payload: dict[str, Any]
    event_type: str
    dispatched: bool
    api_actions: tuple[dict[str, Any], ...] = ()
    fenced_message: Optional[str] = None
    reason: Optional[str] = None


class SlackSocketAdapter:
    """Bridges Slack Socket Mode / AI App events <-> `mp-outpost` party/board."""

    def __init__(
        self,
        *,
        party_id: int,
        signing_secret: Optional[str] = None,
        outpost: Optional[OutpostClient] = None,
        allowed_channels: Optional[Sequence[str]] = None,
        allowed_users: Optional[Sequence[str]] = None,
        board_scope: str = "party/main",
    ) -> None:
        self.party_id = validate_safe_id(party_id, "party_id")
        self._signing_secret = signing_secret.encode("utf-8") if signing_secret else None
        self.outpost = outpost
        self.allowed_channels = frozenset(allowed_channels) if allowed_channels else None
        self.allowed_users = frozenset(allowed_users) if allowed_users else None
        self.board_scope = board_scope

    def verify_http_signature(
        self,
        raw_body: bytes,
        timestamp_header: Optional[str],
        signature_header: Optional[str],
        *,
        now_sec: Optional[int] = None,
    ) -> bool:
        """Verify Slack `v0=` HMAC-SHA256 signature with 5-minute replay protection."""
        if not self._signing_secret or not timestamp_header or not signature_header:
            return False
        if not signature_header.startswith("v0="):
            return False
        try:
            ts = int(timestamp_header.strip())
        except ValueError:
            return False
        cur = now_sec if now_sec is not None else int(time.time())
        if abs(cur - ts) > MAX_SLACK_SKEW_SEC:
            return False
        basestring = f"v0:{ts}:".encode("utf-8") + raw_body
        return verify_hmac_sha256_hex(self._signing_secret, basestring, signature_header[3:])

    def handle_socket_envelope(self, envelope: dict[str, Any]) -> SlackEnvelopeOutcome:
        """Parse a Slack Socket Mode envelope and produce ACK + actions + fenced party post."""
        envelope_id = str(envelope.get("envelope_id") or "")
        ack = {"envelope_id": envelope_id} if envelope_id else {}
        env_type = str(envelope.get("type") or "")
        if env_type != "events_api":
            return SlackEnvelopeOutcome(
                ack_payload=ack,
                event_type=env_type or "unknown",
                dispatched=False,
                reason="non_events_api_envelope",
            )

        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return SlackEnvelopeOutcome(
                ack_payload=ack,
                event_type="invalid",
                dispatched=False,
                reason="missing_payload",
            )
        event = payload.get("event")
        if not isinstance(event, dict):
            return SlackEnvelopeOutcome(
                ack_payload=ack,
                event_type="invalid",
                dispatched=False,
                reason="missing_event",
            )

        # Never loop on bot messages
        if event.get("bot_id") or event.get("subtype") == "bot_message":
            return SlackEnvelopeOutcome(
                ack_payload=ack,
                event_type=str(event.get("type") or ""),
                dispatched=False,
                reason="ignored_bot_message",
            )

        ev_type = str(event.get("type") or "")

        if ev_type == "assistant_thread_started":
            thread = event.get("assistant_thread")
            if not isinstance(thread, dict):
                return SlackEnvelopeOutcome(
                    ack_payload=ack,
                    event_type=ev_type,
                    dispatched=False,
                    reason="missing_assistant_thread",
                )
            channel_id = str(thread.get("channel_id") or "")
            thread_ts = str(thread.get("thread_ts") or "")
            user_id = str(thread.get("user_id") or "")
            if not self._is_allowed(channel_id, user_id):
                return SlackEnvelopeOutcome(
                    ack_payload=ack,
                    event_type=ev_type,
                    dispatched=False,
                    reason="not_in_allowlist",
                )
            prompts_req = self.format_suggested_prompts(channel_id=channel_id, thread_ts=thread_ts)
            return SlackEnvelopeOutcome(
                ack_payload=ack,
                event_type=ev_type,
                dispatched=False,
                api_actions=(prompts_req,),
            )

        if ev_type in ("app_mention", "message"):
            channel_id = str(event.get("channel") or "")
            user_id = str(event.get("user") or "")
            thread_ts = str(event.get("thread_ts") or event.get("ts") or "")
            text = str(event.get("text") or "").strip()

            if not self._is_allowed(channel_id, user_id):
                return SlackEnvelopeOutcome(
                    ack_payload=ack,
                    event_type=ev_type,
                    dispatched=False,
                    reason="not_in_allowlist",
                )
            if not text:
                return SlackEnvelopeOutcome(
                    ack_payload=ack,
                    event_type=ev_type,
                    dispatched=False,
                    reason="empty_text",
                )

            fenced = format_untrusted_envelope(
                text,
                source="slack",
                sender=user_id or "slack-user",
                metadata={
                    "channel_id": channel_id,
                    "thread_ts": thread_ts,
                    "event_type": ev_type,
                },
            )
            refuse_secrets(fenced, context="slack inbound message")

            status_thinking = self.format_set_status(
                channel_id=channel_id,
                thread_ts=thread_ts,
                status="is forwarding to multiplayer.tech party...",
            )

            if self.outpost is not None:
                res = self.outpost.party_say(self.party_id, fenced, scope=self.board_scope)
                if not res.ok:
                    clear_status = self.format_set_status(
                        channel_id=channel_id,
                        thread_ts=thread_ts,
                        status="",
                    )
                    return SlackEnvelopeOutcome(
                        ack_payload=ack,
                        event_type=ev_type,
                        dispatched=False,
                        api_actions=(status_thinking, clear_status),
                        fenced_message=fenced,
                        reason="outpost_dispatch_failed",
                    )

            return SlackEnvelopeOutcome(
                ack_payload=ack,
                event_type=ev_type,
                dispatched=True,
                api_actions=(status_thinking,),
                fenced_message=fenced,
            )

        return SlackEnvelopeOutcome(
            ack_payload=ack,
            event_type=ev_type,
            dispatched=False,
            reason=f"unsupported_event:{ev_type}",
        )

    def _is_allowed(self, channel_id: str, user_id: str) -> bool:
        if self.allowed_channels is not None and channel_id not in self.allowed_channels:
            return False
        if self.allowed_users is not None and user_id not in self.allowed_users:
            return False
        return True

    @staticmethod
    def format_set_status(
        *,
        channel_id: str,
        thread_ts: str,
        status: str,
    ) -> dict[str, Any]:
        """Format `assistant.threads.setStatus` (pass status='' to explicitly clear on error)."""
        if status:
            refuse_secrets(status, context="slack assistant status")
        return {
            "method": "assistant.threads.setStatus",
            "body": {
                "channel_id": channel_id,
                "thread_ts": thread_ts,
                "status": status[:128],
            },
        }

    @staticmethod
    def format_suggested_prompts(
        *,
        channel_id: str,
        thread_ts: str,
        prompts: Sequence[dict[str, str]] = DEFAULT_SUGGESTED_PROMPTS,
    ) -> dict[str, Any]:
        return {
            "method": "assistant.threads.setSuggestedPrompts",
            "body": {
                "channel_id": channel_id,
                "thread_ts": thread_ts,
                "prompts": [
                    {"title": p["title"][:64], "message": refuse_secrets(p["message"], context="slack prompt")[:512]}
                    for p in prompts
                ],
            },
        }

    @staticmethod
    def format_post_message(
        *,
        channel_id: str,
        text: str,
        thread_ts: Optional[str] = None,
    ) -> dict[str, Any]:
        refuse_secrets(text, context="slack outbound message")
        body: dict[str, Any] = {
            "channel": channel_id,
            "text": text[:3900],
        }
        if thread_ts:
            body["thread_ts"] = thread_ts
        return {"method": "chat.postMessage", "body": body}
