"""Discord Interactions adapter (Ed25519 signature verifier + slash command dispatcher).

Verifies Discord's `X-Signature-Ed25519` and `X-Signature-Timestamp` headers
using strict pure-stdlib RFC 8032 Ed25519 verification with replay window checks,
responds to PING (type 1) with PONG (type 1), enforces guild/channel/user
allowlists, dispatches `/party-status`, `/party-say`, and `/blackbird` slash
commands with CSPRNG nonce fencing, and refuses outbound secrets.
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
        validate_safe_id,
        verify_ed25519,
    )
except ImportError:
    from outpost_client import OutpostClient  # type: ignore[no-redef]
    from security import (  # type: ignore[no-redef]
        format_untrusted_envelope,
        refuse_secrets,
        validate_safe_id,
        verify_ed25519,
    )

INTERACTION_PING = 1
INTERACTION_APPLICATION_COMMAND = 2
RESPONSE_PONG = 1
RESPONSE_CHANNEL_MESSAGE = 4
RESPONSE_DEFERRED_CHANNEL_MESSAGE = 5
MAX_DISCORD_SKEW_SEC = 300


@dataclass(frozen=True)
class DiscordInteractionResponse:
    status_code: int
    body: dict[str, Any]
    dispatched: bool = False
    fenced_message: Optional[str] = None
    reason: Optional[str] = None


class DiscordInteractionsAdapter:
    """Verifies Discord Ed25519 interactions and dispatches allowlisted slash commands."""

    def __init__(
        self,
        *,
        public_key_hex: str,
        party_id: int,
        outpost: Optional[OutpostClient] = None,
        allowed_guild_ids: Optional[Sequence[str]] = None,
        allowed_channel_ids: Optional[Sequence[str]] = None,
        allowed_user_ids: Optional[Sequence[str]] = None,
        board_scope: str = "party/main",
    ) -> None:
        try:
            pk = bytes.fromhex(public_key_hex.strip())
        except ValueError as exc:
            raise ValueError("public_key_hex must be 64 hex chars (32-byte Ed25519 key)") from exc
        if len(pk) != 32:
            raise ValueError("public_key_hex must decode to exactly 32 bytes")
        self._public_key = pk
        self.party_id = validate_safe_id(party_id, "party_id")
        self.outpost = outpost
        self.allowed_guild_ids = frozenset(allowed_guild_ids) if allowed_guild_ids else None
        self.allowed_channel_ids = frozenset(allowed_channel_ids) if allowed_channel_ids else None
        self.allowed_user_ids = frozenset(allowed_user_ids) if allowed_user_ids else None
        self.board_scope = board_scope

    def verify_request(
        self,
        raw_body: bytes,
        timestamp_header: Optional[str],
        signature_hex: Optional[str],
        *,
        now_sec: Optional[int] = None,
    ) -> bool:
        """Verify Discord Ed25519 signature over `timestamp + raw_body` + replay window."""
        if not timestamp_header or not signature_hex:
            return False
        ts_str = timestamp_header.strip()
        try:
            ts = int(ts_str)
            sig = bytes.fromhex(signature_hex.strip())
        except ValueError:
            return False
        if len(sig) != 64:
            return False
        cur = now_sec if now_sec is not None else int(time.time())
        if abs(cur - ts) > MAX_DISCORD_SKEW_SEC:
            return False
        return verify_ed25519(self._public_key, ts_str.encode("utf-8") + raw_body, sig)

    def handle_interaction(
        self,
        raw_body: bytes,
        headers: dict[str, str],
        *,
        now_sec: Optional[int] = None,
    ) -> DiscordInteractionResponse:
        lower = {k.lower(): v for k, v in headers.items()}
        if not self.verify_request(
            raw_body,
            lower.get("x-signature-timestamp"),
            lower.get("x-signature-ed25519"),
            now_sec=now_sec,
        ):
            return DiscordInteractionResponse(
                status_code=401,
                body={"error": "invalid_request_signature"},
                reason="invalid_signature",
            )

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return DiscordInteractionResponse(
                status_code=400,
                body={"error": "invalid_json"},
                reason="invalid_json",
            )
        if not isinstance(payload, dict):
            return DiscordInteractionResponse(
                status_code=400,
                body={"error": "invalid_payload"},
                reason="invalid_payload",
            )

        itype = payload.get("type")
        if itype == INTERACTION_PING:
            return DiscordInteractionResponse(status_code=200, body={"type": RESPONSE_PONG})

        if itype != INTERACTION_APPLICATION_COMMAND:
            return DiscordInteractionResponse(
                status_code=400,
                body={"error": "unsupported_interaction_type"},
                reason=f"unsupported_type:{itype}",
            )

        guild_id = str(payload.get("guild_id") or "")
        channel_id = str(payload.get("channel_id") or "")
        member = payload.get("member") if isinstance(payload.get("member"), dict) else {}
        user = member.get("user") if isinstance(member.get("user"), dict) else (
            payload.get("user") if isinstance(payload.get("user"), dict) else {}
        )
        user_id = str(user.get("id") or "")
        username = str(user.get("username") or user_id or "discord-user")

        if self.allowed_guild_ids is not None and guild_id not in self.allowed_guild_ids:
            return DiscordInteractionResponse(
                status_code=403,
                body={"error": "guild_not_allowed"},
                reason="guild_not_allowed",
            )
        if self.allowed_channel_ids is not None and channel_id not in self.allowed_channel_ids:
            return DiscordInteractionResponse(
                status_code=403,
                body={"error": "channel_not_allowed"},
                reason="channel_not_allowed",
            )
        if self.allowed_user_ids is not None and user_id not in self.allowed_user_ids:
            return DiscordInteractionResponse(
                status_code=403,
                body={"error": "user_not_allowed"},
                reason="user_not_allowed",
            )

        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        cmd_name = str(data.get("name") or "")
        options = data.get("options") if isinstance(data.get("options"), list) else []
        opt_map = {
            str(opt.get("name")): str(opt.get("value"))
            for opt in options
            if isinstance(opt, dict) and "name" in opt and "value" in opt
        }

        if cmd_name == "party-status":
            if self.outpost is not None:
                st = self.outpost.party_status()
                summary = (
                    f"Party {self.party_id} status fetched (ok={st.ok})."
                    if st.ok
                    else "Outpost daemon unavailable; check local mp-outpost status."
                )
            else:
                summary = f"Deferred party status check for party {self.party_id}."
            return DiscordInteractionResponse(
                status_code=200,
                body=self.format_ephemeral_response(summary),
                dispatched=False,
            )

        if cmd_name in ("party-say", "blackbird"):
            raw_text = opt_map.get("message") or opt_map.get("prompt") or ""
            raw_text = raw_text.strip()
            if not raw_text:
                return DiscordInteractionResponse(
                    status_code=200,
                    body=self.format_ephemeral_response("Provide a non-empty message/prompt option."),
                    dispatched=False,
                    reason="empty_message",
                )

            fenced = format_untrusted_envelope(
                raw_text,
                source="discord",
                sender=username,
                metadata={
                    "command": cmd_name,
                    "guild_id": guild_id,
                    "channel_id": channel_id,
                    "user_id": user_id,
                },
            )
            refuse_secrets(fenced, context="discord slash command")

            if self.outpost is not None:
                res = self.outpost.party_say(self.party_id, fenced, scope=self.board_scope)
                if not res.ok:
                    return DiscordInteractionResponse(
                        status_code=200,
                        body=self.format_ephemeral_response("Failed to deliver message to mp-outpost."),
                        dispatched=False,
                        fenced_message=fenced,
                        reason="outpost_dispatch_failed",
                    )

            return DiscordInteractionResponse(
                status_code=200,
                body={"type": RESPONSE_DEFERRED_CHANNEL_MESSAGE, "data": {"flags": 64}},
                dispatched=True,
                fenced_message=fenced,
            )

        return DiscordInteractionResponse(
            status_code=200,
            body=self.format_ephemeral_response(f"Unknown slash command: {cmd_name}"),
            dispatched=False,
            reason=f"unknown_command:{cmd_name}",
        )

    @staticmethod
    def format_ephemeral_response(content: str) -> dict[str, Any]:
        refuse_secrets(content, context="discord response")
        return {
            "type": RESPONSE_CHANNEL_MESSAGE,
            "data": {
                "content": content[:1900],
                "flags": 64,  # Ephemeral
            },
        }

    @staticmethod
    def format_followup_message(content: str, *, ephemeral: bool = False) -> dict[str, Any]:
        refuse_secrets(content, context="discord follow-up")
        body: dict[str, Any] = {"content": content[:1900]}
        if ephemeral:
            body["flags"] = 64
        return body
