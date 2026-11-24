"""Telegram Bot API `getUpdates` long-polling adapter (zero inbound firewall port).

Runs strictly outbound `getUpdates` long-polling with monotonic `offset` cursor
tracking, mandatory fail-closed `allowed_chat_ids` allowlist enforcement,
support for both text messages and inline-keyboard `callback_query` approvals,
CSPRNG nonce provenance fencing on ingress, and mandatory outbound secret
refusal on `sendMessage`.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

try:
    from ..outpost_client import OutpostClient
    from ..security import (
        SecretRefusalError,
        format_untrusted_envelope,
        refuse_secrets,
        validate_safe_id,
    )
except ImportError:
    from outpost_client import OutpostClient  # type: ignore[no-redef]
    from security import (  # type: ignore[no-redef]
        SecretRefusalError,
        format_untrusted_envelope,
        refuse_secrets,
        validate_safe_id,
    )


UpdatesFetcher = Callable[[int, int], list[dict[str, Any]]]
BOT_TOKEN_RE = re.compile(r"^[0-9]+:[A-Za-z0-9_-]{20,}$")


class TelegramPollError(RuntimeError):
    """Sanitized Telegram API error that NEVER embeds the bot token or request URL."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise TelegramPollError(f"Telegram API unexpected HTTP redirect ({code})")


@dataclass(frozen=True)
class TelegramPollSummary:
    next_offset: int
    accepted: int
    rejected_allowlist: int
    rejected_secrets: int
    ignored: int
    fenced_messages: tuple[str, ...]


class TelegramPollAdapter:
    """Long-polls Telegram `getUpdates` and bridges allowlisted chats <-> `mp-outpost`."""

    def __init__(
        self,
        *,
        bot_token: str,
        allowed_chat_ids: Sequence[int],
        party_id: int,
        outpost: Optional[OutpostClient] = None,
        board_scope: str = "party/main",
        fetcher: Optional[UpdatesFetcher] = None,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        if not isinstance(bot_token, str) or not BOT_TOKEN_RE.fullmatch(bot_token):
            raise ValueError(
                "bot_token must match strict Telegram token format (<digits>:<20+ [A-Za-z0-9_-]>)"
            )
        if not allowed_chat_ids:
            raise ValueError("allowed_chat_ids must be non-empty (fail-closed allowlist)")
        for cid in allowed_chat_ids:
            if isinstance(cid, bool) or not isinstance(cid, int):
                raise ValueError("allowed_chat_ids must contain integer chat IDs")
        self._bot_token = bot_token
        self.allowed_chat_ids = frozenset(allowed_chat_ids)
        self.party_id = validate_safe_id(party_id, "party_id")
        self.outpost = outpost
        self.board_scope = board_scope
        self.offset = 0
        self._opener = opener or urllib.request.build_opener(_NoRedirectHandler())
        self._fetcher = fetcher or self._http_get_updates

    def _http_get_updates(self, offset: int, timeout_sec: int) -> list[dict[str, Any]]:
        clamped = max(1, min(int(timeout_sec), 50))
        safe_offset = max(0, int(offset))
        url = (
            f"https://api.telegram.org/bot{self._bot_token}/getUpdates"
            f"?offset={safe_offset}&timeout={clamped}"
        )
        req = urllib.request.Request(url, method="GET")
        try:
            with self._opener.open(req, timeout=clamped + 10) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except TelegramPollError:
            raise
        except urllib.error.HTTPError as exc:
            raise TelegramPollError(f"Telegram getUpdates HTTP error ({exc.code})") from None
        except urllib.error.URLError as exc:
            reason = str(exc.reason).replace(self._bot_token, "[REDACTED]")
            raise TelegramPollError(f"Telegram getUpdates transport error: {reason}") from None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            detail = str(exc).replace(self._bot_token, "[REDACTED]")
            raise TelegramPollError(f"Telegram getUpdates failed: {detail}") from None
        if not isinstance(payload, dict) or not payload.get("ok"):
            return []
        result = payload.get("result")
        return result if isinstance(result, list) else []

    def poll_once(self, *, timeout_sec: int = 25) -> TelegramPollSummary:
        """Fetch one batch of updates, advance cursor monotonically, and bridge allowed items."""
        updates = self._fetcher(self.offset, timeout_sec)
        return self.process_updates(updates)

    def process_updates(self, updates: Sequence[dict[str, Any]]) -> TelegramPollSummary:
        accepted = 0
        rejected = 0
        rejected_secrets = 0
        ignored = 0
        fenced_list: list[str] = []

        for upd in updates:
            if not isinstance(upd, dict):
                ignored += 1
                continue
            uid = upd.get("update_id")
            if isinstance(uid, int) and not isinstance(uid, bool) and uid >= self.offset:
                self.offset = uid + 1

            extracted = self._extract_message(upd)
            if extracted is None:
                ignored += 1
                continue

            chat_id, sender, text, kind = extracted
            if chat_id not in self.allowed_chat_ids:
                rejected += 1
                continue

            fenced = format_untrusted_envelope(
                text,
                source="telegram",
                sender=sender,
                metadata={
                    "chat_id": str(chat_id),
                    "kind": kind,
                    "update_id": str(uid) if isinstance(uid, int) else "",
                },
            )
            try:
                refuse_secrets(fenced, context="telegram inbound message")
            except SecretRefusalError:
                rejected_secrets += 1
                continue

            if self.outpost is not None:
                try:
                    res = self.outpost.party_say(self.party_id, fenced, scope=self.board_scope)
                except SecretRefusalError:
                    rejected_secrets += 1
                    continue
                if not res.ok:
                    ignored += 1
                    continue

            accepted += 1
            fenced_list.append(fenced)

        return TelegramPollSummary(
            next_offset=self.offset,
            accepted=accepted,
            rejected_allowlist=rejected,
            rejected_secrets=rejected_secrets,
            ignored=ignored,
            fenced_messages=tuple(fenced_list),
        )

    @staticmethod
    def _extract_message(upd: dict[str, Any]) -> Optional[tuple[int, str, str, str]]:
        msg = upd.get("message")
        if isinstance(msg, dict):
            chat = msg.get("chat")
            text = msg.get("text")
            if isinstance(chat, dict) and isinstance(chat.get("id"), int) and not isinstance(chat.get("id"), bool):
                if isinstance(text, str) and text.strip():
                    sender_obj = msg.get("from") if isinstance(msg.get("from"), dict) else {}
                    sender = str(sender_obj.get("username") or sender_obj.get("id") or "telegram-user")
                    return (chat["id"], sender, text.strip(), "message")
        cb = upd.get("callback_query")
        if isinstance(cb, dict):
            cb_msg = cb.get("message") if isinstance(cb.get("message"), dict) else {}
            chat = cb_msg.get("chat") if isinstance(cb_msg.get("chat"), dict) else {}
            data = cb.get("data")
            if isinstance(chat.get("id"), int) and not isinstance(chat.get("id"), bool):
                if isinstance(data, str) and data.strip():
                    sender_obj = cb.get("from") if isinstance(cb.get("from"), dict) else {}
                    sender = str(sender_obj.get("username") or sender_obj.get("id") or "telegram-user")
                    return (chat["id"], sender, f"[callback] {data.strip()}", "callback_query")
        return None

    def format_send_message(
        self,
        *,
        chat_id: int,
        text: str,
        inline_buttons: Optional[Sequence[tuple[str, str]]] = None,
    ) -> dict[str, Any]:
        """Format a Telegram `sendMessage` request for an allowlisted chat with secret refusal."""
        if chat_id not in self.allowed_chat_ids:
            raise PermissionError(f"chat_id {chat_id} is not in allowed_chat_ids")
        refuse_secrets(text, context="telegram outbound message")
        body: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:4000],
        }
        if inline_buttons:
            body["reply_markup"] = {
                "inline_keyboard": [
                    [{"text": label[:64], "callback_data": cb_data[:64]} for label, cb_data in inline_buttons]
                ]
            }
        return {"method": "sendMessage", "body": body}
