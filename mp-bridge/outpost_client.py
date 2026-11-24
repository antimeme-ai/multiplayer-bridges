"""Thin subprocess client wrapping `mp-outpost` with OUTPOST_STATE_DIR & secret refusal.

Supports both Xbox Live 1-verb `mp2` room commands (`join`, `invite`, `leave`,
`friends`, `add`) and backward-compatible `v0.4.0` `party` subcommands
(`party_say`, `party_read`, `party_wait`, `party_list`, `party_status`), plus
structured `agent_card` formatting.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence, Union

try:
    from .security import format_agent_card, refuse_secrets, validate_safe_id
except ImportError:
    from security import format_agent_card, refuse_secrets, validate_safe_id  # type: ignore[no-redef]


HANDLE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$")
# Room codes exclude visually ambiguous 0, O, 1, I, L (ROOM_PROTOCOL_V2.md §2).
ROOM_CODE_RE = re.compile(r"^[A-HJ-NP-Z2-9]{4}$")
ALLOWED_ROOM_HOSTS = frozenset({"clank.party", "multiplayer.tech", "mp.gg"})


def validate_handle(raw: str) -> str:
    """Validate and normalize a `@handle` (refusing CLI flag injection and secrets)."""
    if not isinstance(raw, str):
        raise ValueError("handle must be a string")
    s = raw.strip()
    if not s or s.startswith("-"):
        raise ValueError("handle must not be empty or start with '-'")
    refuse_secrets(s, context="handle")
    bare = s[1:] if s.startswith("@") else s
    if not HANDLE_RE.fullmatch(bare):
        raise ValueError("handle must be 3..32 ASCII chars starting with [a-z0-9] and using [a-z0-9_-]")
    return f"@{bare.lower()}"


def validate_room_target(target: Union[str, int, None]) -> str:
    """Validate a universal `mp-outpost join` target:
    - empty / None (accept latest pending invite)
    - `@handle`
    - 4-char `room_code` (A-Z, 2-9 excluding 0/O/1/I/L)
    - `clank.party/<CODE>`, `multiplayer.tech/@<handle>|/p/<CODE>`, `mp.gg/@<handle>|/p/<CODE>` (with or without `https://`)
    - positive 52-bit safe integer `party_id`
    Refuses CLI flags (`-...`), untrusted hosts, path traversal, query/fragment, and secrets.
    """
    if target is None:
        return ""
    if isinstance(target, int) and not isinstance(target, bool):
        return str(validate_safe_id(target, "party_id"))
    if not isinstance(target, str):
        raise ValueError("room target must be a string, integer, or None")

    s = target.strip()
    if s == "":
        return ""
    if s.startswith("-") or any(ch.isspace() or ord(ch) < 0x20 for ch in s):
        raise ValueError("room target must not start with '-' or contain whitespace/control chars")
    refuse_secrets(s, context="room target")

    # 1. @handle
    if s.startswith("@"):
        return validate_handle(s)

    # 2. Numeric party_id
    if s.isdigit():
        return str(validate_safe_id(int(s), "party_id"))

    # 3. Bare 4-char room code
    if len(s) == 4:
        upper = s.upper()
        if ROOM_CODE_RE.fullmatch(upper):
            return upper
        raise ValueError("4-character room_code must use A-Z / 2-9 excluding 0, O, 1, I, L")

    # 4. Short or full URL (`clank.party/CODE`, `multiplayer.tech/@handle`, `mp.gg/...`)
    candidate = s if "://" in s else f"https://{s}"
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port is not None:
        raise ValueError("room URL must be plain https:// without userinfo or custom port")
    if parsed.query or parsed.fragment:
        raise ValueError("room URL must not include query parameters or fragments")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_ROOM_HOSTS:
        raise ValueError(f"unsupported room host {host!r}; expected one of {sorted(ALLOWED_ROOM_HOSTS)}")
    raw_path = parsed.path
    if ".." in raw_path or "\\" in raw_path or "//" in raw_path:
        raise ValueError("room URL path must not contain traversal or duplicate slashes")
    parts = [p for p in raw_path.split("/") if p]
    if host == "clank.party":
        if len(parts) == 1 and ROOM_CODE_RE.fullmatch(parts[0].upper()):
            return f"https://clank.party/{parts[0].upper()}"
        if len(parts) == 1 and parts[0].startswith("@"):
            return f"https://clank.party/{validate_handle(parts[0])}"
        raise ValueError("clank.party URL must be clank.party/<4-char-CODE> or clank.party/@handle")

    if len(parts) == 1 and parts[0].startswith("@"):
        return f"https://{host}/{validate_handle(parts[0])}"
    if len(parts) == 2 and parts[0] == "p" and ROOM_CODE_RE.fullmatch(parts[1].upper()):
        return f"https://{host}/p/{parts[1].upper()}"
    raise ValueError(f"{host} URL must be {host}/@handle or {host}/p/<4-char-CODE>")


CommandRunner = Callable[[Sequence[str], dict[str, str], float], subprocess.CompletedProcess[str]]


def _default_runner(
    cmd: Sequence[str],
    env: dict[str, str],
    timeout_sec: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )


@dataclass(frozen=True)
class OutpostResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    data: Optional[dict[str, Any]] = None


class OutpostClient:
    """Executes `mp-outpost` CLI commands without ever passing secrets on argv."""

    def __init__(
        self,
        *,
        binary: str = "mp-outpost",
        state_dir: Optional[str] = None,
        timeout_sec: float = 30.0,
        runner: CommandRunner = _default_runner,
    ) -> None:
        self.binary = binary
        self.state_dir = state_dir
        self.timeout_sec = timeout_sec
        self._runner = runner

    def _build_env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.state_dir:
            env["OUTPOST_STATE_DIR"] = self.state_dir
        return env

    def _base_cmd(self) -> list[str]:
        cmd = [self.binary]
        if self.state_dir:
            cmd.extend(["--state-dir", self.state_dir])
        cmd.append("--json")
        return cmd

    def _run(self, args: Sequence[str], *, timeout_sec: Optional[float] = None) -> OutpostResult:
        cmd = [*self._base_cmd(), *args]
        proc = self._runner(cmd, self._build_env(), timeout_sec or self.timeout_sec)
        parsed: Optional[dict[str, Any]] = None
        if proc.stdout.strip():
            try:
                obj = json.loads(proc.stdout)
                if isinstance(obj, dict):
                    parsed = obj
            except json.JSONDecodeError:
                parsed = None
        return OutpostResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            data=parsed,
        )

    def daemon_status(self) -> OutpostResult:
        return self._run(["daemon", "status"])

    # -----------------------------------------------------------------------
    # Xbox Live 1-Verb `mp2` Helpers (`join`, `invite`, `leave`, `friends`, `add`)
    # -----------------------------------------------------------------------
    def join(self, target: Union[str, int, None] = None) -> OutpostResult:
        """Join a room by `@handle`, 4-char code, `clank.party/CODE`, URL, `party_id`, or latest invite."""
        resolved = validate_room_target(target)
        args = ["join"] if not resolved else ["join", resolved]
        return self._run(args)

    def invite(self, handle: Optional[str] = None, *, name: Optional[str] = None) -> OutpostResult:
        """Invite `@handle` (or return a share link + 4-char code if `handle` is omitted)."""
        args = ["invite"]
        if handle is not None and handle.strip():
            args.append(validate_handle(handle))
        if name is not None and name.strip():
            clean_name = name.strip()
            if clean_name.startswith("-") or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in clean_name):
                raise ValueError("room name must not start with '-' or contain control chars")
            refuse_secrets(clean_name, context="room name")
            args.extend(["--name", clean_name[:80]])
        return self._run(args)

    def leave(self) -> OutpostResult:
        """Leave the active room cleanly."""
        return self._run(["leave"])

    def friends_live(self) -> OutpostResult:
        """Return live Xbox Live friends roster & pending invites."""
        return self._run(["friends"])

    def add_friend(self, handle: str) -> OutpostResult:
        """Send or accept a friend request by `@handle`."""
        return self._run(["add", validate_handle(handle)])

    def post_agent_card(
        self,
        party_id: int,
        *,
        title: str,
        summary: str,
        files: Optional[Sequence[str]] = None,
        status: Optional[str] = None,
        url: Optional[str] = None,
        scope: str = "party/main",
    ) -> OutpostResult:
        """Format and send a compact secret-checked `mp2` `agent_card` payload."""
        card_json = format_agent_card(
            title=title,
            summary=summary,
            files=files,
            status=status,
            url=url,
        )
        return self.party_say(party_id, card_json, scope=scope)

    # -----------------------------------------------------------------------
    # Backward-Compatible `v0.4.0` Party Commands
    # -----------------------------------------------------------------------
    def party_list(self) -> OutpostResult:
        return self._run(["party", "list"])

    def party_status(self) -> OutpostResult:
        return self._run(["party", "status"])

    def party_say(self, party_id: int, text: str, *, scope: str = "party/main") -> OutpostResult:
        pid = validate_safe_id(party_id, "party_id")
        if text in ("--scope", "--to-device") or text.strip() in ("--scope", "--to-device"):
            raise ValueError("party_say message cannot be a bare mp-outpost CLI flag (--scope / --to-device)")
        refuse_secrets(text, context="party_say message")
        refuse_secrets(scope, context="party_say scope")
        return self._run(["party", "say", str(pid), "--scope", scope, text])

    def party_read(self, party_id: int, *, after_seq: int = 0, limit: int = 50) -> OutpostResult:
        pid = validate_safe_id(party_id, "party_id")
        if after_seq < 0:
            raise ValueError("after_seq must be >= 0")
        clamped_limit = max(1, min(limit, 200))
        return self._run(
            ["party", "read", str(pid), "--after-seq", str(after_seq), "--limit", str(clamped_limit)]
        )

    def party_wait(
        self,
        party_id: int,
        *,
        after_seq: int = 0,
        timeout_ms: int = 25_000,
    ) -> OutpostResult:
        pid = validate_safe_id(party_id, "party_id")
        if after_seq < 0:
            raise ValueError("after_seq must be >= 0")
        clamped_ms = max(1000, min(timeout_ms, 45_000))
        return self._run(
            [
                "party",
                "wait",
                str(pid),
                "--after-seq",
                str(after_seq),
                "--timeout-ms",
                str(clamped_ms),
            ],
            timeout_sec=(clamped_ms / 1000.0) + 15.0,
        )
