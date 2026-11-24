"""Thin subprocess client wrapping `mp-outpost` with OUTPOST_STATE_DIR & secret refusal."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

try:
    from .security import refuse_secrets, validate_safe_id
except ImportError:
    from security import refuse_secrets, validate_safe_id  # type: ignore[no-redef]


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
