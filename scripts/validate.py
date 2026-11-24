#!/usr/bin/env python3
"""Automated repository validator for multiplayer-bridges.

Validates:
- YAML syntax & GitHub Actions shell-injection hygiene (`actions/outpost-notify/action.yml`).
- Zellij KDL layout syntax balance (`multiplexers/zellij/blackbird-cockpit.kdl`).
- POSIX shell syntax (`sh -n`) across all `.sh` / `.tmux` scripts.
- Python bytecode compilation (`py_compile`) across all `.py` files.
- Pinned `v0.3.0` SHA-256 format & target completeness in `notify.py`.
- Zero hardcoded real secrets or personal filesystem paths across non-test files.
- Full `python3 -m unittest discover -s tests -v` pass.
"""

from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_action_yaml() -> None:
    action_path = ROOT / "actions" / "outpost-notify" / "action.yml"
    text = action_path.read_text(encoding="utf-8")
    for required in ("name:", "description:", "inputs:", "runs:", 'using: "composite"', "MP_PARTY_ID:"):
        assert required in text, f"action.yml missing required field {required}"
    # Ensure no untrusted ${{ inputs.* }} interpolation appears inside a `run:` block
    in_run = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("run:"):
            in_run = True
            continue
        if in_run and line and not line.startswith(" "):
            in_run = False
        if in_run and "${{ inputs." in line:
            raise AssertionError(f"Unsafe direct inputs interpolation in action.yml run block: {line}")
    # Optional PyYAML check if installed
    try:
        import yaml  # type: ignore

        parsed = yaml.safe_load(text)
        assert isinstance(parsed, dict) and parsed.get("runs", {}).get("using") == "composite"
    except ImportError:
        pass


def check_kdl() -> None:
    kdl_path = ROOT / "multiplexers" / "zellij" / "blackbird-cockpit.kdl"
    text = kdl_path.read_text(encoding="utf-8")
    depth = 0
    in_str = False
    escaped = False
    for line in text.splitlines():
        if line.strip().startswith("//"):
            continue
        for ch in line:
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_str:
                escaped = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if not in_str:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    assert depth >= 0, "Unbalanced '}' in blackbird-cockpit.kdl"
    assert not in_str, "Unterminated string in blackbird-cockpit.kdl"
    assert depth == 0, f"Unbalanced braces in blackbird-cockpit.kdl (depth={depth})"
    assert "layout {" in text and 'command "blackbird"' in text


def check_shell_scripts() -> list[Path]:
    scripts = sorted(
        list(ROOT.glob("*.tmux"))
        + list(ROOT.glob("multiplexers/**/*.sh"))
        + list(ROOT.glob("multiplexers/**/*.tmux"))
    )
    assert len(scripts) >= 4, "Expected root + tmux-blackbird scripts"
    for s in scripts:
        proc = subprocess.run(["sh", "-n", str(s)], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"sh -n failed on {s}: {proc.stderr}"
    return scripts


def check_python_files() -> list[Path]:
    py_files = sorted(ROOT.glob("**/*.py"))
    assert len(py_files) >= 8, "Expected Python modules + tests + validator"
    for f in py_files:
        py_compile.compile(str(f), doraise=True)
    return py_files


def check_pinned_hashes() -> None:
    sys.path.insert(0, str(ROOT / "actions" / "outpost-notify"))
    import notify  # type: ignore

    for ver in ("v0.4.0", "v0.3.0"):
        sums = notify.PINNED_SHA256.get(ver, {})
        for target in ("darwin-arm64", "linux-x86_64", "linux-arm64"):
            h = sums.get(target, "")
            assert re.fullmatch(r"[0-9a-f]{64}", h), f"Invalid pinned SHA-256 for {ver}/{target}: {h!r}"


def check_hygiene() -> None:
    forbidden = [
        re.compile(r"/Users/[A-Za-z0-9_.-]+/"),
        re.compile(r"\b(" + "winter" + "mute|" + "neuro" + r"mancer)\b", re.IGNORECASE),
        re.compile("sk-" + r"ant-[A-Za-z0-9_-]{10,}"),
        re.compile("ghp" + r"_[A-Za-z0-9]{20,}"),
        re.compile("AKI" + r"A[0-9A-Z]{16}"),
        re.compile("BEGIN" + r"\s+[A-Z0-9\s]*PRIVATE\s+KEY"),
    ]
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in forbidden:
            if pat.search(text):
                raise AssertionError(f"Forbidden pattern {pat.pattern} found in {path.relative_to(ROOT)}")


def run_tests() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(ROOT),
        check=False,
    )
    assert proc.returncode == 0, "Unit tests failed"


def main() -> int:
    check_action_yaml()
    check_kdl()
    sh_files = check_shell_scripts()
    py_files = check_python_files()
    check_pinned_hashes()
    check_hygiene()
    run_tests()
    print(
        f"\nVALIDATE PASS: action.yml + blackbird-cockpit.kdl + {len(sh_files)} shell scripts + "
        f"{len(py_files)} Python files + pinned v0.4.0/v0.3.0 SHA-256 + hygiene + unittest OK!"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
