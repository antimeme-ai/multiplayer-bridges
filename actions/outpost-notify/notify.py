#!/usr/bin/env python3
"""Composite GitHub Action driver for `actions/outpost-notify`.

Security invariants:
- Strictly validates `outpost_version` as semver (`^v[0-9]+\\.[0-9]+\\.[0-9]+...`).
- Verifies downloaded `mp-outpost` release tarballs against pinned `v0.4.0` /
  `v0.3.0` SHA-256 sums AND live `SHA256SUMS.txt` over HTTPS GitHub URLs only.
- Audits tarball entries before extraction (rejects `..`, absolute paths,
  symlinks, hardlinks, FIFOs, and device nodes).
- Refuses human `mprk1_` root recovery keys, `.mpkey` containers, and PEM
  private keys in both message payloads and hydrated CI state.
- Hydrates ephemeral scoped CI device state into a mode-`0700` temp directory
  (`OUTPOST_STATE_DIR`) and scrubs it unconditionally in `finally`.
- Bounds and redacts CI output, wrapping untrusted PR/log text in CSPRNG
  64-bit nonce provenance fences.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

# Ensure `mp-bridge` is importable when invoked standalone or from GitHub Actions
_REPO_ROOT = Path(__file__).resolve().parents[2]
_BRIDGE_DIR = _REPO_ROOT / "mp-bridge"
if str(_BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_DIR))

from security import (  # noqa: E402
    SecretRefusalError,
    detect_secret,
    format_untrusted_envelope,
    redact_secrets,
    refuse_secrets,
    sanitize_untrusted_text,
    validate_safe_id,
)

SEMVER_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
VALID_STATUSES = frozenset({"success", "failure", "cancelled", "info"})
MAX_SUMMARY_CHARS = 3000
MAX_CI_STATE_BYTES = 1024 * 1024  # 1 MiB
MAX_TAR_ENTRY_BYTES = 32 * 1024 * 1024  # 32 MiB
MAX_TAR_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB

# Live verified SHA-256 hashes for antimemeai/multiplayer_outpost releases
PINNED_SHA256: dict[str, dict[str, str]] = {
    "v0.4.0": {
        "darwin-arm64": "8c884c44a1d0df70e8c0b994f6b09c73d693ebde8b35f2309c56136b643b0add",
        "linux-arm64": "e016872244f8dc93f952861fc6446ba77bbb847e0a4d8e44d21d70bb95c96cb8",
        "linux-x86_64": "f04dac5d3ee500a077815b38378288d1c878b218ac3c3a1d301d86eaf3707dab",
    },
    "v0.3.0": {
        "darwin-arm64": "bef0c38bd4edba76c250de914eedb39a8fcf43705266394e27c4afabb3f74649",
        "linux-arm64": "4f9a3a1b322d07bcf6f20c0f50c690d9b9221f2f23f865782570378c8eae8f39",
        "linux-x86_64": "84c24a2cb54851434e2e243d15f65bcc769493298707022584e10888e0326d2f",
    },
}

ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)


class _SafeGitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise ValueError(f"Refused redirect to untrusted host: {parsed.scheme}://{parsed.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_version(version: str) -> str:
    v = version.strip()
    if ".." in v or "/" in v or "\\" in v or "%" in v or not SEMVER_RE.fullmatch(v):
        raise ValueError(f"Invalid outpost-version {version!r}: expected strict semver tag like v0.3.0")
    return v


def detect_target() -> str:
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if sys_name == "darwin" and machine in ("arm64", "aarch64"):
        return "darwin-arm64"
    if sys_name == "linux" and machine in ("x86_64", "amd64"):
        return "linux-x86_64"
    if sys_name == "linux" and machine in ("arm64", "aarch64"):
        return "linux-arm64"
    raise RuntimeError(f"Unsupported runner platform: {sys_name}/{machine}")


def audit_and_extract_tarball(
    tar_bytes: bytes,
    dest_dir: Path,
    *,
    max_files: int = 64,
    max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
) -> list[Path]:
    """Audit every tar entry (zero traversal, zero symlinks/hardlinks/devices, bounded size) before extracting."""
    extracted: list[Path] = []
    dest_resolved = dest_dir.resolve()
    total_written = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        members = tf.getmembers()
        if len(members) > max_files:
            raise ValueError(f"Tarball has too many entries ({len(members)} > {max_files})")
        for m in members:
            if m.issym() or m.islnk() or m.ischr() or m.isblk() or m.isfifo() or m.isdev():
                raise ValueError(f"Refused unsafe tar entry type: {m.name}")
            if m.name.startswith("/") or m.name.startswith("\\") or ".." in Path(m.name).parts:
                raise ValueError(f"Refused path traversal in tarball entry: {m.name}")
            target = (dest_resolved / m.name).resolve()
            if dest_resolved not in target.parents and target != dest_resolved:
                raise ValueError(f"Tarball entry escapes destination: {m.name}")
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isfile():
                raise ValueError(f"Unsupported tar entry: {m.name}")
            if m.size < 0 or m.size > MAX_TAR_ENTRY_BYTES:
                raise ValueError(f"Tarball entry exceeds size limit: {m.name} ({m.size} B)")
            total_written += m.size
            if total_written > max_total_bytes:
                raise ValueError(f"Tarball total extracted size exceeds limit ({max_total_bytes} B)")
            target.parent.mkdir(parents=True, exist_ok=True)
            src_fp = tf.extractfile(m)
            if src_fp is None:
                raise ValueError(f"Could not read tar entry: {m.name}")
            data = src_fp.read(MAX_TAR_ENTRY_BYTES + 1)
            if len(data) > MAX_TAR_ENTRY_BYTES:
                raise ValueError(f"Tarball entry actual stream exceeds size limit: {m.name}")
            target.write_bytes(data)
            os.chmod(target, 0o755 if (m.mode & 0o111) else 0o600)
            extracted.append(target)
    return extracted


def hydrate_ci_state(ci_state_b64: str, state_dir: Path) -> None:
    """Hydrate an ephemeral scoped CI bot state tarball while refusing any root key."""
    # Refuse raw human root recovery keys or PEM private keys before decoding
    if detect_secret(ci_state_b64) is not None:
        raise SecretRefusalError(
            "Refused MP_OUTPOST_CI_STATE: looks like a raw root recovery key, .mpkey, or secret token. "
            "Provision a scoped revocable CI bot device state archive instead."
        )
    try:
        raw = base64.b64decode(ci_state_b64.strip(), validate=True)
    except Exception as exc:
        raise ValueError("MP_OUTPOST_CI_STATE must be valid standard base64") from exc
    if len(raw) == 0 or len(raw) > MAX_CI_STATE_BYTES:
        raise ValueError(f"MP_OUTPOST_CI_STATE size out of bounds (1..={MAX_CI_STATE_BYTES} B)")

    # Reject raw `.mpkey` container magic (`MPKEY1\x00\x00`) or `mprk1_` inside decoded bytes
    if raw.startswith(b"MPKEY1\x00\x00") or b"mprk1_" in raw or b"BEGIN MULTIPLAYER RECOVERY KEY" in raw:
        raise SecretRefusalError(
            "Refused MP_OUTPOST_CI_STATE: root key material (`mprk1_` / `.mpkey`) is forbidden in CI."
        )

    os.chmod(state_dir, 0o700)
    files = audit_and_extract_tarball(raw, state_dir, max_files=32, max_total_bytes=MAX_CI_STATE_BYTES)
    for fpath in files:
        if fpath.name.lower() in ("root.key", "recovery.key") or fpath.suffix.lower() == ".mpkey":
            raise SecretRefusalError(
                f"Refused CI state entry '{fpath.name}': human root keys are forbidden in CI."
            )
        content = fpath.read_bytes()
        if (
            b"mprk1_" in content
            or content.startswith(b"MPKEY1\x00\x00")
            or detect_secret(content.decode("utf-8", errors="ignore")) is not None
        ):
            raise SecretRefusalError(
                f"Refused CI state entry '{fpath.name}': contains forbidden root/secret material."
            )
        os.chmod(fpath, 0o600)


def download_verified_outpost(version: str, target: str, work_dir: Path) -> Path:
    """Download mp-outpost release tarball over HTTPS, verify SHA-256, and extract safely."""
    v = validate_version(version)
    asset = f"mp-outpost-{v}-{target}.tar.gz"
    base_url = f"https://github.com/antimemeai/multiplayer_outpost/releases/download/{v}"
    opener = urllib.request.build_opener(_SafeGitHubRedirectHandler())

    def _fetch(url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "multiplayer-bridges-outpost-notify/1.0"})
        with opener.open(req, timeout=30) as resp:
            return resp.read()

    sums_text = _fetch(f"{base_url}/SHA256SUMS.txt").decode("utf-8")
    expected_from_sums: Optional[str] = None
    for line in sums_text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset:
            expected_from_sums = parts[0].lower()
            break
    if not expected_from_sums or not re.fullmatch(r"[0-9a-f]{64}", expected_from_sums):
        raise RuntimeError(f"Could not locate valid SHA-256 for {asset} in SHA256SUMS.txt")

    pinned = PINNED_SHA256.get(v, {}).get(target)
    if pinned is not None and pinned != expected_from_sums:
        raise RuntimeError(f"Pinned SHA-256 mismatch for {asset}: pinned={pinned}, remote={expected_from_sums}")

    tar_bytes = _fetch(f"{base_url}/{asset}")
    actual_sha = hashlib.sha256(tar_bytes).hexdigest()
    if actual_sha != expected_from_sums:
        raise RuntimeError(f"SHA-256 verification failed for {asset}: expected={expected_from_sums}, got={actual_sha}")

    extract_dir = work_dir / "bin-extract"
    extract_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    extracted = audit_and_extract_tarball(tar_bytes, extract_dir)
    for p in extracted:
        if p.name == "mp-outpost":
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            return p
    raise RuntimeError(f"mp-outpost binary not found inside {asset}")


def build_notification_payload(
    *,
    party_id: int,
    scope: str,
    title: str,
    summary: str,
    status: str,
    repo: str = "",
    sha: str = "",
    run_url: str = "",
    ref_name: str = "",
    strict_refuse_secrets: bool = False,
) -> dict[str, Any]:
    """Build a bounded, redacted, nonce-fenced CI notification payload."""
    pid = validate_safe_id(party_id, "party-id")
    norm_status = status.strip().lower() or "info"
    if norm_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status {status!r}: expected one of {sorted(VALID_STATUSES)}")

    refuse_secrets(scope, context="scope")
    if strict_refuse_secrets:
        refuse_secrets(title, context="title")
        refuse_secrets(summary, context="summary")

    safe_title = sanitize_untrusted_text(redact_secrets(title), max_chars=200, single_line=True)
    safe_summary = redact_secrets(summary)
    if len(safe_summary) > MAX_SUMMARY_CHARS:
        safe_summary = safe_summary[: MAX_SUMMARY_CHARS - 15] + " ...[truncated]"

    header_parts = [f"[CI:{norm_status.upper()}]"]
    if repo:
        header_parts.append(sanitize_untrusted_text(repo, max_chars=128, single_line=True))
    if ref_name:
        header_parts.append(f"@{sanitize_untrusted_text(ref_name, max_chars=64, single_line=True)}")
    if sha:
        header_parts.append(f"({sanitize_untrusted_text(sha[:12], max_chars=16, single_line=True)})")
    if safe_title:
        header_parts.append(f"— {safe_title}")

    lines = [" ".join(header_parts), "", safe_summary]
    if run_url:
        lines.append("")
        lines.append(f"Run: {sanitize_untrusted_text(run_url, max_chars=256, single_line=True)}")

    fenced = format_untrusted_envelope(
        "\n".join(lines),
        source="github-actions",
        sender=repo or "ci-bot",
        metadata={
            "status": norm_status,
            "sha": sha[:12] if sha else "",
            "scope": scope,
        },
        max_body_chars=MAX_SUMMARY_CHARS + 512,
    )
    # Final defense-in-depth secret check after redaction
    refuse_secrets(fenced, context="final CI notification")

    return {
        "party_id": pid,
        "scope": scope.strip() or "party/main",
        "status": norm_status,
        "title": safe_title,
        "message": fenced,
    }


_SCRUBBED_ENV_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "OUTPOST_API_URL",
    "OUTPOST_RELAY_URL",
)


def build_scrubbed_outpost_env(
    state_dir: Path,
    base_env: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Construct a minimal scrubbed environment for mp-outpost (zero CI runner secrets)."""
    src = base_env if base_env is not None else dict(os.environ)
    env: dict[str, str] = {}
    for key in _SCRUBBED_ENV_KEYS:
        val = src.get(key)
        if val:
            env[key] = val
    env["OUTPOST_STATE_DIR"] = str(state_dir)
    return env


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="multiplayer.tech Outpost CI notify driver")
    parser.add_argument("--dry-run", action="store_true", help="Emit structured JSON without sending")
    args = parser.parse_args(argv)

    party_id_raw = os.environ.get("MP_PARTY_ID", "").strip()
    if not party_id_raw.isdigit():
        raise SystemExit("MP_PARTY_ID must be a 52-bit positive integer")
    party_id = int(party_id_raw)
    scope = os.environ.get("MP_SCOPE", "party/main").strip() or "party/main"
    title = os.environ.get("MP_TITLE", "")
    summary = os.environ.get("MP_SUMMARY", "")
    status = os.environ.get("MP_STATUS", "info")
    version = validate_version(os.environ.get("MP_OUTPOST_VERSION", "v0.4.0"))
    dry_run = args.dry_run or os.environ.get("MP_DRY_RUN", "false").strip().lower() == "true"

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server_url}/{repo}/actions/runs/{run_id}" if repo and run_id else ""

    payload = build_notification_payload(
        party_id=party_id,
        scope=scope,
        title=title,
        summary=summary,
        status=status,
        repo=repo,
        sha=sha,
        run_url=run_url,
        ref_name=ref_name,
    )
    payload["outpost_version"] = version
    payload["dry_run"] = dry_run

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(f"payload_json={json.dumps(payload, separators=(',', ':'))}\n")

    if dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    ci_state_b64 = os.environ.get("MP_OUTPOST_CI_STATE", "").strip()
    if not ci_state_b64:
        raise SystemExit("MP_OUTPOST_CI_STATE is required unless dry-run is true")

    tmp_root = Path(tempfile.mkdtemp(prefix="mp-outpost-ci-"))
    os.chmod(tmp_root, 0o700)
    try:
        state_dir = tmp_root / "state"
        state_dir.mkdir(mode=0o700)
        hydrate_ci_state(ci_state_b64, state_dir)

        outpost_bin = shutil.which("mp-outpost")
        if outpost_bin is None:
            outpost_bin = str(download_verified_outpost(version, detect_target(), tmp_root))

        env = build_scrubbed_outpost_env(state_dir)

        proc = subprocess.run(
            [
                outpost_bin,
                "--state-dir",
                str(state_dir),
                "--json",
                "party",
                "say",
                str(payload["party_id"]),
                "--scope",
                str(payload["scope"]),
                str(payload["message"]),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            sys.stderr.write(f"mp-outpost party say failed (exit {proc.returncode}): {proc.stderr}\n")
            return proc.returncode
        print(json.dumps(payload, indent=2))
        return 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
