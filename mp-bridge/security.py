"""Zero-trust security primitives for multiplayer.tech ambient bridges.

Provides:
- CSPRNG 64-bit (16-hex) nonce provenance fencing for untrusted external text.
- BiDi override, Unicode tag, C0/C1 control, and angle-bracket sanitization.
- Zero-width and fullwidth normalized outbound secret refusal.
- Constant-time HMAC-SHA256 webhook signature verification.
- Pure-stdlib strict RFC 8032 Ed25519 signature verification (for Discord Interactions).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from typing import Any, Optional, Sequence

MAX_SAFE_ID = (1 << 53) - 1

# Zero-width / invisible characters stripped prior to secret scanning so
# obfuscated tokens (e.g. `mpinv1_\u200b...`) cannot bypass refusal.
_INVISIBLE_CHARS = frozenset(
    {
        "\u00ad",  # soft hyphen
        "\u034f",  # combining grapheme joiner
        "\u061c",  # arabic letter mark
        "\u180e",  # mongolian vowel separator
        "\u200b",  # zero width space
        "\u200c",  # zero width non-joiner
        "\u200d",  # zero width joiner
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # LRE
        "\u202b",  # RLE
        "\u202c",  # PDF
        "\u202d",  # LRO
        "\u202e",  # RLO
        "\u2060",  # word joiner
        "\u2066",  # LRI
        "\u2067",  # RLI
        "\u2068",  # FSI
        "\u2069",  # PDI
        "\ufeff",  # BOM / ZWNBSP
    }
)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"mpinv1_[A-Za-z0-9_-]{4,}", re.IGNORECASE), "account invite token (mpinv1_)"),
    (re.compile(r"mppi1_[0-9]+_[A-Za-z0-9_-]{4,}", re.IGNORECASE), "party invite token (mppi1_)"),
    (
        re.compile(r"mprk1_[\s-]*[0-9A-Za-z](?:[\s-]*[0-9A-Za-z]){7,}", re.IGNORECASE),
        "root recovery key (mprk1_)",
    ),
    (
        re.compile(
            r"(?:[0-9A-HJKMNP-TV-Z]{5}[\s-]){10}[0-9A-HJKMNP-TV-Z]{5}",
            re.IGNORECASE,
        ),
        "possible unprefixed recovery key",
    ),
    (re.compile(r"mpdl1_[A-Za-z0-9_-]{8,}", re.IGNORECASE), "device link poll token (mpdl1_)"),
    (
        re.compile(r"BEGIN\s+[A-Z0-9\s]*(PRIVATE|RECOVERY)\s+KEY", re.IGNORECASE),
        "PEM private or recovery key",
    ),
    (re.compile(r"TVBLRVkxAA[A-D]"), "unarmored .mpkey recovery container"),
    (re.compile(r"4d504b4559310000", re.IGNORECASE), "hex .mpkey recovery container"),
    (re.compile(r"MC4CAQAwBQYDK2Vw|MFECAQEwBQYDK2Vw"), "Ed25519 PKCS#8 DER private key"),
    (re.compile(r"302e020100300506032b657004220420", re.IGNORECASE), "Ed25519 PKCS#8 hex private key"),
    (re.compile(r"b3BlbnNzaC1rZXktdjE"), "OpenSSH private key"),
    (
        re.compile(
            r'"?(device_secret|device_cwt|root_key_hex|root_secret|signing_key|private_key)"?\s*[:=]\s*"?[A-Za-z0-9+/=_-]{8,}',
            re.IGNORECASE,
        ),
        "serialized device/root credential field",
    ),
    (
        re.compile(
            r"(sk-ant-|sk-proj-|sk-live-|ghp_|github_pat_|cfut_|xoxb-|xapp-|xoxp-|lin_api_)[A-Za-z0-9_-]{10,}"
        ),
        "API or platform token",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "cloud access key"),
)


class SecretRefusalError(ValueError):
    """Raised when outbound or bridge text contains recognizable secret material."""


def validate_safe_id(value: int, field: str = "party_id") -> int:
    """Enforce 52-bit/53-bit positive integer ID invariant (never strings or bools)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > MAX_SAFE_ID:
        raise ValueError(f"{field} must be an integer in 1..={MAX_SAFE_ID}")
    return value


def _normalize_for_secret_scan(text: str) -> str:
    """Fold fullwidth ASCII via NFKC and remove zero-width/BiDi/tag obfuscation."""
    nfkc = unicodedata.normalize("NFKC", text)
    out_chars: list[str] = []
    for ch in nfkc:
        cp = ord(ch)
        if ch in _INVISIBLE_CHARS or (0xE0000 <= cp <= 0xE007F):
            continue
        out_chars.append(ch)
    return "".join(out_chars)


def detect_secret(text: str) -> Optional[str]:
    """Return a non-echoing secret category label if text contains forbidden secrets."""
    if not text:
        return None
    normalized = _normalize_for_secret_scan(text)
    for candidate in (text, normalized):
        for pattern, label in _SECRET_PATTERNS:
            if pattern.search(candidate):
                return label
    return None


def refuse_secrets(text: str, context: str = "payload") -> str:
    """Raise SecretRefusalError (without echoing secret bytes) if forbidden material is found."""
    hit = detect_secret(text)
    if hit is not None:
        raise SecretRefusalError(
            f"Refused {context}: detected forbidden secret material ({hit}). "
            "Keep private keys, recovery keys, invites, and API tokens strictly local."
        )
    return text


def redact_secrets(text: str) -> str:
    """Redact recognizable secret patterns for bounded CI/bridge log summaries."""
    if not text:
        return text
    cleaned = _normalize_for_secret_scan(text)
    for pattern, _ in _SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned


def sanitize_untrusted_text(text: str, *, max_chars: int = 8192, single_line: bool = False) -> str:
    """Strip BiDi overrides, Unicode tag chars, C0/C1 controls, and break angle-tag runs."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch in _INVISIBLE_CHARS or (0xE0000 <= cp <= 0xE007F):
            continue
        if cp < 0x20:
            if not single_line and ch in ("\n", "\t"):
                out.append(ch)
            elif single_line and ch in ("\n", "\r", "\t"):
                out.append(" ")
            continue
        if 0x7F <= cp <= 0x9F:
            continue
        out.append(ch)
    cleaned = "".join(out)
    # Neutralize raw XML/HTML tag delimiters so untrusted text cannot forge fence tags.
    cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")
    if single_line:
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 15] + " ...[truncated]"
    return cleaned


def format_untrusted_envelope(
    body: str,
    *,
    source: str,
    sender: str,
    metadata: Optional[dict[str, str]] = None,
    max_body_chars: int = 8192,
) -> str:
    """Wrap external untrusted text in a per-message 64-bit CSPRNG nonce provenance fence."""
    nonce = secrets.token_hex(8)
    safe_source = sanitize_untrusted_text(source, max_chars=64, single_line=True).replace('"', "'")
    safe_sender = sanitize_untrusted_text(sender, max_chars=128, single_line=True).replace('"', "'")
    safe_body = sanitize_untrusted_text(body, max_chars=max_body_chars, single_line=False)

    attrs = [f'nonce="{nonce}"', f'source="{safe_source}"', f'sender="{safe_sender}"']
    if metadata:
        for k, v in sorted(metadata.items()):
            sk = re.sub(r"[^a-zA-Z0-9_-]", "", str(k))[:32]
            if not sk:
                continue
            sv = sanitize_untrusted_text(str(v), max_chars=128, single_line=True).replace('"', "'")
            attrs.append(f'{sk}="{sv}"')

    attr_str = " ".join(attrs)
    return (
        f'<untrusted_external {attr_str}>\n'
        f"{safe_body}\n"
        f'</untrusted_external nonce="{nonce}">'
    )


def format_agent_card(
    *,
    title: str,
    summary: str,
    files: Optional[Sequence[str]] = None,
    status: Optional[str] = None,
    url: Optional[str] = None,
) -> str:
    """Format a compact, secret-checked `mp2` `agent_card` UTF-8 JSON payload."""
    refuse_secrets(title, context="agent_card title")
    refuse_secrets(summary, context="agent_card summary")
    clean_title = title.strip()[:160]
    clean_summary = summary.strip()[:2048]
    if not clean_title:
        raise ValueError("agent_card title must be non-empty")
    if not clean_summary:
        raise ValueError("agent_card summary must be non-empty")

    card: dict[str, Any] = {
        "kind": "agent_card",
        "title": clean_title,
        "summary": clean_summary,
    }
    if status is not None and status.strip():
        refuse_secrets(status, context="agent_card status")
        card["status"] = status.strip()[:64]
    if files:
        clean_files: list[str] = []
        for f in files[:32]:
            sf = str(f).strip()
            if not sf:
                continue
            refuse_secrets(sf, context="agent_card file")
            clean_files.append(sf[:256])
        if clean_files:
            card["files"] = clean_files
    if url is not None and url.strip():
        refuse_secrets(url, context="agent_card url")
        u = url.strip()
        if not (u.startswith("https://") or u.startswith("http://")):
            raise ValueError("agent_card url must be http(s)")
        card["url"] = u[:512]
    return json.dumps(card, separators=(",", ":"), ensure_ascii=False)


def fence_agent_card(
    card_payload: str | dict[str, Any],
    *,
    source: str,
    sender: str,
    metadata: Optional[dict[str, str]] = None,
) -> str:
    """Sanitize an untrusted incoming `mp2` `agent_card` and wrap it in a CSPRNG nonce fence."""
    if isinstance(card_payload, str):
        try:
            obj = json.loads(card_payload)
        except json.JSONDecodeError as exc:
            raise ValueError("agent_card payload must be valid JSON") from exc
    elif isinstance(card_payload, dict):
        obj = card_payload
    else:
        raise ValueError("agent_card payload must be JSON string or dict")
    if not isinstance(obj, dict):
        raise ValueError("agent_card payload must be a JSON object")

    title = str(obj.get("title") or "Agent update")
    summary = str(obj.get("summary") or "")
    status = str(obj.get("status") or "")
    raw_files = obj.get("files") if isinstance(obj.get("files"), list) else []
    files = [str(f) for f in raw_files[:32]]

    lines = [f"[agent_card] {title}" + (f" ({status})" if status else "")]
    if summary:
        lines.append(summary)
    if files:
        lines.append("Files: " + ", ".join(files))

    merged_meta = dict(metadata or {})
    merged_meta["kind"] = "agent_card"
    return format_untrusted_envelope(
        "\n".join(lines),
        source=source,
        sender=sender,
        metadata=merged_meta,
    )


def verify_hmac_sha256_hex(secret: bytes, payload: bytes, expected_hex: str) -> bool:
    """Constant-time HMAC-SHA256 hex digest verification."""
    if not secret or not expected_hex:
        return False
    cleaned = expected_hex.strip().lower()
    if len(cleaned) != 64 or not re.fullmatch(r"[0-9a-f]{64}", cleaned):
        return False
    computed = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, cleaned)


# ---------------------------------------------------------------------------
# Pure-stdlib strict RFC 8032 Ed25519 signature verification (zero external deps)
# ---------------------------------------------------------------------------
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _ED_P:
        return None
    x2 = ((y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _ed_point_add(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * _ED_D * t1 * t2) % _ED_P
    d = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return (e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P


def _ed_scalar_mul(pt: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    acc = (0, 1, 1, 0)
    cur = pt
    k = scalar
    while k > 0:
        if k & 1:
            acc = _ed_point_add(acc, cur)
        cur = _ed_point_add(cur, cur)
        k >>= 1
    return acc


def _ed_point_equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    return (p1[0] * p2[2] - p2[0] * p1[2]) % _ED_P == 0 and (
        p1[1] * p2[2] - p2[1] * p1[2]
    ) % _ED_P == 0


def _ed_decode_point(raw: bytes) -> Optional[tuple[int, int, int, int]]:
    if len(raw) != 32:
        return None
    val = int.from_bytes(raw, "little")
    sign = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _ED_P)


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
assert _ED_BX is not None
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_P)
_ED_IDENTITY = (0, 1, 1, 0)


def verify_ed25519(pubkey_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    """Strict RFC 8032 Ed25519 signature verification (rejects non-canonical S, Y, and small-order A)."""
    if len(pubkey_bytes) != 32 or len(signature_bytes) != 64:
        return False
    a_pt = _ed_decode_point(pubkey_bytes)
    if a_pt is None:
        return False
    # Reject small-order public keys (8 * A == identity)
    if _ed_point_equal(_ed_scalar_mul(a_pt, 8), _ED_IDENTITY):
        return False
    r_bytes = signature_bytes[:32]
    s = int.from_bytes(signature_bytes[32:], "little")
    if s >= _ED_L:
        return False
    r_pt = _ed_decode_point(r_bytes)
    if r_pt is None:
        return False
    h = int.from_bytes(hashlib.sha512(r_bytes + pubkey_bytes + message).digest(), "little") % _ED_L
    lhs = _ed_scalar_mul(_ED_B, s)
    rhs = _ed_point_add(r_pt, _ed_scalar_mul(a_pt, h))
    return _ed_point_equal(lhs, rhs)
