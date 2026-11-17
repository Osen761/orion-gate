"""Secret redaction helpers for errors, logs, and model-visible text."""

from __future__ import annotations

import re
from typing import Any


SECRET_TEXT_RE = re.compile(
    r"("
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|ok_(?:test|live)_[A-Za-z0-9_]{12,}"
    r"|sk-[A-Za-z0-9_-]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]{12,}"
    r"|fernet:[A-Za-z0-9._:/@+-]+"
    r"|(?:postgres(?:ql)?|mysql|redis|rediss)://[^\s\"'<>]+"
    r"|(?:Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"
    r"|(?:connection_string|database_url|redis_url|supabase_service_role_key|service_account_json|secret_id)\s*[:=]\s*[^,\s;>]+"
    r"|[A-Za-z0-9_]*(?:access|refresh)?_?token[A-Za-z0-9_]*\s*[:=]\s*[A-Za-z0-9._-]{12,}"
    r"|(?:api[_-]?key|webhook[_-]?secret|jwt[_-]?secret|password)\s*[:=]\s*[^,\s;]+"
    r")",
    flags=re.IGNORECASE | re.DOTALL,
)


def redact_secret_text(value: Any, *, replacement: str = "[REDACTED]") -> str:
    """Return text with common secret formats removed."""

    if value is None:
        return ""
    text = str(value).replace("\x00", "")
    return SECRET_TEXT_RE.sub(replacement, text)


def safe_text(value: Any, *, max_chars: int = 1_000) -> str:
    """Return redacted, bounded text safe for logs or API previews."""

    text = redact_secret_text(value).strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "...[TRUNCATED]"


def safe_text_preview(value: Any, *, max_chars: int = 1_000) -> str | None:
    """Return a redacted, bounded text preview (or None if value is None)."""

    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    if not text:
        return ""
    text = redact_secret_text(text)
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "...[TRUNCATED]"
