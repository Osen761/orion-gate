"""Strict exact-origin CORS helpers for Orion Gate."""

from __future__ import annotations

from urllib.parse import urlparse


CORS_ALLOWED_METHODS = ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
CORS_ALLOWED_HEADERS = [
    "Authorization",
    "Content-Type",
    "Idempotency-Key",
    "Mcp-Session-Id",
    "X-Orion-Connector-ID",
    "X-Orion-Request-ID",
    "X-Orion-Tenant-Values",
]


def normalize_cors_origin(value: str) -> str:
    """Return one exact browser origin or raise ValueError for unsafe input."""

    raw = (value or "").strip().rstrip("/")
    if not raw:
        raise ValueError("CORS origin cannot be empty.")
    if raw == "*" or "*" in raw:
        raise ValueError("Wildcard CORS origins are not allowed.")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("CORS origin must use http or https.")
    if not parsed.hostname:
        raise ValueError("CORS origin must include a host.")
    if parsed.username or parsed.password:
        raise ValueError("CORS origin must not include credentials.")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("CORS origin must not include a path, query, or fragment.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("CORS origin port is invalid.") from exc
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    return f"{parsed.scheme.lower()}://{netloc}"


def parse_cors_allowed_origins(value: str) -> list[str]:
    """Parse a comma-separated exact-origin allowlist."""

    origins: list[str] = []
    seen: set[str] = set()
    for item in (value or "").split(","):
        if not item.strip():
            continue
        origin = normalize_cors_origin(item)
        if origin not in seen:
            seen.add(origin)
            origins.append(origin)
    return origins
