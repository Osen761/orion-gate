"""Structured security telemetry helpers."""

from __future__ import annotations

import logging
from typing import Any

from orion_gate.security.secrets import redact_secret_text


logger = logging.getLogger("orion.security")


def log_security_event(event_type: str, **metadata: Any) -> None:
    """Emit a redacted structured security event."""

    safe_metadata = {
        key: redact_secret_text(value)
        for key, value in metadata.items()
        if value is not None
    }
    logger.info("security_event=%s metadata=%s", event_type, safe_metadata)
