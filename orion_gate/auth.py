"""Lightweight caller authentication context and key helpers for Orion Gate."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from orion_gate.models import EmbedApplication, EmbedSubject, Workspace


@dataclass
class AuthContext:
    """Resolved authentication context for a standalone Orion Gate request."""

    workspace_id: str
    workspace: Workspace
    auth_type: str
    user_id: str | None = None
    email: str | None = None
    default_api_key: str | None = None
    embed_application: EmbedApplication | None = None
    embed_subject: EmbedSubject | None = None
    embed_tenant_values: dict[str, str] | None = None
    connector_id: str | None = None


def hash_api_key(api_key: str) -> str:
    """Hash a bearer token or API key using SHA-256."""

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def mask_api_key(api_key: str) -> str:
    """Return a safe masked representation of an API key or bearer token."""

    if len(api_key) <= 16:
        return f"{api_key[:4]}****"
    return f"{api_key[:8]}****...{api_key[-4:]}"
