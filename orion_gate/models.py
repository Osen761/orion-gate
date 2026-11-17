"""Lightweight domain models for standalone Orion Gate (zero SQLAlchemy ORM dependency)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass
class Workspace:
    """In-memory workspace record derived from `orion.yaml` or tests."""

    id: UUID = field(default_factory=uuid4)
    name: str = "Orion Gate Standalone"
    owner_email: str = "standalone@oriongate.local"
    supabase_user_id: str | None = None
    plan: str = "standalone"
    created_at: datetime | None = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Connector:
    """In-memory datasource connector record compatible with Orion Gate services."""

    id: UUID = field(default_factory=uuid4)
    workspace_id: UUID | None = None
    type: str = "postgres"
    name: str = "primary-postgres"
    secret_id: str = "orion_yaml_inline"
    schema_cache: str | None = None
    schema_cached_at: datetime | None = None
    workspace_default_access: str = "workspace_query"
    is_active: bool | None = True
    created_at: datetime | None = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class EmbedApplication:
    """Optional embed application metadata for token-origin checks."""

    id: UUID = field(default_factory=uuid4)
    workspace_id: UUID | None = None
    name: str = "standalone-app"
    allowed_origins: str = "[]"


@dataclass
class EmbedSubject:
    """Optional external subject/tenant binding carried on scoped JWTs."""

    id: UUID = field(default_factory=uuid4)
    external_user_id: str | None = None
    external_tenant_id: str | None = None


@dataclass
class SchemaSnapshot:
    """Projected schema snapshot record."""

    id: UUID = field(default_factory=uuid4)
    workspace_id: UUID = field(default_factory=uuid4)
    connector_id: UUID = field(default_factory=uuid4)
    scope_version: str = "yaml_v1"
    projection_hash: str = ""
    raw_schema_hash: str | None = None
    projected_schema_json: str = "{}"
    projected_schema_text: str = ""
    tables_count: int = 0
    columns_count: int = 0
    created_at: datetime | None = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
