"""Effective access scope primitives for Orion Gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


CONNECTOR_ACCESS_LEVELS = ("none", "read_schema", "query", "manage")
ACCESS_RANK = {
    "none": 0,
    "read_schema": 1,
    "query": 2,
    "manage": 3,
}
DEFAULT_SCOPE_VERSION = "phase_1b_v1"


@dataclass(frozen=True)
class TenantFilter:
    """Deterministic tenant predicate required for one table."""

    table: str
    column: str
    operator: str = "="
    value: str | None = None
    source: str = "scope"
    required: bool = True
    policy_id: str | None = None


@dataclass(frozen=True)
class EffectiveAccessScope:
    """Immutable resolved access boundary for a datasource request."""

    workspace_id: str
    surface: str
    principal_type: str
    user_id: str | None
    member_id: str | None
    role: str
    connector_id: str | None
    connector_access_level: str | None
    embed_application_id: str | None = None
    embed_subject_id: str | None = None
    external_user_id: str | None = None
    external_tenant_id: str | None = None
    allowed_tables: tuple[str, ...] | None = None
    denied_tables: tuple[str, ...] = field(default_factory=tuple)
    allowed_columns: tuple[str, ...] | None = None
    denied_columns: tuple[str, ...] = field(default_factory=tuple)
    allowed_metrics: tuple[str, ...] = field(default_factory=tuple)
    allowed_dimensions: tuple[str, ...] = field(default_factory=tuple)
    tenant_filters: tuple[TenantFilter, ...] = field(default_factory=tuple)
    allow_raw_rows: bool = False
    allow_sql_visibility: bool = False
    max_result_rows: int = 10_000
    max_execution_seconds: int = 30
    minimum_group_size: int | None = None
    allow_json_columns: bool = False
    allowed_json_paths: tuple[str, ...] = field(default_factory=tuple)
    allow_cross_joins: bool = False
    allow_raw_pii: bool = True
    pii_masking_columns: tuple[str, ...] = field(default_factory=tuple)
    max_query_cost: float | None = None
    max_bytes_billed: int | None = None
    differencing_budget: int = 5
    differencing_window_seconds: int = 300
    scope_version: str = DEFAULT_SCOPE_VERSION
    expires_at: datetime | None = None


def access_at_least(current: str | None, required: str) -> bool:
    """Return True if the granted connector access level satisfies `required`."""

    return ACCESS_RANK.get(current or "none", 0) >= ACCESS_RANK.get(required, 99)
