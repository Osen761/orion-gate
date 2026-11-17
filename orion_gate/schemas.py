"""Pydantic API contracts for Orion Gate REST, MCP, and telemetry."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class GovernedSchemaColumn(BaseModel):
    """One projected, PII-filtered column visible to an agent or gateway caller."""

    name: str
    data_type: str


class GovernedSchemaTable(BaseModel):
    """One projected table visible to an agent or gateway caller."""

    name: str
    qualified_name: str | None = None
    row_estimate: int | None = None
    columns: list[GovernedSchemaColumn] = Field(default_factory=list)


class GovernedSchemaResponse(BaseModel):
    """Projected schema payload returned by Orion Gate GET /v1/schema."""

    connector_id: UUID
    dialect: str
    schema_text: str = Field(
        validation_alias=AliasChoices("schema", "schema_text"),
        serialization_alias="schema",
    )
    tables: list[GovernedSchemaTable] = Field(default_factory=list)
    projection_hash: str
    tenant_isolation_active: bool = False
    max_result_rows: int
    allow_raw_rows: bool
    latency_ms: int

    @property
    def schema(self) -> str:  # type: ignore[override]
        return self.schema_text


class GovernedQueryRequest(BaseModel):
    """Direct governed SQL execution request for Orion Gate POST /v1/query."""

    model_config = ConfigDict(extra="forbid")

    sql: str = Field(..., min_length=1, max_length=10_000)
    connector_id: UUID | None = None
    tenant_values: dict[str, str] | None = None
    dry_run: bool = False


class GovernedViolationItem(BaseModel):
    """Safe policy violation item."""

    code: str
    message: str
    severity: str = "error"


class GovernedPolicySummary(BaseModel):
    """Safe SQL & result firewall telemetry returned with governed queries."""

    sql_allowed: bool
    result_allowed: bool | None = None
    result_decision: str | None = None
    tenant_isolation_active: bool = False
    tenant_predicates_injected: bool = False
    injected_predicates_count: int = 0
    row_limit_applied: bool = False
    max_rows: int
    redacted_columns: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    violations: list[GovernedViolationItem] = Field(default_factory=list)
    rewritten_sql: str | None = None
    policy_version: str


class GovernedResultColumn(BaseModel):
    """Column metadata in a governed SQL result."""

    name: str
    dtype: str


class GovernedQueryMetadata(BaseModel):
    """Audit and latency metadata for a governed SQL execution."""

    request_id: str | None = None
    analysis_run_id: UUID | None = None
    workspace_id: UUID
    connector_id: UUID
    dialect: str
    surface: str = "gateway"
    dry_run: bool = False
    latency_ms: int


class GovernedQueryResponse(BaseModel):
    """Structured response returned by Orion Gate POST /v1/query."""

    allowed: bool
    status: Literal["allowed", "redacted", "denied", "requires_review"]
    columns: list[GovernedResultColumn] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    redacted: bool = False
    error: str | None = None
    policy: GovernedPolicySummary
    metadata: GovernedQueryMetadata


class TelemetryEventItem(BaseModel):
    """One sanitized gateway telemetry event streamed to an optional control plane."""

    model_config = ConfigDict(extra="forbid")

    event_id: str | None = Field(default=None, max_length=128)
    request_id: str | None = Field(default=None, max_length=128)
    connector_id: UUID | None = None
    dialect: Literal["postgres", "mysql", "bigquery"] = "postgres"
    surface: str = Field(default="gateway", max_length=64)
    sql_preview: str = Field(..., min_length=1, max_length=1_000)
    status: Literal["allowed", "redacted", "denied", "requires_review", "failed"]
    sql_allowed: bool
    result_decision: Literal["allowed", "redacted", "denied", "requires_review"] | None = None
    tenant_isolation_active: bool = False
    tenant_predicates_injected: bool = False
    injected_predicates_count: int = Field(default=0, ge=0, le=100)
    redacted_columns: list[str] = Field(default_factory=list)
    denied_columns: list[str] = Field(default_factory=list)
    referenced_tables: list[str] = Field(default_factory=list)
    referenced_columns: list[str] = Field(default_factory=list)
    violations: list[GovernedViolationItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    row_count: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    policy_version: str = Field(default="phase_2_v1", max_length=64)
    scope_version: str | None = Field(default=None, max_length=128)
    error_message_safe: str | None = Field(default=None, max_length=700)
    occurred_at: datetime | None = None


class TelemetryIngestRequest(BaseModel):
    """Batch of sanitized telemetry events from a standalone/edge Orion Gate node."""

    model_config = ConfigDict(extra="forbid")

    events: list[TelemetryEventItem] = Field(..., min_length=1, max_length=100)
