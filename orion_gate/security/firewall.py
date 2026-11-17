"""Orion Gate Zero-LLM Governed SQL & Schema Firewall execution plane."""

from __future__ import annotations

import json
import re
import time
from dataclasses import replace
from typing import Any
from uuid import UUID

from fastapi import HTTPException, Request, status

from orion_gate.auth import AuthContext
from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.concurrency import run_sync_in_thread
from orion_gate.connectors.registry import get_connector
from orion_gate.errors import request_id_from_request
from orion_gate.models import Connector
from orion_gate.schemas import (
    GovernedPolicySummary,
    GovernedQueryMetadata,
    GovernedQueryResponse,
    GovernedResultColumn,
    GovernedSchemaColumn,
    GovernedSchemaResponse,
    GovernedSchemaTable,
    GovernedViolationItem,
)
from orion_gate.security.cloud_sync import CloudTelemetrySyncClient, build_telemetry_event
from orion_gate.security.differencing import DifferencingGuard, actor_session_key
from orion_gate.security.orion_yaml import (
    OrionYamlConfig,
    get_active_orion_yaml,
    resolve_standalone_gateway_auth,
)
from orion_gate.security.result_policy import (
    ResultPolicyGateway,
    ResultValidationContext,
)
from orion_gate.security.schema_projection import ProjectedSchema, SchemaProjectionService
from orion_gate.security.sql_policy import (
    POLICY_VERSION,
    SQLDialect,
    SQLPolicyDecision,
    SQLPolicyGateway,
    SQLPolicyViolation,
    SQLValidationContext,
)


SQL_CONNECTOR_DIALECTS: dict[str, SQLDialect] = {
    "postgres": "postgres",
    "mysql": "mysql",
    "bigquery": "bigquery",
}

CONNECTOR_ID_HEADER = "X-Orion-Connector-ID"
TENANT_VALUES_HEADER = "X-Orion-Tenant-Values"
RAW_TABLE_ROW_ESTIMATE_RE = re.compile(
    r"^Table:\s+(?P<name>.+?)\s+\((?P<rows>[\d,]+)\s+rows\)\s*$"
)


def _resolve_connector_runtime_config(connector_record: Connector) -> dict[str, Any]:
    standalone_cfg = getattr(connector_record, "_standalone_config", None)
    if isinstance(standalone_cfg, dict):
        return standalone_cfg
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Connector runtime configuration missing from orion.yaml datasource",
    )


def _normalize_identifier(value: str | None) -> str:
    return (value or "").strip().strip('"`[]').lower()


def _parse_row_estimates(raw_schema: str) -> dict[str, int]:
    estimates: dict[str, int] = {}
    for raw_line in raw_schema.splitlines():
        match = RAW_TABLE_ROW_ESTIMATE_RE.match(raw_line.strip())
        if not match:
            continue
        name = _normalize_identifier(match.group("name"))
        try:
            rows = int(match.group("rows").replace(",", ""))
        except ValueError:
            continue
        estimates[name] = rows
        estimates[name.split(".")[-1]] = rows
    return estimates


def _parse_header_tenant_values(request: Request) -> dict[str, str] | None:
    raw = request.headers.get(TENANT_VALUES_HEADER)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Orion-Tenant-Values JSON header",
        ) from exc
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Orion-Tenant-Values must be a JSON object",
        )
    return {str(k): str(v) for k, v in parsed.items()}


async def resolve_gateway_auth(
    request: Request,
    config: OrionYamlConfig | None = None,
) -> AuthContext:
    """Authenticate an Orion Gate caller against active `orion.yaml` auth settings."""

    yaml_config = config or get_active_orion_yaml()
    if yaml_config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Standalone orion.yaml configuration is not active. Set ORION_YAML_PATH or run `orion-gate serve`.",
        )
    return resolve_standalone_gateway_auth(request, yaml_config)


class OrionGateFirewallService:
    """Zero-LLM governed schema & SQL execution plane."""

    def __init__(self, config: OrionYamlConfig | None = None) -> None:
        self.config = config

    async def resolve_connector_and_scope(
        self,
        *,
        request: Request,
        auth: AuthContext,
        connector_id: UUID | str | None = None,
        tenant_values: dict[str, str] | None = None,
        access_mode: str = "query",
        surface: str = "gateway",
    ) -> tuple[Connector, EffectiveAccessScope, SQLDialect, OrionYamlConfig]:
        """Resolve and authorize a SQL datasource and its tenant-bound access scope."""

        header_connector_id = request.headers.get(CONNECTOR_ID_HEADER)
        query_connector_id = request.query_params.get("connector_id")
        requested_connector_id = str(
            connector_id or header_connector_id or query_connector_id or ""
        ).strip() or None

        header_tenant_values = _parse_header_tenant_values(request)
        requested_tenant_values = (
            tenant_values if tenant_values is not None else header_tenant_values
        )

        yaml_config = self.config or get_active_orion_yaml()
        if yaml_config is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Standalone orion.yaml configuration is not active",
            )

        if (
            auth.auth_type == "embed"
            and requested_connector_id
            and requested_connector_id != str(auth.connector_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scoped token cannot override bound connector",
            )

        datasource = yaml_config.resolve_datasource(requested_connector_id or auth.connector_id)
        scope = yaml_config.build_effective_scope(
            datasource=datasource,
            auth=auth,
            requested_tenant_values=requested_tenant_values,
            surface=surface,
        )
        connector_record = datasource.to_connector_model(
            yaml_config.workspace_id,
            scope.allowed_tables,
        )
        request.state.effective_access_scope = scope
        return connector_record, scope, datasource.dialect, yaml_config

    async def describe_schema(
        self,
        *,
        request: Request,
        auth: AuthContext,
        connector_id: UUID | str | None = None,
        table: str | None = None,
        tenant_values: dict[str, str] | None = None,
        surface: str = "gateway",
    ) -> GovernedSchemaResponse:
        """Return projected, PII-filtered schema metadata for an authorized caller."""

        started_at = time.perf_counter()
        connector_record, scope, dialect, _yaml_config = await self.resolve_connector_and_scope(
            request=request,
            auth=auth,
            connector_id=connector_id,
            tenant_values=tenant_values,
            access_mode="read_schema",
            surface=surface,
        )
        connector = get_connector(
            connector_record.type,
            _resolve_connector_runtime_config(connector_record),
        )
        try:
            raw_schema = await run_sync_in_thread(connector.get_schema)
        finally:
            connector.close()

        projected = SchemaProjectionService().project_schema(
            connector_record,
            raw_schema,
            scope,
        )
        tenant_active = bool(scope.tenant_filters)
        row_estimates = {} if tenant_active else _parse_row_estimates(raw_schema)
        tables = self._build_schema_tables(projected, row_estimates, table_filter=table)
        schema_text = (
            self._render_filtered_schema_text(connector_record, tables)
            if table
            else projected.schema_text
        )
        latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))

        return GovernedSchemaResponse(
            connector_id=connector_record.id,
            dialect=dialect,
            schema_text=schema_text,
            tables=tables,
            projection_hash=projected.projection_hash,
            tenant_isolation_active=tenant_active,
            max_result_rows=scope.max_result_rows,
            allow_raw_rows=scope.allow_raw_rows,
            latency_ms=latency_ms,
        )

    async def execute_query(
        self,
        *,
        request: Request,
        auth: AuthContext,
        sql: str,
        connector_id: UUID | str | None = None,
        tenant_values: dict[str, str] | None = None,
        dry_run: bool = False,
        surface: str = "gateway",
    ) -> GovernedQueryResponse:
        """Validate, AST-rewrite, execute, scrub, and emit telemetry for one SQL query."""

        started_at = time.perf_counter()
        public_request_id = request_id_from_request(request)
        connector_record, scope, dialect, yaml_config = await self.resolve_connector_and_scope(
            request=request,
            auth=auth,
            connector_id=connector_id,
            tenant_values=tenant_values,
            access_mode="query",
            surface=surface,
        )

        connector = get_connector(
            connector_record.type,
            _resolve_connector_runtime_config(connector_record),
        )
        try:
            raw_schema = await run_sync_in_thread(connector.get_schema)
            projected_schema = SchemaProjectionService().project_schema(
                connector_record,
                raw_schema,
                scope,
            )

            sql_context = SQLValidationContext(
                dialect=dialect,
                scope=scope,
                projected_schema=projected_schema,
                connector_type=connector_record.type,
                auto_inject_tenant_filters=True,
            )
            sql_decision = SQLPolicyGateway().validate(sql, sql_context)

            if not sql_decision.allowed:
                latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))
                await self._emit_cloud_telemetry(
                    yaml_config=yaml_config,
                    sql=sql,
                    scope=scope,
                    sql_decision=sql_decision,
                    result_decision=None,
                    connector_id=connector_record.id,
                    dialect=dialect,
                    surface=surface,
                    status="denied",
                    row_count=0,
                    latency_ms=latency_ms,
                    request_id=public_request_id,
                    error_message=sql_decision.safe_error_message,
                )
                return GovernedQueryResponse(
                    allowed=False,
                    status="denied",
                    error=sql_decision.safe_error_message,
                    policy=self._build_policy_summary(
                        scope=scope,
                        sql_decision=sql_decision,
                        result_decision=None,
                    ),
                    metadata=self._build_metadata(
                        public_request_id=public_request_id,
                        workspace_id=auth.workspace.id,
                        connector_id=connector_record.id,
                        dialect=dialect,
                        surface=surface,
                        dry_run=dry_run,
                        latency_ms=latency_ms,
                    ),
                )

            session_key = actor_session_key(
                scope=scope,
                request_actor_hint=public_request_id,
            )
            diff_guard = DifferencingGuard()
            diff_decision = diff_guard.check_and_record(
                sql=sql,
                dialect=dialect,
                scope=scope,
                sql_decision=sql_decision,
                session_key=session_key,
                record_query=not dry_run,
            )
            if not diff_decision.allowed:
                denied_decision = replace(
                    sql_decision,
                    allowed=False,
                    reason=diff_decision.message,
                    violations=tuple(sql_decision.violations)
                    + (
                        SQLPolicyViolation(
                            code=diff_decision.code,
                            message=diff_decision.message,
                            severity="error",
                        ),
                    ),
                )
                latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))
                await self._emit_cloud_telemetry(
                    yaml_config=yaml_config,
                    sql=sql,
                    scope=scope,
                    sql_decision=denied_decision,
                    result_decision=None,
                    connector_id=connector_record.id,
                    dialect=dialect,
                    surface=surface,
                    status="denied",
                    row_count=0,
                    latency_ms=latency_ms,
                    request_id=public_request_id,
                    error_message=diff_decision.message,
                )
                return GovernedQueryResponse(
                    allowed=False,
                    status="denied",
                    error=diff_decision.message,
                    policy=self._build_policy_summary(
                        scope=scope,
                        sql_decision=denied_decision,
                        result_decision=None,
                    ),
                    metadata=self._build_metadata(
                        public_request_id=public_request_id,
                        workspace_id=auth.workspace.id,
                        connector_id=connector_record.id,
                        dialect=dialect,
                        surface=surface,
                        dry_run=dry_run,
                        latency_ms=latency_ms,
                    ),
                )

            if dry_run:
                latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))
                await self._emit_cloud_telemetry(
                    yaml_config=yaml_config,
                    sql=sql,
                    scope=scope,
                    sql_decision=sql_decision,
                    result_decision=None,
                    connector_id=connector_record.id,
                    dialect=dialect,
                    surface=surface,
                    status="allowed",
                    row_count=0,
                    latency_ms=latency_ms,
                    request_id=public_request_id,
                )
                return GovernedQueryResponse(
                    allowed=True,
                    status="allowed",
                    columns=[],
                    rows=[],
                    row_count=0,
                    truncated=False,
                    redacted=False,
                    policy=self._build_policy_summary(
                        scope=scope,
                        sql_decision=sql_decision,
                        result_decision=None,
                    ),
                    metadata=self._build_metadata(
                        public_request_id=public_request_id,
                        workspace_id=auth.workspace.id,
                        connector_id=connector_record.id,
                        dialect=dialect,
                        surface=surface,
                        dry_run=True,
                        latency_ms=latency_ms,
                    ),
                )

            setattr(connector, "sql_policy_context", sql_context)
            setattr(connector, "last_sql_policy_decision", sql_decision)
            setattr(connector, "last_result_policy_decision", None)

            df, text_output = await run_sync_in_thread(
                connector.execute_sql,
                sql,
            )
            result_decision = getattr(connector, "last_result_policy_decision", None)
            if result_decision is None:
                if text_output.startswith("ERROR:") and df.empty:
                    latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))
                    await self._emit_cloud_telemetry(
                        yaml_config=yaml_config,
                        sql=sql,
                        scope=scope,
                        sql_decision=sql_decision,
                        result_decision=None,
                        connector_id=connector_record.id,
                        dialect=dialect,
                        surface=surface,
                        status="failed",
                        row_count=0,
                        latency_ms=latency_ms,
                        request_id=public_request_id,
                        error_message="Database rejected governed SQL execution",
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Database rejected governed SQL execution",
                    )
                result_decision = ResultPolicyGateway().validate(
                    df,
                    ResultValidationContext(
                        scope=scope,
                        projected_schema=projected_schema,
                        sql_policy_decision=sql_decision,
                        connector_type=connector_record.type,
                        connector_id=scope.connector_id,
                        pii_masking=yaml_config.policy.pii_masking,
                    ),
                )
        finally:
            connector.close()

        latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))

        if any(
            getattr(v, "code", "") == "small_group_suppressed"
            for v in getattr(result_decision, "violations", ())
        ) or any("k-anonymity" in str(w).lower() for w in getattr(result_decision, "warnings", ())):
            diff_guard.mark_small_group_suppressed(
                scope=scope,
                session_key=session_key,
                template_hash=diff_decision.template_hash,
            )

        if not result_decision.allowed or result_decision.safe_result is None:
            denied_status = (
                "requires_review"
                if result_decision.decision == "requires_review"
                else "denied"
            )
            await self._emit_cloud_telemetry(
                yaml_config=yaml_config,
                sql=sql,
                scope=scope,
                sql_decision=sql_decision,
                result_decision=result_decision,
                connector_id=connector_record.id,
                dialect=dialect,
                surface=surface,
                status=denied_status,
                row_count=0,
                latency_ms=latency_ms,
                request_id=public_request_id,
                error_message=result_decision.safe_error_message,
            )
            return GovernedQueryResponse(
                allowed=False,
                status=denied_status,
                error=result_decision.safe_error_message,
                policy=self._build_policy_summary(
                    scope=scope,
                    sql_decision=sql_decision,
                    result_decision=result_decision,
                ),
                metadata=self._build_metadata(
                    public_request_id=public_request_id,
                    workspace_id=auth.workspace.id,
                    connector_id=connector_record.id,
                    dialect=dialect,
                    surface=surface,
                    dry_run=False,
                    latency_ms=latency_ms,
                ),
            )

        safe_result = result_decision.safe_result
        final_status = "redacted" if result_decision.decision == "redacted" else "allowed"

        await self._emit_cloud_telemetry(
            yaml_config=yaml_config,
            sql=sql,
            scope=scope,
            sql_decision=sql_decision,
            result_decision=result_decision,
            connector_id=connector_record.id,
            dialect=dialect,
            surface=surface,
            status=final_status,
            row_count=safe_result.row_count,
            latency_ms=latency_ms,
            request_id=public_request_id,
        )

        return GovernedQueryResponse(
            allowed=True,
            status=final_status,
            columns=[
                GovernedResultColumn(name=col.name, dtype=col.dtype)
                for col in safe_result.columns
            ],
            rows=list(safe_result.rows),
            row_count=safe_result.row_count,
            truncated=safe_result.truncated,
            redacted=safe_result.redacted,
            policy=self._build_policy_summary(
                scope=scope,
                sql_decision=sql_decision,
                result_decision=result_decision,
            ),
            metadata=self._build_metadata(
                public_request_id=public_request_id,
                workspace_id=auth.workspace.id,
                connector_id=connector_record.id,
                dialect=dialect,
                surface=surface,
                dry_run=False,
                latency_ms=latency_ms,
            ),
        )

    def _build_schema_tables(
        self,
        projected: ProjectedSchema,
        row_estimates: dict[str, int],
        *,
        table_filter: str | None = None,
    ) -> list[GovernedSchemaTable]:
        target = _normalize_identifier(table_filter) if table_filter else None
        tables: list[GovernedSchemaTable] = []
        for item in projected.schema_json.get("objects", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            qualified_name = str(item.get("qualified_name") or name)
            if target and target not in {
                _normalize_identifier(name),
                _normalize_identifier(qualified_name),
            }:
                continue
            columns = [
                GovernedSchemaColumn(
                    name=str(col.get("name") or ""),
                    data_type=str(col.get("type") or "unknown"),
                )
                for col in item.get("columns", [])
                if isinstance(col, dict)
                and col.get("name")
                and str(col.get("name")).lower() != "no visible columns"
            ]
            estimate = row_estimates.get(_normalize_identifier(qualified_name))
            if estimate is None:
                estimate = row_estimates.get(_normalize_identifier(name))
            tables.append(
                GovernedSchemaTable(
                    name=name,
                    qualified_name=qualified_name,
                    row_estimate=estimate,
                    columns=columns,
                )
            )
        if target and not tables:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Requested table is not visible in governed schema",
            )
        return tables

    def _render_filtered_schema_text(
        self,
        connector: Connector,
        tables: list[GovernedSchemaTable],
    ) -> str:
        lines = [f"Projected schema for {connector.name} ({connector.type})"]
        for table in tables:
            lines.append(f"Table: {table.qualified_name or table.name}")
            for col in table.columns:
                lines.append(f"  - {col.name}: {col.data_type}")
        return "\n".join(lines)

    def _build_policy_summary(
        self,
        *,
        scope: EffectiveAccessScope,
        sql_decision: SQLPolicyDecision,
        result_decision: Any | None,
    ) -> GovernedPolicySummary:
        violations = [
            GovernedViolationItem(
                code=v.code,
                message=v.message,
                severity=v.severity,
            )
            for v in sql_decision.violations
        ]
        if result_decision is not None:
            violations.extend(
                GovernedViolationItem(
                    code=v.code,
                    message=v.message,
                    severity=v.severity,
                )
                for v in getattr(result_decision, "violations", ())
            )

        warnings = list(getattr(result_decision, "warnings", ()) or [])
        redacted_columns = list(getattr(result_decision, "redacted_columns", ()) or [])

        return GovernedPolicySummary(
            sql_allowed=sql_decision.allowed,
            result_allowed=(
                bool(result_decision.allowed) if result_decision is not None else None
            ),
            result_decision=(
                str(result_decision.decision) if result_decision is not None else None
            ),
            tenant_isolation_active=bool(scope.tenant_filters),
            tenant_predicates_injected=sql_decision.tenant_predicates_injected,
            injected_predicates_count=sql_decision.injected_predicates_count,
            row_limit_applied=sql_decision.row_limit_applied,
            max_rows=sql_decision.max_rows,
            redacted_columns=redacted_columns,
            warnings=warnings,
            violations=violations,
            rewritten_sql=sql_decision.safe_sql if scope.allow_sql_visibility else None,
            policy_version=sql_decision.policy_version or POLICY_VERSION,
        )

    def _build_metadata(
        self,
        *,
        public_request_id: str | None,
        workspace_id: UUID | str,
        connector_id: UUID | str,
        dialect: str,
        surface: str,
        dry_run: bool,
        latency_ms: int,
    ) -> GovernedQueryMetadata:
        return GovernedQueryMetadata(
            request_id=public_request_id,
            analysis_run_id=None,
            workspace_id=workspace_id if isinstance(workspace_id, UUID) else UUID(str(workspace_id)),
            connector_id=connector_id if isinstance(connector_id, UUID) else UUID(str(connector_id)),
            dialect=dialect,
            surface=surface,
            dry_run=dry_run,
            latency_ms=latency_ms,
        )

    async def _emit_cloud_telemetry(
        self,
        *,
        yaml_config: OrionYamlConfig | None,
        sql: str,
        scope: EffectiveAccessScope,
        sql_decision: SQLPolicyDecision,
        result_decision: Any | None,
        connector_id: UUID | str,
        dialect: SQLDialect,
        surface: str,
        status: str,
        row_count: int,
        latency_ms: int,
        request_id: str | None = None,
        error_message: str | None = None,
    ) -> None:
        sync_client = CloudTelemetrySyncClient(yaml_config)
        if not sync_client.telemetry_enabled:
            return
        event = build_telemetry_event(
            sql=sql,
            scope=scope,
            sql_decision=sql_decision,
            result_decision=result_decision,
            connector_id=connector_id,
            dialect=dialect,
            surface=surface,
            status=status,
            row_count=row_count,
            latency_ms=latency_ms,
            request_id=request_id,
            error_message=error_message,
        )
        await sync_client.emit_event(event)
