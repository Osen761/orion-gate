"""Shared deterministic fixtures for Orion Gate adversarial attack tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from orion_gate.auth import AuthContext
from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.models import Connector, Workspace
from orion_gate.security.result_policy import ResultValidationContext
from orion_gate.security.schema_projection import ProjectedSchema, SchemaProjectionService
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


RAW_SCHEMA = """Dataset: sales
Table: customers (4 rows)
  - id: integer
  - email: text
  - name: text
  - phone: text
  - created_at: timestamp
  - password_hash: text
  - api_token: text
Table: orders (20 rows)
  - id: integer
  - customer_id: integer
  - total: numeric
  - status: text
  - created_at: timestamp
Table: invoices (20 rows)
  - id: integer
  - customer_id: integer
  - amount: numeric
  - created_at: timestamp
Table: payroll (3 rows)
  - employee_id: integer
  - salary: numeric
  - private_key: text
Table: hidden_audit_log (9 rows)
  - id: integer
  - actor_email: text
  - denied_column_name: text
"""

SECRET_VALUE = "ok_test_abcdefghijklmnopqrstuvwxyz123456"
JWT_VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzNDU2In0.signature1234567890"
PRIVATE_KEY_VALUE = "-----BEGIN PRIVATE KEY-----\nabc123secret\n-----END PRIVATE KEY-----"


def make_workspace(name: str = "Orion Gate") -> Workspace:
    return Workspace(
        id=uuid.uuid4(),
        name=name,
        owner_email=f"{name.lower().replace(' ', '_')}@example.com",
        plan="standalone",
    )


def make_connector(
    workspace_id: uuid.UUID,
    *,
    connector_type: str = "postgres",
    default_access: str = "restricted",
    allowed_tables: tuple[str, ...] | None = ("customers", "orders", "invoices"),
) -> Connector:
    connector = Connector(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        type=connector_type,
        name="Warehouse",
        secret_id="orion_yaml_inline",
        workspace_default_access=default_access,
        is_active=True,
    )
    if allowed_tables is not None:
        connector.schema_cache = '{"allowed_tables": [' + ",".join(f'"{table}"' for table in allowed_tables) + "]}"
    return connector


def make_api_key_auth(workspace: Workspace) -> AuthContext:
    return AuthContext(
        workspace_id=str(workspace.id),
        workspace=workspace,
        auth_type="api_key",
    )


def make_scope(
    connector: Connector | None = None,
    *,
    allowed_tables: tuple[str, ...] | None = ("customers", "orders", "invoices"),
    denied_tables: tuple[str, ...] = (),
    allowed_columns: tuple[str, ...] | None = None,
    denied_columns: tuple[str, ...] = (),
    allow_raw_rows: bool = False,
    max_result_rows: int = 100,
    max_execution_seconds: int = 17,
    minimum_group_size: int | None = None,
    role: str = "analyst",
    access_level: str = "query",
) -> EffectiveAccessScope:
    connector = connector or make_connector(make_workspace().id)
    return EffectiveAccessScope(
        workspace_id=str(connector.workspace_id),
        surface="gateway",
        principal_type="api_key",
        user_id=str(uuid.uuid4()),
        member_id=None,
        role=role,
        connector_id=str(connector.id),
        connector_access_level=access_level,
        allowed_tables=allowed_tables,
        denied_tables=denied_tables,
        allowed_columns=allowed_columns,
        denied_columns=denied_columns,
        allow_raw_rows=allow_raw_rows,
        max_result_rows=max_result_rows,
        max_execution_seconds=max_execution_seconds,
        minimum_group_size=minimum_group_size,
    )


def make_projected_schema(
    connector: Connector | None = None,
    *,
    raw_schema: str = RAW_SCHEMA,
    scope: EffectiveAccessScope | None = None,
) -> ProjectedSchema:
    connector = connector or make_connector(make_workspace().id)
    scope = scope or make_scope(connector)
    return SchemaProjectionService().project_schema(connector, raw_schema, scope)


def make_sql_context(
    *,
    dialect: str = "postgres",
    connector_type: str = "postgres",
    raw_schema: str = RAW_SCHEMA,
    **scope_kwargs: Any,
) -> SQLValidationContext:
    connector = make_connector(make_workspace().id, connector_type=connector_type)
    scope = make_scope(connector, **scope_kwargs)
    projected = make_projected_schema(connector, raw_schema=raw_schema, scope=scope)
    return SQLValidationContext(
        dialect=dialect,  # type: ignore[arg-type]
        scope=scope,
        projected_schema=projected,
        connector_type=connector_type,
    )


def make_result_context(
    *,
    connector_type: str = "postgres",
    dialect: str = "postgres",
    sql: str | None = None,
    raw_schema: str = RAW_SCHEMA,
    **scope_kwargs: Any,
) -> ResultValidationContext:
    connector = make_connector(make_workspace().id, connector_type=connector_type)
    scope = make_scope(connector, **scope_kwargs)
    projected = make_projected_schema(connector, raw_schema=raw_schema, scope=scope)
    sql_decision = None
    if sql is not None:
        sql_decision = SQLPolicyGateway().validate(
            sql,
            SQLValidationContext(
                dialect=dialect,  # type: ignore[arg-type]
                scope=scope,
                projected_schema=projected,
                connector_type=connector_type,
            ),
        )
    return ResultValidationContext(
        scope=scope,
        projected_schema=projected,
        sql_policy_decision=sql_decision,
        connector_type=connector_type,
        connector_id=str(connector.id),
    )


def serialized(value: Any) -> str:
    return str(value)


def assert_no_terms(testcase: Any, text: str, terms: tuple[str, ...]) -> None:
    lower = text.lower()
    for term in terms:
        testcase.assertNotIn(term.lower(), lower)


@dataclass
class FakeSafeResult:
    redacted: bool = False
    truncated: bool = False


@dataclass
class FakeDecision:
    allowed: bool = True
    decision: str = "allowed"
    warnings: tuple[str, ...] = ()
    redacted_columns: tuple[str, ...] = ()
    safe_result: FakeSafeResult | None = None
