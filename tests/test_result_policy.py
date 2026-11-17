"""Phase 1E result policy gateway tests."""

from __future__ import annotations

import unittest
import uuid
from unittest.mock import patch

import pandas as pd

from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.connectors.bigquery import BigQueryConnector
from orion_gate.connectors.mysql import MySQLConnector
from orion_gate.connectors.postgres import PostgresConnector
from orion_gate.models import Connector
from orion_gate.security.result_policy import (
    ResultPolicyGateway,
    ResultValidationContext,
    SafeQueryResult,
)
from orion_gate.security.schema_projection import SchemaProjectionService
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


RAW_SCHEMA = """Dataset: sales
Table: customers (10 rows)
  - id: integer
  - email: text
  - name: text
  - created_at: timestamp
  - note: text
  - comment: text
  - password_hash: text
Table: orders (20 rows)
  - id: integer
  - customer_id: integer
  - total: numeric
  - status: text
  - department: text
  - created_at: timestamp
"""


def make_connector(connector_type: str = "postgres") -> Connector:
    return Connector(
        id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        type=connector_type,
        name="Warehouse",
        secret_id="fernet:secret",
        is_active=True,
        workspace_default_access="restricted",
    )


def make_scope(
    connector: Connector,
    *,
    allow_raw_rows: bool = False,
    max_result_rows: int = 100,
    allowed_tables: tuple[str, ...] | None = ("sales.customers", "sales.orders", "customers", "orders"),
    denied_columns: tuple[str, ...] = (),
    minimum_group_size: int | None = None,
) -> EffectiveAccessScope:
    return EffectiveAccessScope(
        workspace_id=str(connector.workspace_id),
        surface="workspace",
        principal_type="workspace_user",
        user_id=str(uuid.uuid4()),
        member_id=str(uuid.uuid4()),
        role="analyst",
        connector_id=str(connector.id),
        connector_access_level="query",
        allowed_tables=allowed_tables,
        denied_columns=denied_columns,
        allow_raw_rows=allow_raw_rows,
        max_result_rows=max_result_rows,
        minimum_group_size=minimum_group_size,
    )


def make_result_context(
    *,
    connector_type: str = "postgres",
    dialect: str = "postgres",
    allow_raw_rows: bool = False,
    max_result_rows: int = 100,
    denied_columns: tuple[str, ...] = (),
    minimum_group_size: int | None = None,
    sql: str | None = None,
    raw_schema: str = RAW_SCHEMA,
    allowed_tables: tuple[str, ...] | None = ("sales.customers", "sales.orders", "customers", "orders"),
) -> ResultValidationContext:
    connector = make_connector(connector_type)
    scope = make_scope(
        connector,
        allow_raw_rows=allow_raw_rows,
        max_result_rows=max_result_rows,
        denied_columns=denied_columns,
        minimum_group_size=minimum_group_size,
        allowed_tables=allowed_tables,
    )
    projected = SchemaProjectionService().project_schema(connector, raw_schema, scope)
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


def make_sql_context(
    *,
    connector_type: str = "postgres",
    dialect: str = "postgres",
    allow_raw_rows: bool = False,
    max_result_rows: int = 100,
    allowed_tables: tuple[str, ...] | None = ("sales.customers", "sales.orders", "customers", "orders"),
) -> SQLValidationContext:
    connector = make_connector(connector_type)
    scope = make_scope(
        connector,
        allow_raw_rows=allow_raw_rows,
        max_result_rows=max_result_rows,
        allowed_tables=allowed_tables,
    )
    projected = SchemaProjectionService().project_schema(connector, RAW_SCHEMA, scope)
    return SQLValidationContext(
        dialect=dialect,  # type: ignore[arg-type]
        scope=scope,
        projected_schema=projected,
        connector_type=connector_type,
    )


def violation_codes(decision) -> set[str]:
    return {violation.code for violation in decision.violations}


class ResultPolicyGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = ResultPolicyGateway()

    def validate(self, df: pd.DataFrame, **context_kwargs):
        return self.gateway.validate(df, make_result_context(**context_kwargs))

    def test_safe_aggregate_result_is_allowed(self):
        decision = self.validate(pd.DataFrame({"total_revenue": [1234.5], "count": [12]}))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.decision, "allowed")
        self.assertEqual(decision.safe_result.result_type, "aggregate")

    def test_denied_column_is_redacted_when_result_remains_meaningful(self):
        decision = self.validate(
            pd.DataFrame({"total": [10], "email": ["a@example.com"]}),
            denied_columns=("email",),
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.decision, "redacted")
        self.assertEqual(decision.redacted_columns, ("email",))
        self.assertNotIn("email", decision.safe_result.to_dataframe().columns)

    def test_sensitive_default_column_is_denied_when_only_column(self):
        decision = self.validate(pd.DataFrame({"password_hash": ["$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHijklmno"]}))

        self.assertFalse(decision.allowed)
        self.assertIn("sensitive_column", violation_codes(decision))

    def test_allow_raw_rows_false_blocks_raw_customer_list(self):
        decision = self.validate(
            pd.DataFrame(
                {
                    "id": [1, 2],
                    "email": ["a@example.com", "b@example.com"],
                    "name": ["A", "B"],
                }
            )
        )

        self.assertFalse(decision.allowed)
        self.assertIn("raw_rows_denied", violation_codes(decision))

    def test_allow_raw_rows_true_allows_safe_table_result(self):
        decision = self.validate(
            pd.DataFrame({"id": [1, 2], "total": [10, 20]}),
            allow_raw_rows=True,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.safe_result.row_count, 2)

    def test_result_above_max_rows_is_truncated(self):
        decision = self.validate(
            pd.DataFrame({"total": [1, 2, 3], "count": [10, 11, 12]}),
            max_result_rows=2,
        )

        self.assertTrue(decision.allowed)
        self.assertTrue(decision.safe_result.truncated)
        self.assertEqual(decision.returned_row_count, 2)
        self.assertIn("truncated", " ".join(decision.warnings).lower())

    def test_long_string_values_are_truncated(self):
        decision = self.validate(
            pd.DataFrame({"note": ["x" * 700]}),
            allow_raw_rows=True,
        )

        value = decision.safe_result.rows[0]["note"]
        self.assertTrue(decision.allowed)
        self.assertLess(len(value), 540)
        self.assertIn("[TRUNCATED]", value)

    def test_token_like_values_are_redacted(self):
        secret = "ok_test_abcdefghijklmnopqrstuvwxyz123456"
        decision = self.validate(
            pd.DataFrame({"comment": [secret]}),
            allow_raw_rows=True,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.decision, "redacted")
        self.assertEqual(decision.safe_result.rows[0]["comment"], "[REDACTED]")

    def test_minimum_group_size_suppresses_small_groups(self):
        decision = self.validate(
            pd.DataFrame(
                {
                    "department": ["Sales", "Support"],
                    "count": [2, 8],
                    "total": [100, 200],
                }
            ),
            minimum_group_size=5,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.returned_row_count, 1)
        self.assertEqual(decision.safe_result.rows[0]["department"], "Support")
        self.assertTrue(decision.small_group_warnings)

    def test_safe_single_value_result_is_allowed(self):
        decision = self.validate(pd.DataFrame({"count": [42]}))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.safe_result.result_type, "single_value")

    def test_safe_time_series_result_is_allowed(self):
        decision = self.validate(
            pd.DataFrame(
                {
                    "created_at": pd.to_datetime(["2026-01-01", "2026-01-02"]),
                    "total": [10, 20],
                }
            )
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.safe_result.result_type, "time_series")

    def test_too_many_columns_requires_review(self):
        df = pd.DataFrame({f"metric_{idx}": [idx] for idx in range(55)})
        decision = self.validate(df)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "requires_review")
        self.assertIn("too_many_columns", violation_codes(decision))

    def test_redacted_result_never_contains_original_sensitive_value(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
        decision = self.validate(
            pd.DataFrame({"comment": [secret], "count": [1]}),
            allow_raw_rows=True,
        )

        serialized = self.gateway.to_model_text(decision.safe_result)
        self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_model_safe_serialization_excludes_redacted_column_data(self):
        decision = self.validate(
            pd.DataFrame({"total": [10], "password_hash": ["secret-hash"]}),
        )

        serialized = self.gateway.to_model_text(decision.safe_result)
        self.assertNotIn("password_hash", serialized)
        self.assertNotIn("secret-hash", serialized)
        self.assertIn("total", serialized)

    def test_decision_is_deterministic(self):
        context = make_result_context()
        df = pd.DataFrame({"total_revenue": [1234.5], "count": [12]})

        first = self.gateway.validate(df, context)
        second = self.gateway.validate(df, context)

        self.assertEqual(first, second)

    def test_alias_attempt_to_hide_sensitive_source_is_blocked(self):
        decision = self.validate(
            pd.DataFrame({"customer_identifier": ["a@example.com"]}),
            allow_raw_rows=True,
            sql="SELECT email AS customer_identifier FROM customers",
        )

        self.assertFalse(decision.allowed)

    def test_hidden_projected_column_in_result_is_denied(self):
        decision = self.validate(
            pd.DataFrame({"card_number": ["4242424242424242"]}),
            allow_raw_rows=True,
        )

        self.assertFalse(decision.allowed)
        self.assertIn("column_not_visible", violation_codes(decision))

    def test_safe_error_message_does_not_reveal_sensitive_values(self):
        secret = "ok_test_abcdefghijklmnopqrstuvwxyz123456"
        decision = self.validate(pd.DataFrame({"password_hash": [secret]}))

        self.assertFalse(decision.allowed)
        self.assertNotIn(secret, decision.safe_error_message)
        self.assertNotIn("password_hash", decision.safe_error_message)


class FakeEngine:
    def connect(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeBigQueryRows:
    def __init__(self, df: pd.DataFrame) -> None:
        self.df = df

    def to_dataframe(self) -> pd.DataFrame:
        return self.df


class FakeBigQueryJob:
    def __init__(self, df: pd.DataFrame) -> None:
        self.df = df

    def result(self, timeout: int):
        return FakeBigQueryRows(self.df)


class FakeBigQueryClient:
    def __init__(self, df: pd.DataFrame) -> None:
        self.df = df
        self.last_sql: str | None = None

    def query(self, sql: str):
        self.last_sql = sql
        return FakeBigQueryJob(self.df)


class ResultPolicyConnectorTests(unittest.TestCase):
    def postgres_connector(self, df: pd.DataFrame, *, max_result_rows: int = 100) -> PostgresConnector:
        connector = PostgresConnector.__new__(PostgresConnector)
        connector.allowed_tables = set()
        connector.sql_policy_context = make_sql_context(max_result_rows=max_result_rows)
        connector._get_connection = lambda: object()  # type: ignore[method-assign]
        connector._put_connection = lambda conn: None  # type: ignore[method-assign]
        connector._test_df = df
        return connector

    def test_postgres_safe_sql_result_passes_through_result_policy(self):
        connector = self.postgres_connector(pd.DataFrame({"total": [10, 20]}))

        with patch("orion_gate.connectors.postgres.pd.read_sql", return_value=connector._test_df):
            df, output = connector.execute_query("SELECT total FROM orders")

        self.assertFalse(df.empty)
        self.assertIn("total", output)
        self.assertTrue(connector.last_result_policy_decision.allowed)

    def test_postgres_denied_result_does_not_reach_tool_caller(self):
        connector = self.postgres_connector(pd.DataFrame({"password_hash": ["secret"]}))

        with patch("orion_gate.connectors.postgres.pd.read_sql", return_value=connector._test_df):
            df, output = connector.execute_query("SELECT total FROM orders")

        self.assertTrue(df.empty)
        self.assertIn("Result policy denied", output)
        self.assertFalse(connector.last_result_policy_decision.allowed)

    def test_mysql_safe_sql_result_passes_through_result_policy(self):
        connector = MySQLConnector.__new__(MySQLConnector)
        connector.allowed_tables = set()
        connector.engine = FakeEngine()
        connector.sql_policy_context = make_sql_context(connector_type="mysql", dialect="mysql")

        with patch("orion_gate.connectors.mysql.pd.read_sql", return_value=pd.DataFrame({"total": [10]})):
            df, output = connector.execute_query("SELECT total FROM orders")

        self.assertFalse(df.empty)
        self.assertIn("total", output)
        self.assertTrue(connector.last_result_policy_decision.allowed)

    def test_bigquery_safe_sql_result_passes_through_result_policy(self):
        connector = BigQueryConnector.__new__(BigQueryConnector)
        connector.dataset_ids = set()
        connector.project_id = "demo"
        connector.client = FakeBigQueryClient(pd.DataFrame({"total": [10]}))
        connector.sql_policy_context = make_sql_context(
            connector_type="bigquery",
            dialect="bigquery",
            allowed_tables=("sales.orders",),
        )

        df, output = connector.execute_query("SELECT total FROM `demo.sales.orders`")

        self.assertFalse(df.empty)
        self.assertIn("total", output)
        self.assertTrue(connector.last_result_policy_decision.allowed)

    def test_denied_sensitive_result_returns_safe_error(self):
        connector = self.postgres_connector(pd.DataFrame({"password_hash": ["secret"]}))

        with patch("orion_gate.connectors.postgres.pd.read_sql", return_value=connector._test_df):
            _, output = connector.execute_query("SELECT total FROM orders")

        self.assertIn("Result policy denied", output)
        self.assertNotIn("password_hash", output)
        self.assertNotIn("secret", output)

    def test_truncated_result_includes_warning(self):
        connector = self.postgres_connector(
            pd.DataFrame({"total": [1, 2, 3], "count": [10, 11, 12]}),
            max_result_rows=2,
        )

        with patch("orion_gate.connectors.postgres.pd.read_sql", return_value=connector._test_df):
            df, output = connector.execute_query("SELECT total FROM orders")

        self.assertEqual(len(df.index), 2)
        self.assertIn("truncated", output.lower())

    def test_connector_rejects_arbitrary_python_without_exec(self):
        connector = self.postgres_connector(pd.DataFrame())
        df, output = connector.execute_query("import os; result = pd.DataFrame({'x': [1]})")
        self.assertTrue(df.empty)
        self.assertIn("only executes read-only SELECT/WITH SQL", output)


if __name__ == "__main__":
    unittest.main()
