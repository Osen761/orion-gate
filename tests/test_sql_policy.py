"""Phase 1D SQL policy gateway tests."""

from __future__ import annotations

import unittest
import uuid

from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.connectors.postgres import PostgresConnector
from orion_gate.models import Connector
from orion_gate.security.schema_projection import ProjectedSchema, SchemaProjectionService
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


RAW_SCHEMA = """Dataset: sales
Table: customers (10 rows)
  - id: integer
  - email: text
  - name: text
  - created_at: timestamp
  - password_hash: text
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
    allowed_tables: tuple[str, ...] | None = ("customers", "orders", "invoices"),
    denied_tables: tuple[str, ...] = (),
    allowed_columns: tuple[str, ...] | None = None,
    denied_columns: tuple[str, ...] = (),
    max_result_rows: int = 100,
    max_execution_seconds: int = 17,
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
        denied_tables=denied_tables,
        allowed_columns=allowed_columns,
        denied_columns=denied_columns,
        max_result_rows=max_result_rows,
        max_execution_seconds=max_execution_seconds,
    )


def make_context(
    *,
    dialect: str = "postgres",
    raw_schema: str = RAW_SCHEMA,
    connector_type: str | None = None,
    **scope_kwargs,
) -> SQLValidationContext:
    connector = make_connector(connector_type or dialect)
    scope = make_scope(connector, **scope_kwargs)
    projected = SchemaProjectionService().project_schema(connector, raw_schema, scope)
    return SQLValidationContext(
        dialect=dialect,  # type: ignore[arg-type]
        scope=scope,
        projected_schema=projected,
        connector_type=connector.type,
    )


def violation_codes(decision) -> set[str]:
    return {violation.code for violation in decision.violations}


class SQLPolicyGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()

    def validate(self, sql: str, **context_kwargs):
        return self.gateway.validate(sql, make_context(**context_kwargs))

    def test_select_is_allowed_and_limited(self):
        decision = self.validate("SELECT id, email FROM customers")

        self.assertTrue(decision.allowed)
        self.assertIn("LIMIT 100", decision.safe_sql or "")
        self.assertTrue(decision.row_limit_applied)
        self.assertEqual(decision.timeout_seconds, 17)

    def test_with_final_select_is_allowed(self):
        decision = self.validate(
            "WITH recent AS (SELECT id, total FROM orders) SELECT id, total FROM recent"
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.statement_type, "with")

    def test_insert_is_denied(self):
        decision = self.validate("INSERT INTO customers (id) VALUES (1)")

        self.assertFalse(decision.allowed)
        self.assertIn("non_read_only_statement", violation_codes(decision))

    def test_drop_is_denied(self):
        decision = self.validate("DROP TABLE customers")

        self.assertFalse(decision.allowed)
        self.assertIn("non_read_only_statement", violation_codes(decision))

    def test_multiple_statements_are_denied(self):
        decision = self.validate("SELECT id FROM customers; SELECT id FROM orders")

        self.assertFalse(decision.allowed)
        self.assertIn("multiple_statements", violation_codes(decision))

    def test_projected_hidden_table_is_denied(self):
        decision = self.validate("SELECT employee_id FROM payroll")

        self.assertFalse(decision.allowed)
        self.assertIn("table_not_allowed", violation_codes(decision))

    def test_scope_denied_table_is_denied(self):
        decision = self.validate(
            "SELECT id, total FROM orders",
            denied_tables=("orders",),
        )

        self.assertFalse(decision.allowed)
        self.assertIn("table_denied", violation_codes(decision))

    def test_hidden_sensitive_column_is_denied(self):
        decision = self.validate("SELECT id, password_hash FROM customers")

        self.assertFalse(decision.allowed)
        self.assertIn("column_not_visible", violation_codes(decision))

    def test_select_star_is_denied(self):
        decision = self.validate("SELECT * FROM customers")

        self.assertFalse(decision.allowed)
        self.assertIn("select_star_denied", violation_codes(decision))

    def test_alias_does_not_hide_denied_column(self):
        decision = self.validate("SELECT password_hash AS safe_name FROM customers")

        self.assertFalse(decision.allowed)
        self.assertIn("column_not_visible", violation_codes(decision))

    def test_union_all_is_allowed(self):
        decision = self.validate(
            "SELECT id FROM customers UNION ALL SELECT customer_id FROM orders"
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.statement_type, "set_operation")

    def test_subquery_is_allowed(self):
        decision = self.validate(
            "SELECT id, total FROM (SELECT id, total FROM orders) AS recent"
        )

        self.assertTrue(decision.allowed)

    def test_cte_is_allowed(self):
        decision = self.validate(
            "WITH totals AS (SELECT customer_id, total FROM orders) SELECT customer_id, total FROM totals"
        )

        self.assertTrue(decision.allowed)

    def test_metadata_table_is_denied(self):
        decision = self.validate("SELECT table_name FROM information_schema.tables")

        self.assertFalse(decision.allowed)
        self.assertIn("metadata_table_denied", violation_codes(decision))

    def test_existing_low_limit_is_preserved(self):
        decision = self.validate("SELECT id FROM customers LIMIT 5")

        self.assertTrue(decision.allowed)
        self.assertFalse(decision.row_limit_applied)
        self.assertIn("LIMIT 5", decision.safe_sql or "")

    def test_existing_high_limit_is_reduced(self):
        decision = self.validate("SELECT id FROM customers LIMIT 5000")

        self.assertTrue(decision.allowed)
        self.assertTrue(decision.row_limit_applied)
        self.assertIn("LIMIT 100", decision.safe_sql or "")

    def test_recursive_cte_is_denied(self):
        decision = self.validate(
            "WITH RECURSIVE nums AS (SELECT id FROM customers) SELECT id FROM nums"
        )

        self.assertFalse(decision.allowed)
        self.assertIn("recursive_cte_denied", violation_codes(decision))

    def test_too_many_joins_are_denied(self):
        raw_schema = "\n".join(
            [f"Table: t{i} (1 rows)\n  - id: integer" for i in range(11)]
        )
        sql = "SELECT t0.id FROM t0 " + " ".join(
            f"JOIN t{i} ON t{i}.id = t0.id" for i in range(1, 10)
        )
        decision = self.validate(
            sql,
            raw_schema=raw_schema,
            allowed_tables=tuple(f"t{i}" for i in range(11)),
        )

        self.assertFalse(decision.allowed)
        self.assertIn("too_many_joins", violation_codes(decision))

    def test_too_many_ctes_are_denied(self):
        ctes = ", ".join(f"c{i} AS (SELECT id FROM customers)" for i in range(9))
        decision = self.validate(f"WITH {ctes} SELECT id FROM c0")

        self.assertFalse(decision.allowed)
        self.assertIn("too_many_ctes", violation_codes(decision))

    def test_unparseable_sql_is_denied(self):
        decision = self.validate("SELECT FROM WHERE")

        self.assertFalse(decision.allowed)
        self.assertIn("unparseable_sql", violation_codes(decision))

    def test_unsafe_function_is_denied(self):
        decision = self.validate("SELECT id FROM customers WHERE pg_sleep(1) IS NULL")

        self.assertFalse(decision.allowed)
        self.assertIn("unsafe_function", violation_codes(decision))

    def test_bigquery_qualified_table_is_allowed(self):
        decision = self.validate(
            "SELECT id, total FROM `demo.sales.orders`",
            dialect="bigquery",
            connector_type="bigquery",
            allowed_tables=("sales.orders",),
        )

        self.assertTrue(decision.allowed)
        self.assertIn("`demo.sales.orders`", decision.safe_sql or "")

    def test_bigquery_information_schema_is_denied(self):
        decision = self.validate(
            "SELECT job_id FROM `demo.region-us.INFORMATION_SCHEMA.JOBS_BY_PROJECT`",
            dialect="bigquery",
            connector_type="bigquery",
            allowed_tables=None,
        )

        self.assertFalse(decision.allowed)
        self.assertIn("metadata_table_denied", violation_codes(decision))

    def test_mysql_backtick_table_is_allowed(self):
        decision = self.validate(
            "SELECT id, total FROM `orders`",
            dialect="mysql",
            connector_type="mysql",
        )

        self.assertTrue(decision.allowed)
        self.assertIn("`orders`", decision.safe_sql or "")

    def test_decisions_are_deterministic(self):
        context = make_context()

        first = self.gateway.validate("SELECT id FROM customers", context)
        second = self.gateway.validate("SELECT id FROM customers", context)

        self.assertEqual(first, second)

    def test_table_alias_qualified_columns_are_allowed(self):
        decision = self.validate("SELECT c.id, c.email FROM customers AS c")

        self.assertTrue(decision.allowed)

    def test_unknown_column_is_denied(self):
        decision = self.validate("SELECT missing_column FROM customers")

        self.assertFalse(decision.allowed)
        self.assertIn("column_not_visible", violation_codes(decision))

    def test_allowed_columns_scope_is_enforced(self):
        decision = self.validate(
            "SELECT id, email FROM customers",
            allowed_columns=("customers.id",),
        )

        self.assertFalse(decision.allowed)
        self.assertIn("column_not_allowed", violation_codes(decision))

    def test_injection_attempt_with_hidden_table_is_denied(self):
        decision = self.validate(
            "SELECT id FROM customers WHERE id IN (SELECT employee_id FROM payroll)"
        )

        self.assertFalse(decision.allowed)
        self.assertIn("table_not_allowed", violation_codes(decision))

    def test_safe_error_does_not_expose_hidden_identifier(self):
        decision = self.validate("SELECT password_hash FROM customers")

        self.assertFalse(decision.allowed)
        self.assertNotIn("password_hash", decision.safe_error_message)
        self.assertNotIn("customers", decision.safe_error_message)

    def test_denied_sql_connector_path_does_not_need_database_connection(self):
        connector = PostgresConnector.__new__(PostgresConnector)
        connector.allowed_tables = set()
        connector.sql_policy_context = make_context()

        df, output = connector.execute_query("SELECT password_hash FROM customers")

        self.assertTrue(df.empty)
        self.assertIn("SQL policy denied", output)
        self.assertFalse(connector.last_sql_policy_decision.allowed)

    def test_projected_schema_type_is_carried_in_context(self):
        context = make_context()

        self.assertIsInstance(context.projected_schema, ProjectedSchema)


if __name__ == "__main__":
    unittest.main()
