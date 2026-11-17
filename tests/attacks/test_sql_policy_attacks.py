"""SQL policy bypass attack tests."""

from __future__ import annotations

import unittest

from orion_gate.security.sql_policy import SQLPolicyGateway

from tests.attacks.helpers import make_sql_context


def _many_table_schema(count: int = 14) -> str:
    lines = ["Dataset: sales"]
    for index in range(count):
        lines.append(f"Table: t{index}")
        lines.append("  - id: integer")
        lines.append("  - total: numeric")
    return "\n".join(lines)


SQL_ATTACKS = {
    "drop_table": ("DROP TABLE users", {}),
    "select_star": ("SELECT * FROM customers", {}),
    "alias_denied_column": ("SELECT email AS customer_id FROM customers", {}),
    "union_denied_column": ("SELECT id FROM customers UNION ALL SELECT password_hash FROM customers", {}),
    "cte_denied_table": ("WITH p AS (SELECT employee_id FROM payroll) SELECT employee_id FROM p", {}),
    "subquery_hidden_table": ("SELECT id FROM orders WHERE customer_id IN (SELECT employee_id FROM payroll)", {}),
    "multi_statement_injection": ("SELECT id FROM orders; DROP TABLE customers", {}),
    "comment_hiding_write_statement": ("SELECT id FROM orders /* DROP TABLE customers */", {}),
    "quoted_denied_table": ('SELECT "employee_id" FROM "payroll"', {}),
    "case_mixed_denied_keyword": ("DrOp TABLE customers", {}),
    "bigquery_information_schema": (
        "SELECT table_name FROM `project.sales.INFORMATION_SCHEMA.TABLES`",
        {"dialect": "bigquery", "connector_type": "bigquery"},
    ),
    "postgres_pg_catalog": ("SELECT relname FROM pg_catalog.pg_class", {}),
    "mysql_performance_schema": (
        "SELECT table_name FROM performance_schema.tables",
        {"dialect": "mysql", "connector_type": "mysql"},
    ),
    "unsafe_pg_sleep": ("SELECT pg_sleep(1)", {}),
    "unsafe_load_file": ("SELECT load_file('/etc/passwd')", {"dialect": "mysql", "connector_type": "mysql"}),
    "unsafe_current_user": ("SELECT current_user", {}),
    "recursive_cte": (
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT n FROM r",
        {},
    ),
    "excessive_joins": (
        "SELECT orders.id FROM orders "
        + " ".join(f"JOIN orders o{i} ON o{i}.id = orders.id" for i in range(9)),
        {},
    ),
    "excessive_ctes": (
        "WITH "
        + ", ".join(f"c{i} AS (SELECT id FROM orders)" for i in range(9))
        + " SELECT id FROM c8",
        {},
    ),
    "excessive_sql_length": ("SELECT id FROM orders WHERE status = '" + ("x" * 10_100) + "'", {}),
    "unknown_table": ("SELECT id FROM shadow_customers", {}),
    "unknown_column": ("SELECT credit_card_number FROM customers", {}),
    "set_role": ("SET ROLE admin", {}),
    "copy_statement": ("COPY customers TO STDOUT", {}),
    "call_statement": ("CALL refresh_materialized_view()", {}),
    "create_temp_table": ("CREATE TEMP TABLE tmp AS SELECT id FROM customers", {}),
    "metadata_probe_sys_table": ("SELECT name FROM sys.tables", {"dialect": "mysql", "connector_type": "mysql"}),
}


class SQLPolicyAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()

    def assert_denied(self, sql: str, **context_kwargs):
        raw_schema = context_kwargs.pop("raw_schema", None)
        if raw_schema is None:
            context = make_sql_context(**context_kwargs)
        else:
            context = make_sql_context(raw_schema=raw_schema, **context_kwargs)
        decision = self.gateway.validate(sql, context)

        self.assertFalse(decision.allowed, sql)
        self.assertTrue(decision.violations, sql)
        self.assertIsNone(decision.safe_sql)
        self.assertIn("SQL policy denied", decision.safe_error_message)
        self.assertNotIn("payroll", decision.safe_error_message.lower())
        self.assertNotIn("password_hash", decision.safe_error_message.lower())

    def test_allowed_direct_select_with_explicit_columns_still_passes(self):
        decision = self.gateway.validate("SELECT id, total FROM orders", make_sql_context())

        self.assertTrue(decision.allowed)
        self.assertIn("LIMIT", decision.safe_sql or "")


def _make_attack_test(name: str, sql: str, context_kwargs: dict):
    def test(self):
        self.assert_denied(sql, **context_kwargs)

    test.__name__ = f"test_{name}_is_denied"
    return test


for _name, (_sql, _context_kwargs) in SQL_ATTACKS.items():
    setattr(SQLPolicyAttackTests, f"test_{_name}_is_denied", _make_attack_test(_name, _sql, _context_kwargs))
