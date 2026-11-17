"""Tests for real-world SQL agent security edge cases across Orion Gate layers."""

from __future__ import annotations

import json
import unittest
import uuid
from unittest.mock import MagicMock, patch

import pandas as pd
from fastapi.testclient import TestClient

from orion_gate.authz.connectors import EffectiveAccessScope, TenantFilter
from orion_gate.connectors.bigquery import BigQueryConnector
from orion_gate.connectors.mysql import MySQLConnector
from orion_gate.connectors.postgres import PostgresConnector
from orion_gate.models import Connector
from orion_gate.gate_app import app
from orion_gate.security.differencing import reset_differencing_store
from orion_gate.security.orion_yaml import (
    clear_active_orion_yaml,
    parse_orion_yaml,
    set_active_orion_yaml,
)
from orion_gate.security.result_policy import ResultPolicyGateway, ResultValidationContext
from orion_gate.security.schema_projection import SchemaProjectionService
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


EDGE_CASE_SCHEMA = """Table: users (100 rows)
  - id: integer
  - org_id: text
  - country: text
  - region: text
  - department: text
  - email: text
  - customer_phone: text
  - ssn: text
  - password_hash: text
Table: orders (500 rows)
  - id: integer
  - org_id: text
  - customer_id: integer
  - total: numeric
  - status: text
  - customer_email: text
  - customer_phone: text
Table: events (1000 rows)
  - id: integer
  - org_id: text
  - event_type: text
  - metadata: jsonb
  - payload: json
"""


def _make_connector(connector_type: str = "postgres") -> Connector:
    return Connector(
        id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        type=connector_type,
        name="ProdDB",
        secret_id="fernet:secret",
        is_active=True,
        workspace_default_access="restricted",
    )


def _make_scope(
    connector: Connector,
    *,
    access_level: str = "query",
    allow_json_columns: bool = False,
    allowed_json_paths: tuple[str, ...] = (),
    allow_cross_joins: bool = False,
    allow_raw_pii: bool = False,
    pii_masking_columns: tuple[str, ...] = ("email", "customer_email", "customer_phone"),
    minimum_group_size: int | None = None,
    max_query_cost: float | None = None,
    max_bytes_billed: int | None = None,
    tenant_filters: tuple[TenantFilter, ...] = (),
    denied_columns: tuple[str, ...] = ("password_hash", "ssn"),
) -> EffectiveAccessScope:
    return EffectiveAccessScope(
        workspace_id=str(connector.workspace_id),
        surface="gateway",
        principal_type="api_key",
        user_id="user-1",
        member_id=None,
        role="member",
        connector_id=str(connector.id),
        connector_access_level=access_level,
        allowed_tables=("users", "orders", "events"),
        denied_columns=denied_columns,
        tenant_filters=tenant_filters,
        allow_raw_rows=True,
        allow_json_columns=allow_json_columns,
        allowed_json_paths=allowed_json_paths,
        allow_cross_joins=allow_cross_joins,
        allow_raw_pii=allow_raw_pii,
        pii_masking_columns=pii_masking_columns,
        minimum_group_size=minimum_group_size,
        max_query_cost=max_query_cost,
        max_bytes_billed=max_bytes_billed,
    )


class JSONColumnLeakTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()
        self.connector = _make_connector()

    def test_raw_json_columns_are_hidden_by_default_in_schema_projection(self) -> None:
        scope = _make_scope(self.connector)
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )

        self.assertNotIn("metadata", projected.schema_text)
        self.assertNotIn("payload", projected.schema_text)
        self.assertIn("events.metadata", projected.denied_columns)
        self.assertIn("events.payload", projected.denied_columns)

    def test_json_path_extraction_requires_explicit_allowlist(self) -> None:
        scope = _make_scope(
            self.connector,
            allowed_json_paths=("events.metadata.region",),
        )
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )
        ctx = SQLValidationContext(
            dialect="postgres", scope=scope, projected_schema=projected
        )

        # Explicitly allowlisted JSON path succeeds
        ok = self.gateway.validate("SELECT metadata->>'region' FROM events", ctx)
        self.assertTrue(ok.allowed, ok.violations)

        # Unlisted secret JSON key is blocked
        denied_secret = self.gateway.validate(
            "SELECT metadata->>'api_secret' FROM events", ctx
        )
        self.assertFalse(denied_secret.allowed)
        self.assertIn("json_path_not_allowed", {v.code for v in denied_secret.violations})

        # Raw projection or text cast of JSONB column is blocked
        denied_raw = self.gateway.validate("SELECT metadata FROM events", ctx)
        self.assertFalse(denied_raw.allowed)
        self.assertIn("json_column_denied", {v.code for v in denied_raw.violations})

        denied_cast = self.gateway.validate("SELECT metadata::text FROM events", ctx)
        self.assertFalse(denied_cast.allowed)

        # row_to_json / json_extract / json_value are blocked
        denied_row = self.gateway.validate("SELECT row_to_json(events) FROM events", ctx)
        self.assertFalse(denied_row.allowed)

        denied_fn = self.gateway.validate(
            "SELECT JSON_VALUE(metadata, '$.api_secret') FROM events", ctx
        )
        self.assertFalse(denied_fn.allowed)

    def test_even_when_json_columns_allowed_sensitive_keys_are_blocked(self) -> None:
        scope = _make_scope(self.connector, allow_json_columns=True)
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )
        ctx = SQLValidationContext(
            dialect="postgres", scope=scope, projected_schema=projected
        )

        ok = self.gateway.validate("SELECT metadata->>'region' FROM events", ctx)
        self.assertTrue(ok.allowed)

        denied = self.gateway.validate("SELECT metadata->>'api_secret' FROM events", ctx)
        self.assertFalse(denied.allowed)
        self.assertIn("json_sensitive_path_denied", {v.code for v in denied.violations})

        denied_brace = self.gateway.validate(
            "SELECT metadata #>> '{nested,api_secret}' FROM events", ctx
        )
        self.assertFalse(denied_brace.allowed)
        self.assertIn("json_sensitive_path_denied", {v.code for v in denied_brace.violations})

    def test_layer4_scrubs_embedded_secrets_ssns_and_unmasked_emails(self) -> None:
        scope = _make_scope(self.connector, allow_raw_pii=False)
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )
        res_ctx = ResultValidationContext(scope=scope, projected_schema=projected)
        df = pd.DataFrame(
            {
                "event_type": [
                    "api_secret=supersecretvalue123",
                    "AKIAIOSFODNN7EXAMPLE",
                    "123-45-6789",
                    "contact alice@acme.io for details",
                    "masked a***@acme.io and ***-***-0199 stay intact",
                    "call +1 (415) 555-0199 or 415-555-0199",
                    "card 4111-1111-1111-1111 failed",
                ]
            }
        )
        decision = ResultPolicyGateway().validate(df, res_ctx)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.decision, "redacted")
        rows = [r["event_type"] for r in decision.safe_result.rows]
        self.assertEqual(rows[0], "[REDACTED]")
        self.assertEqual(rows[1], "[REDACTED]")
        self.assertEqual(rows[2], "[REDACTED]")
        self.assertNotIn("alice@acme.io", rows[3])
        self.assertIn("[REDACTED_EMAIL]", rows[3])
        self.assertIn("a***@acme.io", rows[4])
        self.assertIn("***-***-0199", rows[4])
        self.assertNotIn("415-555-0199", rows[5])
        self.assertIn("[REDACTED_PHONE]", rows[5])
        self.assertNotIn("4111-1111-1111-1111", rows[6])
        self.assertIn("[REDACTED_CARD]", rows[6])


class CTEAndAliasShadowingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()
        self.connector = _make_connector()
        self.tenant_filters = (
            TenantFilter(table="users", column="org_id", value="org_acme", required=True),
            TenantFilter(table="orders", column="org_id", value="org_acme", required=True),
        )
        self.scope = _make_scope(self.connector, tenant_filters=self.tenant_filters)
        self.projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, self.scope
        )

    def test_cte_with_same_name_as_base_table_cannot_bypass_tenant_injection(self) -> None:
        ctx = SQLValidationContext(
            dialect="postgres",
            scope=self.scope,
            projected_schema=self.projected,
            auto_inject_tenant_filters=True,
        )
        decision = self.gateway.validate(
            "WITH users AS (SELECT id FROM users) SELECT id FROM users",
            ctx,
        )
        self.assertTrue(decision.allowed, decision.violations)
        self.assertTrue(decision.tenant_predicates_injected)
        self.assertIn("users.org_id = 'org_acme'", decision.safe_sql or "")

        # Without auto-inject, missing tenant predicate inside shadowed CTE is denied
        strict_ctx = SQLValidationContext(
            dialect="postgres",
            scope=self.scope,
            projected_schema=self.projected,
            auto_inject_tenant_filters=False,
        )
        denied = self.gateway.validate(
            "WITH users AS (SELECT id FROM users) SELECT id FROM users",
            strict_ctx,
        )
        self.assertFalse(denied.allowed)
        self.assertIn("tenant_predicate_missing", {v.code for v in denied.violations})

    def test_reused_table_alias_across_ctes_validates_against_correct_table(self) -> None:
        ctx = SQLValidationContext(
            dialect="postgres",
            scope=self.scope,
            projected_schema=self.projected,
            auto_inject_tenant_filters=True,
        )
        # Valid: u is users in c1 and orders in c2
        ok = self.gateway.validate(
            "WITH c1 AS (SELECT u.id FROM users u), "
            "c2 AS (SELECT u.total FROM orders u) "
            "SELECT c1.id, c2.total FROM c1 JOIN c2 ON c1.id = c2.total",
            ctx,
        )
        self.assertTrue(ok.allowed, ok.violations)

        # Invalid: c1 aliases users as u, then selects orders-only column u.total
        bad = self.gateway.validate(
            "WITH c1 AS (SELECT u.total FROM users u), "
            "c2 AS (SELECT u.total FROM orders u) "
            "SELECT c1.total FROM c1",
            ctx,
        )
        self.assertFalse(bad.allowed)
        self.assertIn("column_not_visible", {v.code for v in bad.violations})

    def test_cte_output_columns_are_enforced_in_outer_query(self) -> None:
        ctx = SQLValidationContext(
            dialect="postgres",
            scope=self.scope,
            projected_schema=self.projected,
            auto_inject_tenant_filters=True,
        )
        denied = self.gateway.validate(
            "WITH t AS (SELECT id FROM users) SELECT t.region FROM t",
            ctx,
        )
        self.assertFalse(denied.allowed)
        self.assertIn("column_not_visible", {v.code for v in denied.violations})

    def test_explicit_cte_and_subquery_column_lists_work_and_block_pii_renames(self) -> None:
        scope = _make_scope(
            self.connector,
            pii_masking_columns=("email", "customer_phone"),
            tenant_filters=self.tenant_filters,
        )
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )
        ctx = SQLValidationContext(
            dialect="postgres",
            scope=scope,
            projected_schema=projected,
            auto_inject_tenant_filters=True,
        )

        # Legitimate explicit column list renames on CTE and derived table
        ok_cte = self.gateway.validate(
            "WITH t(uid, reg) AS (SELECT id, region FROM users) SELECT t.uid, t.reg FROM t",
            ctx,
        )
        self.assertTrue(ok_cte.allowed, ok_cte.violations)
        self.assertIn("org_acme", ok_cte.safe_sql)

        ok_sub = self.gateway.validate(
            "SELECT uid, reg FROM (SELECT id, region FROM users) AS s(uid, reg)",
            ctx,
        )
        self.assertTrue(ok_sub.allowed, ok_sub.violations)
        self.assertIn("org_acme", ok_sub.safe_sql)

        # Positional column rename cannot hide masked PII behind an aggregate-looking alias
        bad_cte = self.gateway.validate(
            "WITH t(total_count) AS (SELECT email FROM users) SELECT total_count FROM t",
            ctx,
        )
        self.assertFalse(bad_cte.allowed)
        self.assertIn("sensitive_alias_denied", {v.code for v in bad_cte.violations})

        bad_sub = self.gateway.validate(
            "SELECT total_count FROM (SELECT customer_phone FROM orders) AS s(total_count)",
            ctx,
        )
        self.assertFalse(bad_sub.allowed)
        self.assertIn("sensitive_alias_denied", {v.code for v in bad_sub.violations})


class DoSAndCostGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()
        self.connector = _make_connector()
        self.scope = _make_scope(self.connector)
        self.projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, self.scope
        )
        self.ctx = SQLValidationContext(
            dialect="postgres", scope=self.scope, projected_schema=self.projected
        )

    def test_cross_join_implicit_comma_join_and_tautology_join_are_denied(self) -> None:
        for sql in (
            "SELECT a.id FROM orders a CROSS JOIN orders b",
            "SELECT a.id FROM orders a, orders b",
            "SELECT a.id FROM orders a JOIN orders b ON 1 = 1",
        ):
            decision = self.gateway.validate(sql, self.ctx)
            self.assertFalse(decision.allowed, sql)
            self.assertIn("cross_join_denied", {v.code for v in decision.violations})

    def test_table_valued_generate_series_and_redos_are_denied(self) -> None:
        gen = self.gateway.validate(
            "SELECT id FROM generate_series(1, 1000000) AS g", self.ctx
        )
        self.assertFalse(gen.allowed)

        redos = self.gateway.validate(
            "SELECT id FROM orders WHERE status ~* '(a+)+'", self.ctx
        )
        self.assertFalse(redos.allowed)
        self.assertIn("unsafe_regex_denied", {v.code for v in redos.violations})

        pii_regex = self.gateway.validate(
            "SELECT id FROM users WHERE email ~ '^a'", self.ctx
        )
        self.assertFalse(pii_regex.allowed)
        self.assertIn("unsafe_regex_denied", {v.code for v in pii_regex.violations})

    def test_postgres_explain_cost_check_blocks_expensive_query(self) -> None:
        pg = PostgresConnector.__new__(PostgresConnector)
        pg.allowed_tables = set()
        pg.sql_policy_context = SQLValidationContext(
            dialect="postgres",
            scope=_make_scope(self.connector, max_query_cost=500.0),
            projected_schema=self.projected,
        )
        cursor = MagicMock()
        cursor.fetchone.return_value = ([{"Plan": {"Total Cost": 25000.0}}],)
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        pg._get_connection = lambda: conn  # type: ignore[method-assign]
        pg._put_connection = lambda c: None  # type: ignore[method-assign]

        df, out = pg.execute_query("SELECT id FROM orders")
        self.assertTrue(df.empty)
        self.assertIn("Query cost exceeds policy threshold", out)

    def test_mysql_applies_session_execution_timeout_and_cost_check(self) -> None:
        mysql = MySQLConnector.__new__(MySQLConnector)
        mysql.allowed_tables = set()
        mysql.sql_policy_context = SQLValidationContext(
            dialect="mysql",
            scope=_make_scope(self.connector, max_query_cost=100.0),
            projected_schema=self.projected,
        )
        conn = MagicMock()
        explain_result = MagicMock()
        explain_result.fetchone.return_value = (
            json.dumps({"query_block": {"cost_info": {"query_cost": "9999.5"}}}),
        )
        conn.execute.return_value = explain_result
        engine = MagicMock()
        engine.connect.return_value.__enter__.return_value = conn
        mysql.engine = engine

        df, out = mysql.execute_query("SELECT id FROM orders")
        self.assertTrue(df.empty)
        self.assertIn("Query cost exceeds policy threshold", out)
        executed_sqls = [str(call.args[0]) for call in conn.execute.call_args_list]
        self.assertTrue(any("max_execution_time" in s for s in executed_sqls))

    def test_bigquery_sets_maximum_bytes_billed_and_cancels_on_timeout(self) -> None:
        bq = BigQueryConnector.__new__(BigQueryConnector)
        bq.dataset_ids = set()
        bq.project_id = "demo"
        bq.sql_policy_context = SQLValidationContext(
            dialect="bigquery",
            scope=_make_scope(self.connector, max_bytes_billed=50_000_000),
            projected_schema=self.projected,
        )
        job = MagicMock()
        job.result.side_effect = TimeoutError("timed out")
        client = MagicMock()
        client.query.return_value = job
        bq.client = client

        df, out = bq.execute_query("SELECT id FROM orders")
        self.assertTrue(df.empty)
        self.assertIn("timed out", out)
        job.cancel.assert_called_once()
        _, kwargs = client.query.call_args
        self.assertEqual(kwargs["job_config"].maximum_bytes_billed, 50_000_000)


class KAnonymityAndDifferencingTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_differencing_store()
        clear_active_orion_yaml()
        self.gateway = SQLPolicyGateway()
        self.connector = _make_connector()

    def tearDown(self) -> None:
        clear_active_orion_yaml()
        reset_differencing_store()

    def test_aliased_count_column_cannot_bypass_minimum_group_size(self) -> None:
        scope = _make_scope(self.connector, minimum_group_size=5)
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )
        sql_decision = self.gateway.validate(
            "SELECT department, COUNT(*) AS people FROM users GROUP BY department",
            SQLValidationContext(dialect="postgres", scope=scope, projected_schema=projected),
        )
        self.assertTrue(sql_decision.allowed)
        self.assertIn("people", sql_decision.count_output_columns)

        res_decision = ResultPolicyGateway().validate(
            pd.DataFrame({"department": ["HR", "Eng"], "people": [2, 12]}),
            ResultValidationContext(
                scope=scope,
                projected_schema=projected,
                sql_policy_decision=sql_decision,
            ),
        )
        self.assertTrue(res_decision.allowed)
        self.assertEqual(res_decision.returned_row_count, 1)
        self.assertEqual(res_decision.safe_result.rows[0]["department"], "Eng")

    def test_differencing_attack_blocked_across_gateway_session(self) -> None:
        cfg = parse_orion_yaml(
            {
                "version": "1.0",
                "datasource": {"name": "db", "dialect": "postgres", "url": "postgresql://u:p@localhost/db"},
                "policy": {
                    "allowed_tables": ["users"],
                    "limits": {
                        "minimum_group_size": 5,
                        "differencing_budget": 3,
                        "differencing_window_seconds": 300,
                    },
                },
                "auth": {"static_tokens": ["secret-token"]},
            }
        )
        set_active_orion_yaml(cfg)

        class _FakeConn:
            def __init__(self) -> None:
                self.sql_policy_context = None
                self.last_result_policy_decision = None

            def get_schema(self) -> str:
                return EDGE_CASE_SCHEMA

            def execute_sql(self, sql: str):
                assert self.sql_policy_context is not None
                sql_dec = SQLPolicyGateway().validate(sql, self.sql_policy_context)
                df = pd.DataFrame({"people": [105]})
                res_dec = ResultPolicyGateway().validate(
                    df,
                    ResultValidationContext(
                        scope=self.sql_policy_context.scope,
                        projected_schema=self.sql_policy_context.projected_schema,
                        sql_policy_decision=sql_dec,
                    ),
                )
                self.last_result_policy_decision = res_dec
                return res_dec.safe_result.to_dataframe(), "ok"

            def close(self) -> None:
                return None

        client = TestClient(app)
        headers = {"Authorization": "Bearer secret-token"}
        with patch("orion_gate.security.firewall.get_connector", return_value=_FakeConn()):
            r1 = client.post(
                "/v1/query",
                headers=headers,
                json={"sql": "SELECT COUNT(*) AS people FROM users WHERE country = 'Uganda'"},
            )
            self.assertEqual(r1.status_code, 200)
            self.assertTrue(r1.json()["allowed"])

            # Identical repeat does not trigger differencing block
            r_repeat = client.post(
                "/v1/query",
                headers=headers,
                json={"sql": "SELECT COUNT(*) AS people FROM users WHERE country = 'Uganda'"},
            )
            self.assertEqual(r_repeat.status_code, 200)
            self.assertTrue(r_repeat.json()["allowed"])

            # Complementary exclusion predicate is blocked immediately
            r2 = client.post(
                "/v1/query",
                headers=headers,
                json={
                    "sql": "SELECT COUNT(*) AS people FROM users WHERE country = 'Uganda' AND region != 'Mbarara'"
                },
            )
            self.assertEqual(r2.status_code, 403)
            self.assertFalse(r2.json()["allowed"])
            self.assertEqual(r2.json()["status"], "denied")
            self.assertIn(
                "differencing_attack_denied",
                {v["code"] for v in r2.json()["policy"]["violations"]},
            )

            # Alias-swapped + SUM(CASE ...) negation or range-exclusion is also blocked
            r3 = client.post(
                "/v1/query",
                headers=headers,
                json={
                    "sql": (
                        "SELECT SUM(CASE WHEN country = 'Uganda' AND region != 'Mbarara' "
                        "THEN 1 ELSE 0 END) AS headcount FROM users"
                    )
                },
            )
            self.assertEqual(r3.status_code, 403)
            self.assertIn(
                "differencing_attack_denied",
                {v["code"] for v in r3.json()["policy"]["violations"]},
            )

            r4 = client.post(
                "/v1/query",
                headers=headers,
                json={
                    "sql": (
                        "SELECT COUNT(*) AS headcount FROM users "
                        "WHERE country = 'Uganda' AND (region < 'Mbarara' OR region > 'Mbarara')"
                    )
                },
            )
            self.assertEqual(r4.status_code, 403)
            self.assertIn(
                "differencing_attack_denied",
                {v["code"] for v in r4.json()["policy"]["violations"]},
            )

            # COUNT(NULLIF(...)) exclusion and single-query multi-count differencing are blocked
            r5 = client.post(
                "/v1/query",
                headers=headers,
                json={
                    "sql": (
                        "SELECT COUNT(NULLIF(region, 'Mbarara')) AS non_mbarara "
                        "FROM users WHERE country = 'Uganda'"
                    )
                },
            )
            self.assertEqual(r5.status_code, 403)
            self.assertIn(
                "differencing_attack_denied",
                {v["code"] for v in r5.json()["policy"]["violations"]},
            )

            for single_sql in (
                "SELECT COUNT(*) AS total_cnt, COUNT(NULLIF(region, 'Mbarara')) AS non_mbarara FROM users",
                "SELECT COUNT(*) AS total_cnt, COUNT(*) FILTER (WHERE region != 'Mbarara') AS non_mbarara FROM users",
                "SELECT ROUND(COUNT(NULLIF(region, 'Mbarara')) * 1.0 / COUNT(*), 4) AS ratio FROM users",
            ):
                r_single = client.post("/v1/query", headers=headers, json={"sql": single_sql})
                self.assertEqual(r_single.status_code, 403, single_sql)
                self.assertIn(
                    "differencing_attack_denied",
                    {v["code"] for v in r_single.json()["policy"]["violations"]},
                    single_sql,
                )

    def test_layer4_suppresses_pairwise_differencing_across_two_count_columns(self) -> None:
        scope = _make_scope(self.connector, minimum_group_size=5)
        projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, scope
        )
        sql_decision = self.gateway.validate(
            "SELECT country, COUNT(*) AS total_cnt, COUNT(department) AS dept_cnt "
            "FROM users GROUP BY country",
            SQLValidationContext(dialect="postgres", scope=scope, projected_schema=projected),
        )
        self.assertTrue(sql_decision.allowed)
        res_decision = ResultPolicyGateway().validate(
            pd.DataFrame(
                {
                    "country": ["Uganda", "Kenya"],
                    "total_cnt": [105, 50],
                    "dept_cnt": [104, 42],
                }
            ),
            ResultValidationContext(
                scope=scope,
                projected_schema=projected,
                sql_policy_decision=sql_decision,
            ),
        )
        self.assertTrue(res_decision.allowed)
        self.assertEqual(res_decision.returned_row_count, 1)
        self.assertEqual(res_decision.safe_result.rows[0]["country"], "Kenya")


class EncodingAndTypeCastEvasionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()
        self.connector = _make_connector()
        self.scope = _make_scope(
            self.connector,
            pii_masking_columns=("email", "customer_email", "customer_phone"),
        )
        self.projected = SchemaProjectionService().project_schema(
            self.connector, EDGE_CASE_SCHEMA, self.scope
        )
        self.ctx = SQLValidationContext(
            dialect="postgres", scope=self.scope, projected_schema=self.projected
        )

    def test_encoding_reversing_substring_and_binary_cast_on_masked_pii_are_denied(self) -> None:
        for sql in (
            "SELECT encode(email::bytea, 'base64') AS total_count FROM users",
            "SELECT reverse(customer_phone) AS total_count FROM orders",
            "SELECT substring(customer_email, 1, 10) AS customer_email FROM orders",
            "SELECT CAST(email AS BYTEA) AS email FROM users",
            "SELECT encode(ssn::bytea, 'base64') AS s FROM users",
            "SELECT email || '' AS email FROM users",
            "SELECT SUM(CASE WHEN customer_phone = '415-555-0199' THEN 1 ELSE 0 END) AS people FROM orders",
        ):
            decision = self.gateway.validate(sql, self.ctx)
            self.assertFalse(decision.allowed, sql)
            codes = {v.code for v in decision.violations}
            self.assertTrue(
                codes & {"sensitive_transform_denied", "column_denied", "sensitive_alias_denied"},
                f"{sql} -> {codes}",
            )

    def test_bare_pii_masked_columns_still_allowed_for_layer4_masking(self) -> None:
        decision = self.gateway.validate(
            "SELECT id, customer_email, customer_phone FROM orders",
            self.ctx,
        )
        self.assertTrue(decision.allowed, decision.violations)

    def test_result_policy_catches_aliased_custom_pii_masking_column(self) -> None:
        sql_decision = self.gateway.validate(
            "SELECT customer_phone AS total_count FROM orders",
            self.ctx,
        )
        self.assertFalse(sql_decision.allowed)
        res_decision = ResultPolicyGateway().validate(
            pd.DataFrame({"total_count": ["415-555-0199"]}),
            ResultValidationContext(
                scope=self.scope,
                projected_schema=self.projected,
                sql_policy_decision=sql_decision,
            ),
        )
        self.assertFalse(res_decision.allowed)
        self.assertIn("alias_sensitive_column", {v.code for v in res_decision.violations})


if __name__ == "__main__":
    unittest.main()
