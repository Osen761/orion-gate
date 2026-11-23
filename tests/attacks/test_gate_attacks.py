"""Adversarial attack suite for Orion Gate standalone tenant isolation, REST gateway, and MCP."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import pandas as pd
from fastapi.testclient import TestClient

from orion_gate.auth import AuthContext
from orion_gate.authz.connectors import EffectiveAccessScope, TenantFilter
from orion_gate.connectors.postgres import PostgresConnector
from orion_gate.gate_app import app
from orion_gate.models import Connector, Workspace
from orion_gate.security.orion_yaml import (
    clear_active_orion_yaml,
    issue_standalone_agent_token,
    parse_orion_yaml,
    set_active_orion_yaml,
)
from orion_gate.security.schema_projection import SchemaProjectionService
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


RAW_SAAS_SCHEMA = """
Table: orders (1,200 rows)
  - id: integer
  - business_id: text
  - customer_id: integer
  - total: numeric
  - status: text
  - created_at: timestamp
Table: customers (400 rows)
  - id: integer
  - business_id: text
  - email: text
  - phone: text
  - password_hash: text
"""

SAMPLE_GATE_YAML = """
version: "1.0"
workspace:
  id: "00000000-0000-0000-0000-000000000777"
  name: "Gate Security Suite"
datasource:
  id: "00000000-0000-0000-0000-000000000888"
  name: "prod_postgres"
  dialect: postgres
  url: "postgresql://readonly:secret@db.internal:5432/acme_prod?sslmode=require"
policy:
  allowed_tables:
    - orders
    - customers
  denied_columns:
    customers:
      - password_hash
  pii_masking:
    customers.email: redact_email
    customers.phone: mask_phone
  tenant_isolation:
    required: true
    claim: org_id
    tables:
      orders: org_id
      customers: org_id
  limits:
    max_rows: 100
    allow_raw_pii: false
    allow_raw_rows: true
auth:
  token_env: ORION_LOCAL_TOKEN
  jwt_secret_env: ORION_JWT_SECRET
"""


TENANT_REWRITE_BYPASS_ATTACKS: dict[str, tuple[str, str]] = {
    "explicit_wrong_tenant_value": (
        "SELECT id, total FROM orders WHERE business_id = 'tenant_B'",
        "tenant_predicate_wrong_value",
    ),
    "or_tautology_on_tenant_column": (
        "SELECT id, total FROM orders WHERE business_id = 'tenant_A' OR 1 = 1",
        "tenant_or_denied",
    ),
    "or_multi_tenant_probe": (
        "SELECT id, total FROM orders WHERE (business_id = 'tenant_A' OR business_id = 'tenant_B')",
        "tenant_or_denied",
    ),
    "not_equal_tenant_operator": (
        "SELECT id, total FROM orders WHERE business_id != 'tenant_A'",
        "tenant_predicate_invalid",
    ),
    "in_list_tenant_bypass": (
        "SELECT id, total FROM orders WHERE business_id IN ('tenant_A', 'tenant_B')",
        "tenant_predicate_invalid",
    ),
    "negated_tenant_equality": (
        "SELECT id, total FROM orders WHERE NOT (business_id = 'tenant_A')",
        "tenant_predicate_invalid",
    ),
    "like_wildcard_tenant_probe": (
        "SELECT id, total FROM orders WHERE business_id LIKE 'tenant_%'",
        "tenant_predicate_invalid",
    ),
    "is_null_tenant_probe": (
        "SELECT id, total FROM orders WHERE business_id IS NULL",
        "tenant_predicate_invalid",
    ),
    "coalesce_wrapped_tenant_column": (
        "SELECT id, total FROM orders WHERE COALESCE(business_id, 'tenant_A') = 'tenant_A'",
        "tenant_predicate_invalid",
    ),
    "column_to_column_tenant_comparison": (
        "SELECT id, total FROM orders WHERE business_id = status",
        "tenant_predicate_wrong_value",
    ),
    "union_second_branch_cross_tenant": (
        "SELECT id, total FROM orders WHERE business_id = 'tenant_A' "
        "UNION ALL SELECT id, total FROM orders WHERE business_id = 'tenant_B'",
        "tenant_predicate_wrong_value",
    ),
    "left_join_on_clause_wrong_tenant": (
        "SELECT c.id, o.total FROM customers c "
        "LEFT JOIN orders o ON o.customer_id = c.id AND o.business_id = 'tenant_B'",
        "tenant_predicate_wrong_value",
    ),
}


def _make_auto_inject_context(*, strict: bool = False) -> SQLValidationContext:
    connector = Connector(type="postgres", name="prod")
    scope = EffectiveAccessScope(
        workspace_id="00000000-0000-0000-0000-000000000100",
        surface="gateway",
        principal_type="embedded_user",
        user_id="agent-1",
        member_id=None,
        role="member",
        connector_id=str(connector.id),
        connector_access_level="query",
        external_tenant_id="tenant_A",
        allowed_tables=("orders", "customers"),
        denied_columns=("password_hash", "customers.password_hash"),
        tenant_filters=(
            TenantFilter(table="orders", column="business_id", value="tenant_A", required=True),
            TenantFilter(table="customers", column="business_id", value="tenant_A", required=True),
        ),
        allow_raw_rows=True,
        allow_sql_visibility=True,
        max_result_rows=100,
    )
    projected = SchemaProjectionService().project_schema(connector, RAW_SAAS_SCHEMA, scope)
    return SQLValidationContext(
        dialect="postgres",
        scope=scope,
        projected_schema=projected,
        connector_type="postgres",
        auto_inject_tenant_filters=not strict,
    )


class OrionGateASTBypassAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()
        self.auto_ctx = _make_auto_inject_context()

    def test_all_tenant_rewrite_bypass_attacks_blocked(self) -> None:
        for attack_name, (sql, expected_code) in TENANT_REWRITE_BYPASS_ATTACKS.items():
            with self.subTest(attack=attack_name):
                decision = self.gateway.validate(sql, self.auto_ctx)
                self.assertFalse(decision.allowed)
                codes = {v.code for v in decision.violations}
                self.assertIn(expected_code, codes)

    def test_subquery_predicate_cannot_satisfy_outer_table_in_strict_mode(self) -> None:
        strict_ctx = _make_auto_inject_context(strict=True)
        sql = (
            "SELECT id, total FROM orders "
            "WHERE customer_id IN (SELECT id FROM customers WHERE business_id = 'tenant_A')"
        )
        decision = self.gateway.validate(sql, strict_ctx)
        self.assertFalse(decision.allowed)
        self.assertIn("tenant_predicate_missing", {v.code for v in decision.violations})

    def test_auto_inject_wraps_existing_or_clause_and_isolates_both_branches(self) -> None:
        sql = "SELECT id, total FROM orders WHERE status = 'paid' OR status = 'refunded'"
        decision = self.gateway.validate(sql, self.auto_ctx)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.tenant_predicates_injected)
        self.assertIn("orders.business_id = 'tenant_A'", decision.safe_sql or "")
        self.assertIn("AND", decision.safe_sql or "")


class OrionGateEndpointAttackTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_active_orion_yaml()

    def test_cross_tenant_body_and_mcp_probe_blocked(self) -> None:
        cfg = parse_orion_yaml(SAMPLE_GATE_YAML)
        set_active_orion_yaml(cfg)
        secret = "gate_attack_test_secret_32bytes_min"
        raw_schema = "\n".join(
            [
                "Table: orders (100 rows)",
                "  - id: integer",
                "  - org_id: text",
                "  - amount: numeric",
                "Table: customers (100 rows)",
                "  - id: integer",
                "  - org_id: text",
                "  - email: text",
                "  - phone: text",
                "  - password_hash: text",
            ]
        )

        with (
            patch.dict(os.environ, {"ORION_JWT_SECRET": secret}),
            patch.object(PostgresConnector, "get_schema", return_value=raw_schema),
            patch.object(
                PostgresConnector,
                "_execute_sql",
                return_value=(pd.DataFrame([{"id": 1}]), "id\n1"),
            ),
        ):
            client = TestClient(app)
            jwt_token = issue_standalone_agent_token(
                cfg,
                subject="attacker-agent",
                tenant_id="org_acme",
                secret=secret,
            )

            # Attempt reading password_hash via REST
            resp = client.post(
                "/v1/query",
                headers={"Authorization": f"Bearer {jwt_token}"},
                json={"sql": "SELECT password_hash FROM customers"},
            )
            self.assertEqual(resp.status_code, 403)
            self.assertFalse(resp.json()["allowed"])

            # Attempt OR 1=1 via MCP
            mcp_resp = client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {jwt_token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "query_governed_sql",
                        "arguments": {
                            "sql": "SELECT id, amount FROM orders WHERE org_id = 'org_acme' OR 1=1"
                        },
                    },
                },
            )
            self.assertEqual(mcp_resp.status_code, 200)
            self.assertTrue(mcp_resp.json()["result"]["isError"])

    def test_schema_endpoint_hides_denied_tables_columns_and_jsonb(self) -> None:
        cfg = parse_orion_yaml(SAMPLE_GATE_YAML)
        set_active_orion_yaml(cfg)
        secret = "gate_attack_test_secret_32bytes_min"
        raw_schema = "\n".join(
            [
                "Table: orders (100 rows)",
                "  - id: integer",
                "  - org_id: text",
                "  - amount: numeric",
                "  - metadata: jsonb",
                "Table: customers (100 rows)",
                "  - id: integer",
                "  - org_id: text",
                "  - email: text",
                "  - password_hash: text",
                "Table: audit_logs (900 rows)",
                "  - id: integer",
                "  - raw_token: text",
            ]
        )

        with (
            patch.dict(os.environ, {"ORION_JWT_SECRET": secret}),
            patch.object(PostgresConnector, "get_schema", return_value=raw_schema),
        ):
            client = TestClient(app)
            jwt_token = issue_standalone_agent_token(
                cfg,
                subject="schema-prober",
                tenant_id="org_acme",
                secret=secret,
            )
            resp = client.get("/v1/schema", headers={"Authorization": f"Bearer {jwt_token}"})
            self.assertEqual(resp.status_code, 200)
            schema_text = resp.json()["schema"]
            self.assertIn("orders", schema_text)
            self.assertIn("customers", schema_text)
            self.assertNotIn("audit_logs", schema_text)
            self.assertNotIn("password_hash", schema_text)
            self.assertNotIn("metadata", schema_text)

    def test_expired_wrong_secret_and_tenant_spoof_tokens_rejected(self) -> None:
        cfg = parse_orion_yaml(SAMPLE_GATE_YAML)
        set_active_orion_yaml(cfg)
        secret = "gate_attack_test_secret_32bytes_min"

        with (
            patch.dict(os.environ, {"ORION_JWT_SECRET": secret}),
            patch.object(PostgresConnector, "get_schema", return_value=RAW_SAAS_SCHEMA),
        ):
            client = TestClient(app)

            expired_jwt = issue_standalone_agent_token(
                cfg,
                subject="expired-agent",
                tenant_id="org_acme",
                ttl_seconds=-10,
                secret=secret,
            )
            exp_resp = client.get("/v1/schema", headers={"Authorization": f"Bearer {expired_jwt}"})
            self.assertEqual(exp_resp.status_code, 401)

            wrong_secret_jwt = issue_standalone_agent_token(
                cfg,
                subject="forged-agent",
                tenant_id="org_acme",
                secret="attacker_signing_secret_differs_32b",
            )
            forged_resp = client.get("/v1/schema", headers={"Authorization": f"Bearer {wrong_secret_jwt}"})
            self.assertEqual(forged_resp.status_code, 401)

            valid_jwt = issue_standalone_agent_token(
                cfg,
                subject="scoped-agent",
                tenant_id="org_acme",
                secret=secret,
            )
            spoof_resp = client.post(
                "/v1/query",
                headers={
                    "Authorization": f"Bearer {valid_jwt}",
                    "X-Orion-Tenant-Values": '{"org_id": "org_globex"}',
                },
                json={"sql": "SELECT id, amount FROM orders"},
            )
            self.assertEqual(spoof_resp.status_code, 403)

    def test_result_layer_pii_masking_and_secret_scrubbing_end_to_end(self) -> None:
        cfg = parse_orion_yaml(SAMPLE_GATE_YAML)
        set_active_orion_yaml(cfg)
        secret = "gate_attack_test_secret_32bytes_min"
        raw_schema = "\n".join(
            [
                "Table: orders (100 rows)",
                "  - id: integer",
                "  - org_id: text",
                "  - amount: numeric",
                "Table: customers (100 rows)",
                "  - id: integer",
                "  - org_id: text",
                "  - email: text",
                "  - phone: text",
                "  - password_hash: text",
            ]
        )
        leaked_df = pd.DataFrame(
            [
                {
                    "email": "alice@acme.io",
                    "phone": "+1-415-555-0199",
                },
                {
                    "email": "bob@acme.io",
                    "phone": "leak sk-live_AbCdEf1234567890",
                },
            ]
        )

        with (
            patch.dict(os.environ, {"ORION_JWT_SECRET": secret}),
            patch.object(PostgresConnector, "get_schema", return_value=raw_schema),
            patch.object(PostgresConnector, "_execute_sql", return_value=(leaked_df, "")),
        ):
            client = TestClient(app)
            valid_jwt = issue_standalone_agent_token(
                cfg,
                subject="pii-agent",
                tenant_id="org_acme",
                secret=secret,
            )
            resp = client.post(
                "/v1/query",
                headers={"Authorization": f"Bearer {valid_jwt}"},
                json={"sql": "SELECT email, phone FROM customers"},
            )
            self.assertEqual(resp.status_code, 200)
            payload = resp.json()
            serialized = repr(payload["rows"])
            self.assertNotIn("alice@acme.io", serialized)
            self.assertNotIn("bob@acme.io", serialized)
            self.assertNotIn("415-555-0199", serialized)
            self.assertNotIn("sk-live_", serialized)


class OrionGateHardeningRegressionTests(unittest.TestCase):
    """Adversarial regressions for AST, auth, differencing, result scrubbing, and demo DoS loopholes."""

    def setUp(self) -> None:
        self.gateway = SQLPolicyGateway()
        self.auto_ctx = _make_auto_inject_context()

    def tearDown(self) -> None:
        clear_active_orion_yaml()

    def test_dangerous_dynamic_sql_xml_file_and_config_functions_blocked(self) -> None:
        for sql in (
            "SELECT query_to_xml('SELECT * FROM admin_audit_secrets', true, true, '') FROM orders",
            "SELECT table_to_xml('orders', true, true, '') FROM orders",
            "SELECT lo_export(1234, '/tmp/leak') FROM orders",
            "SELECT set_config('statement_timeout', '0', false) FROM orders",
            "SELECT dblink_exec('dbname=app', 'DROP TABLE orders') FROM orders",
            "SELECT pg_ls_waldir() FROM orders",
        ):
            with self.subTest(sql=sql):
                decision = self.gateway.validate(sql, self.auto_ctx)
                self.assertFalse(decision.allowed)
                self.assertIn("unsafe_function", {v.code for v in decision.violations})

    def test_data_modifying_cte_select_into_and_locking_clauses_blocked(self) -> None:
        for sql, expected_code in (
            (
                "WITH d AS (DELETE FROM orders WHERE business_id = 'tenant_A' RETURNING id) SELECT id FROM d",
                "non_read_only_statement",
            ),
            (
                "SELECT id, total INTO orders FROM orders",
                "non_read_only_statement",
            ),
            (
                "SELECT id, total FROM orders FOR UPDATE",
                "locking_clause_denied",
            ),
            (
                "SELECT id, total FROM orders FOR SHARE",
                "locking_clause_denied",
            ),
        ):
            with self.subTest(sql=sql):
                decision = self.gateway.validate(sql, self.auto_ctx)
                self.assertFalse(decision.allowed)
                self.assertIn(expected_code, {v.code for v in decision.violations})

    def test_cartesian_tautology_and_natural_joins_blocked(self) -> None:
        for sql in (
            "SELECT a.id, b.id FROM orders a JOIN orders b ON a.id = a.id",
            "SELECT a.id, b.id FROM orders a JOIN orders b ON 1 < 2",
            "SELECT a.id, b.id FROM orders a JOIN orders b ON a.id = b.id OR 1 = 1",
            "WITH x AS (SELECT 1 AS dummy) SELECT a.id FROM orders a NATURAL JOIN x",
        ):
            with self.subTest(sql=sql):
                decision = self.gateway.validate(sql, self.auto_ctx)
                self.assertFalse(decision.allowed)
                self.assertIn("cross_join_denied", {v.code for v in decision.violations})

    def test_pii_string_array_and_overlay_obfuscation_blocked(self) -> None:
        for sql in (
            "SELECT email, string_to_array(email, '@') FROM customers",
            "SELECT email, overlay(email placing 'x' from 1 for 1) FROM customers",
            "SELECT email, btrim(email, 'a') FROM customers",
            "SELECT email, lpad(email, 50, 'x') FROM customers",
            "SELECT email, repeat(email, 2) FROM customers",
            "SELECT email, ARRAY[email] FROM customers",
        ):
            with self.subTest(sql=sql):
                decision = self.gateway.validate(sql, self.auto_ctx)
                self.assertFalse(decision.allowed)
                self.assertIn("sensitive_transform_denied", {v.code for v in decision.violations})

    def test_per_table_allowed_columns_does_not_leak_across_tables(self) -> None:
        cfg = parse_orion_yaml(
            {
                "version": "1.0",
                "datasource": {"name": "db", "dialect": "postgres", "url": "postgresql://u:p@localhost/db"},
                "policy": {
                    "allowed_tables": ["orders", "customers"],
                    "allowed_columns": {
                        "orders": ["id", "org_id", "amount"],
                        "customers": ["id", "org_id", "phone"],
                    },
                    "tenant_isolation": {
                        "required": True,
                        "claim": "org_id",
                        "tables": {"orders": "org_id", "customers": "org_id"},
                    },
                },
            }
        )
        ds = cfg.primary_datasource
        workspace = Workspace(id=cfg.workspace_id, name="t", plan="standalone", owner_email="a@b.c")
        auth = AuthContext(workspace_id=str(cfg.workspace_id), workspace=workspace, auth_type="api_key", user_id="u1")
        scope = cfg.build_effective_scope(
            datasource=ds, auth=auth, requested_tenant_values={"org_id": "org_acme"}
        )
        raw_schema = (
            "Table: orders (100 rows)\n"
            "  - id: integer\n"
            "  - org_id: text\n"
            "  - amount: numeric\n"
            "  - phone: text\n"
            "Table: customers (100 rows)\n"
            "  - id: integer\n"
            "  - org_id: text\n"
            "  - phone: text\n"
        )
        connector = ds.to_connector_model(cfg.workspace_id, scope.allowed_tables)
        projected = SchemaProjectionService().project_schema(connector, raw_schema, scope)

        # orders.phone is NOT allowed even though customers.phone is allowed
        self.assertIn("orders.phone", projected.denied_columns)
        self.assertIn("customers.phone", projected.included_columns)

        ctx = SQLValidationContext(
            dialect="postgres", scope=scope, projected_schema=projected, auto_inject_tenant_filters=True
        )
        ok_orders = self.gateway.validate("SELECT id, amount FROM orders", ctx)
        self.assertTrue(ok_orders.allowed, ok_orders.violations)

        bad_cross_table = self.gateway.validate("SELECT id, phone FROM orders", ctx)
        self.assertFalse(bad_cross_table.allowed)

    def test_jwt_rejects_missing_exp_wrong_aud_and_wrong_workspace(self) -> None:
        from datetime import datetime, timedelta, timezone
        from jose import jwt

        cfg = parse_orion_yaml(SAMPLE_GATE_YAML)
        set_active_orion_yaml(cfg)
        secret = "gate_attack_test_secret_32bytes_min"
        now = datetime.now(timezone.utc)
        exp = int((now + timedelta(minutes=15)).timestamp())

        no_exp = jwt.encode(
            {"sub": "a", "aud": "orion-gate", "workspace_id": str(cfg.workspace_id), "org_id": "org_acme"},
            secret,
            algorithm="HS256",
        )
        wrong_aud = jwt.encode(
            {"sub": "a", "aud": "other-service", "workspace_id": str(cfg.workspace_id), "org_id": "org_acme", "exp": exp},
            secret,
            algorithm="HS256",
        )
        wrong_ws = jwt.encode(
            {"sub": "a", "aud": "orion-gate", "workspace_id": "00000000-0000-0000-0000-000000009999", "org_id": "org_acme", "exp": exp},
            secret,
            algorithm="HS256",
        )

        with (
            patch.dict(os.environ, {"ORION_JWT_SECRET": secret}),
            patch.object(PostgresConnector, "get_schema", return_value=RAW_SAAS_SCHEMA),
        ):
            client = TestClient(app)
            for label, tok in (("no_exp", no_exp), ("wrong_aud", wrong_aud), ("wrong_ws", wrong_ws)):
                with self.subTest(token=label):
                    resp = client.get("/v1/schema", headers={"Authorization": f"Bearer {tok}"})
                    self.assertEqual(resp.status_code, 401)

    def test_result_policy_scrubs_stripe_keys_db_uris_and_string_dtype(self) -> None:
        from orion_gate.security.result_policy import ResultPolicyGateway, ResultValidationContext

        scope = self.auto_ctx.scope
        projected = self.auto_ctx.projected_schema
        df = pd.DataFrame(
            {
                "status": pd.Series(
                    [
                        "sk_live_AbCdEf1234567890123456",
                        "whsec_live_8f92a7c4b1e0d3948576",
                        "postgresql://root:Sup3rS3cr3t@10.0.4.12:5432/prod",
                    ],
                    dtype="string",
                )
            }
        )
        decision = ResultPolicyGateway().validate(
            df, ResultValidationContext(scope=scope, projected_schema=projected)
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.decision, "redacted")
        rows = [r["status"] for r in decision.safe_result.rows]
        self.assertEqual(rows, ["[REDACTED]", "[REDACTED]", "[REDACTED]"])

    def test_firewall_marks_small_group_suppression_and_blocks_followup_differencing(self) -> None:
        from orion_gate.security.differencing import reset_differencing_store

        reset_differencing_store()
        cfg = parse_orion_yaml(
            {
                "version": "1.0",
                "datasource": {"name": "db", "dialect": "postgres", "url": "postgresql://u:p@localhost/db"},
                "policy": {
                    "allowed_tables": ["orders"],
                    "limits": {
                        "minimum_group_size": 5,
                        "differencing_budget": 5,
                        "differencing_window_seconds": 300,
                    },
                },
                "auth": {"static_tokens": ["diff-test-token"]},
            }
        )
        set_active_orion_yaml(cfg)

        class _SmallGroupConn:
            def __init__(self) -> None:
                self.sql_policy_context = None
                self.last_result_policy_decision = None

            def get_schema(self) -> str:
                return RAW_SAAS_SCHEMA

            def execute_sql(self, sql: str):
                from orion_gate.security.result_policy import ResultPolicyGateway, ResultValidationContext

                assert self.sql_policy_context is not None
                sql_dec = SQLPolicyGateway().validate(sql, self.sql_policy_context)
                df = pd.DataFrame({"status": ["paid", "rare"], "people": [20, 2]})
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
        headers = {"Authorization": "Bearer diff-test-token"}
        try:
            with patch("orion_gate.security.firewall.get_connector", return_value=_SmallGroupConn()):
                r1 = client.post(
                    "/v1/query",
                    headers=headers,
                    json={"sql": "SELECT status, COUNT(*) AS people FROM orders WHERE total > 10 GROUP BY status"},
                )
                self.assertEqual(r1.status_code, 200)
                # Follow-up positive variation on same template after small-group suppression must be blocked
                r2 = client.post(
                    "/v1/query",
                    headers=headers,
                    json={"sql": "SELECT status, COUNT(*) AS people FROM orders WHERE total > 20 GROUP BY status"},
                )
                self.assertEqual(r2.status_code, 403)
                self.assertIn(
                    "differencing_attack_denied",
                    {v["code"] for v in r2.json()["policy"]["violations"]},
                )
        finally:
            reset_differencing_store()

    def test_demo_simulator_aborts_recursive_cte_dos(self) -> None:
        client = TestClient(app)
        resp = client.post(
            "/v1/demo/simulate",
            json={
                "sql": "WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM r) SELECT COUNT(*) FROM r",
                "active_tenant": "org_acme",
                "dialect": "postgres",
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["orion_gate"]["status"], "blocked")
        self.assertEqual(body["raw_agent"]["status"], "syntax_error")


if __name__ == "__main__":
    unittest.main()
