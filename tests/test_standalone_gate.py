"""Standalone verification tests for Orion Gate CLI, REST gateway, MCP server, simulator, and packaging."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pandas as pd
from fastapi.testclient import TestClient

from orion_gate.api.demo_simulator import DEMO_PRESETS
from orion_gate.cli import main as cli_main
from orion_gate.connectors.postgres import PostgresConnector
from orion_gate.gate_app import app
from orion_gate.security.cloud_sync import set_telemetry_hook
from orion_gate.security.orion_yaml import (
    clear_active_orion_yaml,
    get_active_orion_yaml,
    issue_standalone_agent_token,
    load_orion_yaml,
    parse_orion_yaml,
    set_active_orion_yaml,
)


GATE_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_YAML = """
version: "1.0"
workspace:
  id: "00000000-0000-0000-0000-000000000777"
  name: "Acme Standalone Gateway"
datasource:
  id: "00000000-0000-0000-0000-000000000888"
  name: "Acme Postgres"
  dialect: postgres
  url: "postgresql://readonly:secret@db.internal:5432/acme_prod?sslmode=require"
policy:
  allowed_tables:
    - orders
    - customers
    - invoices
  denied_tables:
    - audit_logs
  denied_columns:
    customers:
      - password_hash
      - stripe_secret_key
      - ssn
  pii_masking:
    customers.email: redact_email
    customers.phone: mask_phone
  tenant_isolation:
    required: true
    claim: tenant_id
    tables:
      orders: org_id
      customers: org_id
      invoices: org_id
  limits:
    max_rows: 50
    timeout_seconds: 10
    allow_raw_pii: false
    allow_raw_rows: true
auth:
  token_env: ORION_LOCAL_TOKEN
  jwt_secret_env: ORION_JWT_SECRET
"""

RAW_SCHEMA = "\n".join(
    [
        "Table: orders (1,200 rows)",
        "  - id: uuid",
        "  - org_id: text",
        "  - amount: numeric",
        "  - status: text",
        "Table: customers (400 rows)",
        "  - id: uuid",
        "  - org_id: text",
        "  - email: text",
        "  - phone: text",
        "  - password_hash: text",
        "  - stripe_secret_key: text",
        "  - ssn: text",
        "Table: audit_logs (9,000 rows)",
        "  - id: uuid",
        "  - payload: text",
    ]
)


class StandaloneOrionGateTests(unittest.TestCase):
    """Verify `orion.yaml` parsing, standalone gateway/MCP execution, hot reload, and CLI commands."""

    def tearDown(self) -> None:
        clear_active_orion_yaml()
        set_telemetry_hook(None)

    def test_no_commercial_or_cloud_modules_loaded(self) -> None:
        forbidden_prefixes = ("app.", "alembic", "langgraph", "supabase", "firebase_admin")
        loaded = [
            name
            for name in sys.modules
            if name == "app" or name.startswith(forbidden_prefixes)
        ]
        self.assertEqual(loaded, [])

    def test_example_orion_yaml_loads_valid_config(self) -> None:
        cfg = load_orion_yaml(GATE_ROOT / "orion.example.yaml")
        self.assertEqual(cfg.version, "1.0")
        self.assertEqual(cfg.primary_datasource.dialect, "postgres")
        self.assertIn("orders", cfg.policy.allowed_tables or ())
        self.assertTrue(cfg.policy.tenant_isolation.required)
        self.assertEqual(cfg.policy.tenant_isolation.tables.get("orders"), "org_id")
        self.assertEqual(cfg.policy.pii_masking.get("customers.email"), "redact_email")

    def test_invalid_dialect_and_masking_strategy_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_orion_yaml({"version": "1.0", "datasource": {"dialect": "sqlite"}})

        with self.assertRaises(ValueError):
            parse_orion_yaml(
                {
                    "version": "1.0",
                    "datasource": {"dialect": "postgres"},
                    "policy": {"pii_masking": {"customers.email": "encrypt_aes"}},
                }
            )

    def test_orion_yaml_env_path_hot_reloads_when_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "orion.yaml"
            yaml_path.write_text(SAMPLE_YAML, encoding="utf-8")
            with patch.dict(os.environ, {"ORION_YAML_PATH": str(yaml_path)}):
                first = get_active_orion_yaml()
                self.assertIsNotNone(first)
                self.assertEqual(first.policy.limits.max_rows, 50)

                updated_yaml = SAMPLE_YAML.replace("max_rows: 50", "max_rows: 25")
                yaml_path.write_text(updated_yaml, encoding="utf-8")
                future_mtime = time.time() + 5
                os.utime(yaml_path, (future_mtime, future_mtime))

                second = get_active_orion_yaml()
                self.assertIsNotNone(second)
                self.assertEqual(second.policy.limits.max_rows, 25)

    def test_standalone_gateway_executes_rest_and_mcp_end_to_end(self) -> None:
        cfg = parse_orion_yaml(SAMPLE_YAML)
        set_active_orion_yaml(cfg)
        captured_events: list[Any] = []
        set_telemetry_hook(captured_events.append)

        executed_sql: list[str] = []

        def fake_execute_sql(connector_self: PostgresConnector, sql: str) -> tuple[pd.DataFrame, str]:
            safe_sql, err = connector_self._apply_sql_policy(sql)
            if err:
                return pd.DataFrame(), err
            executed_sql.append(safe_sql or sql)
            if "customers" in (safe_sql or "").lower():
                df = pd.DataFrame(
                    [
                        {
                            "id": "cust-1",
                            "email": "alice@acme.io",
                            "phone": "+1 (415) 555-0199",
                        }
                    ]
                )
            else:
                df = pd.DataFrame([{"id": "ord-1", "amount": 250.0, "status": "paid"}])
            return connector_self._apply_result_policy(df)

        env = {
            "ORION_LOCAL_TOKEN": "local_dev_token_123",
            "ORION_JWT_SECRET": "standalone_jwt_secret_key_for_tests_32b",
        }
        with (
            patch.dict(os.environ, env),
            patch.object(PostgresConnector, "get_schema", return_value=RAW_SCHEMA),
            patch.object(PostgresConnector, "_execute_sql", autospec=True, side_effect=fake_execute_sql),
        ):
            client = TestClient(app)
            agent_jwt = issue_standalone_agent_token(
                cfg,
                subject="support-agent",
                tenant_id="org_acme",
                secret=env["ORION_JWT_SECRET"],
            )

            # 1. GET /v1/schema hides denied tables and columns
            schema_resp = client.get(
                "/v1/schema",
                headers={"Authorization": f"Bearer {agent_jwt}"},
            )
            self.assertEqual(schema_resp.status_code, 200)
            schema_body = schema_resp.json()
            table_names = [t["name"] for t in schema_body["tables"]]
            self.assertIn("orders", table_names)
            self.assertIn("customers", table_names)
            self.assertNotIn("audit_logs", table_names)
            customer_cols = [
                c["name"]
                for t in schema_body["tables"]
                if t["name"] == "customers"
                for c in t["columns"]
            ]
            self.assertIn("email", customer_cols)
            self.assertNotIn("password_hash", customer_cols)
            self.assertNotIn("stripe_secret_key", customer_cols)

            # 2. POST /v1/query auto-injects org_id and masks email + phone
            query_resp = client.post(
                "/v1/query",
                headers={"Authorization": f"Bearer {agent_jwt}"},
                json={"sql": "SELECT id, email, phone FROM customers"},
            )
            self.assertEqual(query_resp.status_code, 200)
            q_body = query_resp.json()
            self.assertTrue(q_body["allowed"])
            self.assertEqual(q_body["status"], "redacted")
            self.assertTrue(q_body["policy"]["tenant_predicates_injected"])
            self.assertIn("customers.org_id = 'org_acme'", executed_sql[-1])
            self.assertEqual(q_body["rows"][0]["email"], "a***@acme.io")
            self.assertEqual(q_body["rows"][0]["phone"], "***-***-0199")
            self.assertIn("email", q_body["policy"]["redacted_columns"])
            self.assertIn("phone", q_body["policy"]["redacted_columns"])

            # 3. Scoped JWT attempting to override tenant_values is rejected with 403
            spoof_resp = client.post(
                "/v1/query",
                headers={"Authorization": f"Bearer {agent_jwt}"},
                json={
                    "sql": "SELECT id, amount FROM orders",
                    "tenant_values": {"tenant_id": "org_other"},
                },
            )
            self.assertEqual(spoof_resp.status_code, 403)

            # 4. Local operator token with X-Orion-Tenant-Values succeeds; without it fails 403
            missing_tenant_resp = client.post(
                "/v1/query",
                headers={"Authorization": "Bearer local_dev_token_123"},
                json={"sql": "SELECT id, amount FROM orders"},
            )
            self.assertEqual(missing_tenant_resp.status_code, 403)

            operator_dry_run = client.post(
                "/v1/query",
                headers={
                    "Authorization": "Bearer local_dev_token_123",
                    "X-Orion-Tenant-Values": json.dumps({"tenant_id": "org_acme"}),
                },
                json={"sql": "SELECT id, amount FROM orders", "dry_run": True},
            )
            self.assertEqual(operator_dry_run.status_code, 200)
            self.assertIn("orders.org_id = 'org_acme'", operator_dry_run.json()["policy"]["rewritten_sql"])

            # 5. MCP tool call works in standalone mode
            mcp_resp = client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {agent_jwt}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {
                        "name": "query_governed_sql",
                        "arguments": {"sql": "SELECT id, amount FROM orders"},
                    },
                },
            )
            self.assertEqual(mcp_resp.status_code, 200)
            mcp_result = mcp_resp.json()["result"]
            self.assertFalse(mcp_result["isError"])
            self.assertTrue(mcp_result["structuredContent"]["policy"]["tenant_predicates_injected"])

            # 6. Telemetry hook captured sanitized events without raw rows
            self.assertGreaterEqual(len(captured_events), 2)
            self.assertTrue(captured_events[0].tenant_predicates_injected)
            self.assertIn("email", captured_events[0].redacted_columns)

    def test_cli_validate_check_sql_and_mint_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "orion.yaml"
            yaml_path.write_text(SAMPLE_YAML, encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["validate", "--config", str(yaml_path)])
            self.assertEqual(rc, 0)
            val_out = json.loads(buf.getvalue())
            self.assertTrue(val_out["valid"])

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(
                    [
                        "check-sql",
                        "--config",
                        str(yaml_path),
                        "--sql",
                        "SELECT id, amount FROM orders WHERE status = 'paid' OR status = 'pending'",
                        "--tenant",
                        "org_acme",
                    ]
                )
            self.assertEqual(rc, 0)
            check_out = json.loads(buf.getvalue())
            self.assertTrue(check_out["allowed"])
            self.assertTrue(check_out["tenant_predicates_injected"])
            self.assertIn("orders.org_id = 'org_acme'", check_out["rewritten_sql"])

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(
                    [
                        "check-sql",
                        "--config",
                        str(yaml_path),
                        "--sql",
                        "SELECT password_hash FROM customers",
                        "--tenant",
                        "org_acme",
                    ]
                )
            self.assertEqual(rc, 2)
            denied_out = json.loads(buf.getvalue())
            self.assertFalse(denied_out["allowed"])

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(
                    [
                        "mint-token",
                        "--config",
                        str(yaml_path),
                        "--sub",
                        "agent-cli",
                        "--tenant",
                        "org_acme",
                        "--secret",
                        "cli_test_secret_key_32_bytes_min",
                    ]
                )
            self.assertEqual(rc, 0)
            tok_out = json.loads(buf.getvalue())
            self.assertTrue(tok_out["token"].startswith("eyJ"))


class StandaloneLiveAttackSimulatorAndPackagingTests(unittest.TestCase):
    """Verify public attack simulator endpoints and Apache-2.0 package artifacts."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_health_and_demo_presets(self) -> None:
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["service"], "orion-gate")

        resp = self.client.get("/v1/demo/presets")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(len(body["presets"]), 6)
        self.assertEqual(body["available_dialects"], ["postgres", "mysql", "bigquery"])

    def test_all_curated_presets_match_expected_outcomes(self) -> None:
        for preset in DEMO_PRESETS:
            with self.subTest(preset_id=preset.id):
                resp = self.client.post(
                    "/v1/demo/simulate",
                    json={
                        "sql": preset.sql,
                        "active_tenant": "org_acme",
                        "dialect": "postgres",
                    },
                )
                self.assertEqual(resp.status_code, 200)
                data = resp.json()
                self.assertEqual(data["orion_gate"]["status"], preset.expected_orion_outcome)

    def test_packaging_artifacts_and_entrypoint(self) -> None:
        pyproject_path = GATE_ROOT / "pyproject.toml"
        parsed = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        project = parsed["project"]
        self.assertEqual(project["name"], "orion-gate")
        self.assertEqual(project["scripts"]["orion-gate"], "orion_gate.cli:main")

        dockerfile_gate = (GATE_ROOT / "Dockerfile.gate").read_text(encoding="utf-8")
        self.assertIn("orion-gate serve", dockerfile_gate)
        self.assertIn("USER orionuser", dockerfile_gate)

        manifest = json.loads((GATE_ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["packages"][0]["identifier"], "orion-gate")
        self.assertEqual(manifest["packages"][0]["transport"]["type"], "streamable-http")

        self.assertTrue((GATE_ROOT / "LICENSE").is_file())
        self.assertTrue((GATE_ROOT / "SECURITY.md").is_file())
        self.assertTrue((GATE_ROOT / "benchmarks" / "ast_latency.py").is_file())


class GatewayControlPlaneAgentTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_active_orion_yaml()

    def test_standalone_mode_makes_zero_control_plane_calls(self) -> None:
        import asyncio
        from orion_gate.security.cloud_sync import CloudTelemetrySyncClient, GatewayControlPlaneAgent

        cfg = parse_orion_yaml(SAMPLE_YAML)
        set_active_orion_yaml(cfg)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ORION_API_KEY", None)
            os.environ.pop("ORION_CLOUD_URL", None)
            self.assertFalse(CloudTelemetrySyncClient(cfg).control_plane_enabled)
            reloaded = asyncio.run(GatewayControlPlaneAgent().sync_once())
            self.assertFalse(reloaded)

    def test_register_heartbeat_hot_reload_and_fail_open_on_cloud_outage(self) -> None:
        import asyncio
        import httpx
        from orion_gate.security.cloud_sync import GatewayControlPlaneAgent

        initial_yaml = SAMPLE_YAML + "\ncloud:\n  sync_policies: true\n"
        cfg = parse_orion_yaml(initial_yaml)
        set_active_orion_yaml(cfg)

        updated_dict = {
            "version": "1.0",
            "workspace": {"id": str(cfg.workspace_id), "name": cfg.workspace_name},
            "datasource": {
                "id": str(cfg.primary_datasource.id),
                "name": cfg.primary_datasource.name,
                "dialect": "postgres",
                "url": "postgresql://readonly:secret@db.internal:5432/acme_prod?sslmode=require",
            },
            "policy": {
                "allowed_tables": ["orders"],
                "limits": {"max_rows": 25, "timeout_seconds": 5},
            },
        }

        calls: list[tuple[str, str, str]] = []
        fail_cloud = {"enabled": False}
        heartbeat_versions: list[int | None] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            q = request.url.query
            calls.append((request.method, request.url.path, q.decode() if isinstance(q, bytes) else (q or "")))
            if fail_cloud["enabled"]:
                return httpx.Response(503, json={"detail": "Cloud temporarily unavailable"})
            if request.url.path == "/v1/gateways/register":
                return httpx.Response(
                    201,
                    json={"id": "00000000-0000-0000-0000-00000000aaaa", "policy_drift": True},
                )
            if request.url.path == "/v1/telemetry/policy-bundle":
                return httpx.Response(200, json={"policy_version": 7, "orion_yaml": updated_dict})
            if request.url.path == "/v1/gateways/00000000-0000-0000-0000-00000000aaaa/heartbeat":
                body = json.loads(request.content.decode("utf-8"))
                heartbeat_versions.append(body.get("active_policy_version"))
                return httpx.Response(200, json={"sync_required": False, "policy_drift": False})
            return httpx.Response(404)

        agent = GatewayControlPlaneAgent(
            transport=httpx.MockTransport(_handler),
            api_key="ok_test_edge_key_123456",
            endpoint="https://cloud.oriongate.test",
        )

        # 1. First sync registers, sees policy_drift=True, pulls ?environment=staging, hot-reloads policy (max_rows=25), preserves local auth
        with patch.dict(os.environ, {"ORION_ENVIRONMENT": "staging"}, clear=False):
            reloaded = asyncio.run(agent.sync_once())
        self.assertTrue(reloaded)
        active = get_active_orion_yaml()
        self.assertIsNotNone(active)
        self.assertEqual(active.policy.limits.max_rows, 25)
        self.assertEqual(active.auth.token_env, cfg.auth.token_env)
        self.assertEqual(heartbeat_versions, [7])
        self.assertEqual(
            calls,
            [
                ("POST", "/v1/gateways/register", ""),
                ("GET", "/v1/telemetry/policy-bundle", "environment=staging"),
                ("POST", "/v1/gateways/00000000-0000-0000-0000-00000000aaaa/heartbeat", ""),
            ],
        )

        # 2. Second sync heartbeats cleanly with no drift
        reloaded2 = asyncio.run(agent.sync_once())
        self.assertFalse(reloaded2)

        # 3. Cloud 503 outage fails open without crashing and keeps active policy intact
        fail_cloud["enabled"] = True
        reloaded3 = asyncio.run(agent.sync_once())
        self.assertFalse(reloaded3)
        self.assertEqual(get_active_orion_yaml().policy.limits.max_rows, 25)


if __name__ == "__main__":
    unittest.main()
