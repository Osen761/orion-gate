"""Orion Gate CLI entrypoint (`orion-gate validate | check-sql | mint-token | serve`)."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from typing import Sequence

import uvicorn

from orion_gate.auth import AuthContext
from orion_gate.models import Workspace
from orion_gate.security.cloud_sync import CloudTelemetrySyncClient
from orion_gate.security.orion_yaml import (
    OrionYamlConfig,
    issue_standalone_agent_token,
    load_orion_yaml,
    set_active_orion_yaml,
)
from orion_gate.security.schema_projection import (
    ProjectedSchema,
    SchemaProjectionService,
)
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


def _build_synthetic_projected_schema(config: OrionYamlConfig) -> ProjectedSchema:
    """Build a projected schema purely from `orion.yaml` rules for zero-DB CLI `check-sql`."""

    ds = config.primary_datasource
    connector = ds.to_connector_model(config.workspace_id, config.policy.allowed_tables)
    tables = list(config.policy.allowed_tables or ())
    for tbl in config.policy.tenant_isolation.tables:
        if tbl not in tables:
            tables.append(tbl)
    if not tables:
        tables = ["orders", "customers", "invoices"]

    raw_lines: list[str] = []
    for tbl in tables:
        tenant_col = config.policy.tenant_isolation.tables.get(tbl, "org_id")
        cols: dict[str, str] = {
            "id": "uuid",
            tenant_col: "text",
        }
        if config.policy.allowed_columns:
            for item in config.policy.allowed_columns:
                if "." in item:
                    tname, cname = item.split(".", 1)
                    if tname == tbl:
                        cols.setdefault(cname, "text")
                else:
                    cols.setdefault(item, "text")
        else:
            for cname, dtype in (
                ("name", "text"),
                ("email", "text"),
                ("phone", "text"),
                ("status", "text"),
                ("amount", "numeric"),
                ("total", "numeric"),
                ("created_at", "timestamp"),
            ):
                cols.setdefault(cname, dtype)
        for key in config.policy.pii_masking:
            if "." in key:
                tname, cname = key.split(".", 1)
                if tname == tbl:
                    cols.setdefault(cname, "text")

        raw_lines.append(f"Table: {tbl} (100 rows)")
        for cname, dtype in cols.items():
            raw_lines.append(f"  - {cname}: {dtype}")

    auth = AuthContext(
        workspace_id=str(config.workspace_id),
        workspace=Workspace(
            id=config.workspace_id,
            name=config.workspace_name,
            plan="standalone",
            owner_email="cli@oriongate.local",
        ),
        auth_type="api_key",
        user_id="cli",
    )
    scope = config.build_effective_scope(
        datasource=ds,
        auth=auth,
        requested_tenant_values=(
            {config.policy.tenant_isolation.claim: "placeholder"}
            if config.policy.tenant_isolation.required
            else None
        ),
    )
    projected = SchemaProjectionService().project_schema(
        connector,
        "\n".join(raw_lines),
        scope,
    )
    return projected


def _cmd_validate(args: argparse.Namespace) -> int:
    config = load_orion_yaml(args.config)
    payload = {
        "valid": True,
        "version": config.version,
        "workspace_id": str(config.workspace_id),
        "workspace_name": config.workspace_name,
        "policy_hash": config.policy_hash,
        "datasources": [
            {
                "id": str(ds.id),
                "name": ds.name,
                "dialect": ds.dialect,
                "url_env": ds.url_env,
            }
            for ds in config.datasources
        ],
        "tenant_isolation": {
            "required": config.policy.tenant_isolation.required,
            "claim": config.policy.tenant_isolation.claim,
            "tables": config.policy.tenant_isolation.tables,
        },
        "limits": {
            "max_rows": config.policy.limits.max_rows,
            "timeout_seconds": config.policy.limits.timeout_seconds,
            "allow_raw_pii": config.policy.limits.allow_raw_pii,
            "allow_raw_rows": config.policy.limits.allow_raw_rows,
        },
    }
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_check_sql(args: argparse.Namespace) -> int:
    config = load_orion_yaml(args.config)
    ds = config.primary_datasource
    connector = ds.to_connector_model(config.workspace_id, config.policy.allowed_tables)
    claim_key = config.policy.tenant_isolation.claim
    tenant_values = {claim_key: args.tenant} if args.tenant else None

    auth = AuthContext(
        workspace_id=str(config.workspace_id),
        workspace=Workspace(
            id=config.workspace_id,
            name=config.workspace_name,
            plan="standalone",
            owner_email="cli@oriongate.local",
        ),
        auth_type="api_key",
        user_id="cli",
    )
    scope = config.build_effective_scope(
        datasource=ds,
        auth=auth,
        requested_tenant_values=tenant_values,
    )
    if args.schema_text:
        projected = SchemaProjectionService().project_schema(
            connector,
            args.schema_text,
            scope,
        )
    else:
        projected = _build_synthetic_projected_schema(config)

    decision = SQLPolicyGateway().validate(
        args.sql,
        SQLValidationContext(
            dialect=ds.dialect,
            scope=scope,
            projected_schema=projected,
            connector_type=ds.dialect,
            auto_inject_tenant_filters=True,
        ),
    )
    output = {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "original_sql": args.sql,
        "rewritten_sql": decision.safe_sql,
        "tenant_predicates_injected": decision.tenant_predicates_injected,
        "injected_predicates_count": decision.injected_predicates_count,
        "row_limit_applied": decision.row_limit_applied,
        "max_rows": decision.max_rows,
        "tables_referenced": list(decision.tables_referenced),
        "columns_referenced": list(decision.columns_referenced),
        "violations": [
            {"code": v.code, "message": v.message, "severity": v.severity}
            for v in decision.violations
        ],
    }
    print(json.dumps(output, indent=2))
    return 0 if decision.allowed else 2


def _cmd_mint_token(args: argparse.Namespace) -> int:
    config = load_orion_yaml(args.config)
    token = issue_standalone_agent_token(
        config,
        subject=args.sub,
        tenant_id=args.tenant,
        agent_role=args.role,
        purpose=args.purpose,
        ttl_seconds=args.ttl,
        secret=args.secret,
    )
    print(
        json.dumps(
            {
                "token": token,
                "token_type": "Bearer",
                "subject": args.sub,
                "tenant_id": args.tenant,
                "ttl_seconds": args.ttl,
            },
            indent=2,
        )
    )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    resolved_path = os.path.abspath(args.config)
    config = load_orion_yaml(resolved_path)
    if config.cloud.sync_policies and os.getenv(config.cloud.api_key_env, "").strip():
        try:
            synced = asyncio.run(CloudTelemetrySyncClient(config).pull_policy_bundle())
            config = synced
        except Exception as exc:
            print(
                f"Warning: Policy bundle sync failed ({exc}); using local {resolved_path}",
                file=sys.stderr,
            )
    os.environ["ORION_YAML_PATH"] = resolved_path
    set_active_orion_yaml(config)
    uvicorn.run(
        "orion_gate.gate_app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orion-gate",
        description="Orion Gate — Zero-Trust SQL & MCP Firewall CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_p = subparsers.add_parser("validate", help="Validate an orion.yaml policy file")
    validate_p.add_argument("--config", "-c", default="orion.yaml", help="Path to orion.yaml")

    check_p = subparsers.add_parser(
        "check-sql",
        help="Validate and AST-rewrite a SQL statement against an orion.yaml policy",
    )
    check_p.add_argument("--config", "-c", default="orion.yaml", help="Path to orion.yaml")
    check_p.add_argument("--sql", required=True, help="Candidate SQL query to evaluate")
    check_p.add_argument("--tenant", default=None, help="Tenant claim value (e.g. org_acme)")
    check_p.add_argument("--schema-text", default=None, help="Optional raw schema text")

    token_p = subparsers.add_parser(
        "mint-token",
        help="Mint a scoped HS256 agent JWT for standalone Orion Gate",
    )
    token_p.add_argument("--config", "-c", default="orion.yaml", help="Path to orion.yaml")
    token_p.add_argument("--sub", default="agent-1", help="Agent or user subject ID")
    token_p.add_argument("--tenant", default=None, help="Tenant ID claim value")
    token_p.add_argument("--role", default="support_agent", help="Agent role claim")
    token_p.add_argument("--purpose", default="governed_sql", help="Query purpose claim")
    token_p.add_argument("--ttl", type=int, default=900, help="Token TTL in seconds")
    token_p.add_argument("--secret", default=None, help="Override HS256 signing secret")

    serve_p = subparsers.add_parser(
        "serve",
        help="Run Orion Gate standalone server (/v1/schema, /v1/query, /mcp) with orion.yaml",
    )
    serve_p.add_argument("--config", "-c", default="orion.yaml", help="Path to orion.yaml")
    serve_p.add_argument("--host", default="0.0.0.0", help="Bind host")
    serve_p.add_argument("--port", type=int, default=8000, help="Bind port")
    serve_p.add_argument("--reload", action="store_true", help="Enable auto-reload")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "validate":
            return _cmd_validate(args)
        if args.command == "check-sql":
            return _cmd_check_sql(args)
        if args.command == "mint-token":
            return _cmd_mint_token(args)
        if args.command == "serve":
            return _cmd_serve(args)
    except Exception as exc:
        print(json.dumps({"valid": False, "error": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
