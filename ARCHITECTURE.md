# Orion Gate Architecture

Orion Gate is a standalone, zero-LLM deterministic SQL AST and MCP security firewall (`Apache-2.0`) sitting between AI agents and production PostgreSQL, MySQL, and BigQuery databases.

## 5-Layer Defense Pipeline

```
AI Agent / MCP Client / App Backend
        │
        │  Authorization: Bearer <ORION_LOCAL_TOKEN or scoped HS256 JWT>
        ▼
  1. Schema Projection (`orion_gate/security/schema_projection.py`)
     • Filters schemas through `allowed_tables`, `denied_tables`, `allowed_columns`,
       `denied_columns`, default sensitive column/table lists, and JSON/JSONB blocks.
        │
        ▼
  2. SQL AST Firewall (`orion_gate/security/sql_policy.py`)
     • Parses SQL via `sqlglot` (rejects multi-statements, DDL/DML, `SELECT *`,
       `UNION` leaks, obfuscation functions, nested-quantifier regex, dangerous
       functions like `pg_read_file`/`dblink`, and cross joins).
     • Enforces lexical CTE / subquery / table-alias scoping and injects tenant
       predicates across `WHERE`, CTEs, `UNION` branches, and `LEFT JOIN ... ON`.
     • Clamps row limits deterministically (`LIMIT <= limits.max_rows`).
        │
        ▼
  3. K-Anonymity & Differencing Guard (`orion_gate/security/differencing.py`)
     • Tracks structural query templates (`template_hash` vs `variant_hash`) and
       blocks single-query or multi-query complement / `NULLIF` differencing attacks.
        │
        ▼
  4. Read-Only Connector Execution (`orion_gate/connectors/`)
     • Executes rewritten SQL via pooled PostgreSQL, MySQL, or BigQuery connectors
       with statement timeouts and optional cost / bytes-billed guardrails.
        │
        ▼
  5. Result Policy & PII Scrubbing (`orion_gate/security/result_policy.py`)
     • Enforces `limits.max_rows`, k-anonymity `minimum_group_size` suppression,
       declarative `pii_masking` rules (`redact`, `redact_email`, `mask_phone`,
       `hash`, `last4`), and defense-in-depth scrubbing of secrets, emails, phones,
       SSNs, and Luhn-valid payment card numbers.
```

## Runtime Interfaces

- **CLI (`orion_gate/cli.py` / `orion-gate`):**
  - `orion-gate validate --config orion.yaml`
  - `orion-gate check-sql --config orion.yaml --sql "..." --tenant org_acme`
  - `orion-gate mint-token --config orion.yaml --sub agent-1 --tenant org_acme`
  - `orion-gate serve --config orion.yaml --host 0.0.0.0 --port 8000`
- **REST Firewall (`orion_gate/api/gateway.py`):** `GET /v1/schema`, `POST /v1/query`
- **MCP Streamable HTTP Server (`orion_gate/api/mcp.py`):** `POST /mcp`, `GET /mcp`, `DELETE /mcp` exposing `list_allowed_tables`, `describe_table_schema`, and `query_governed_sql`
- **Interactive Attack Simulator (`orion_gate/api/demo_simulator.py`):** `GET /v1/demo/presets`, `POST /v1/demo/simulate`
- **Optional Control-Plane Telemetry Sync (`orion_gate/security/cloud_sync.py`):** opt-in row-free telemetry & policy-bundle client when `ORION_API_KEY` + `ORION_CLOUD_URL` are configured.
