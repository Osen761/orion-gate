# Orion Gate Roadmap

## `v0.4.x` (Current Standalone OSS Extraction)
- Standalone Apache-2.0 `orion-gate` package, `orion-gate` CLI (`validate`, `check-sql`, `mint-token`, `serve`), REST (`/v1/schema`, `/v1/query`, `/v1/demo/simulate`), and Streamable HTTP MCP (`/mcp`).
- Multi-dialect `sqlglot` AST policy enforcement & tenant predicate injection (`postgres`, `mysql`, `bigquery`).
- Result-layer PII masking, Luhn-checked secret/card redaction, k-anonymity enforcement, and session differencing guard.
- Reproducible AST benchmark (`benchmarks/ast_latency.py`) and CI import-boundary checks.

## `v0.5.0` (Distribution & Live Dialect Hardening)
- Publish `orion-gate` to TestPyPI and PyPI (`pipx install orion-gate`).
- Record 20-30s Raw Agent vs. Orion Gate demo GIF for `README.md`.
- Switch Orion Cloud to import `orion-gate` as a dependency and remove Cloud's duplicated policy engine copy.
- Automated differential fuzzing tests against live containerized PostgreSQL and MySQL engines alongside AST unit suites.

## `v0.6.0+` (Ecosystem & Protocol Expansion)
- Additional read-only SQL dialects (Snowflake, DuckDB, ClickHouse) with per-dialect dangerous-function blocklists.
- Pluggable OpenTelemetry / structured JSON audit exporters for SIEM ingestion.
- Optional SQL wire-protocol (PostgreSQL pgwire) proxy mode in addition to HTTP/MCP.
