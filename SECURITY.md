# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.4.x` (standalone Orion Gate) | Yes |
| `< 0.4.0` | No — upgrade to `0.4.0` or newer |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities, policy bypasses, parser differentials, or authentication flaws.

Report issues confidentially via:
- **GitHub Private Vulnerability Reporting:** use the **Security -> Advisories -> Report a vulnerability** workflow on this repository.
- **Email:** `osenmuntu761@gmail.com` (make sure to include a minimal reproduction query or `orion.yaml` snippet, affected dialect, and expected vs. observed output).

We aim to acknowledge reports within 48 hours and provide an assessment or patch timeline within 5 business days.

## Threat Scope & Defense-in-Depth Expectations

1. **Primary Control + Database Hardening:** Orion Gate's AST policy gateway is the primary AI-agent guardrail, not a substitute for database-native permissions. Always pair Orion Gate with:
   - a **read-only** database role (`SELECT` privilege only on approved tables),
   - **PostgreSQL Row-Level Security (RLS)** (or database views filtered by tenant) as defense-in-depth, and
   - short statement timeouts configured on both `orion.yaml` (`timeout_seconds`) and the database role.
2. **Views:** Only map base tables in `tenant_isolation.tables` unless any exposed view includes the mapped tenant column directly in its output. Views that aggregate or hide tenant columns must enforce tenant filtering inside the view definition.
3. **HS256 Signing Secret Hygiene:**
   - Store `ORION_JWT_SECRET` in a secret manager or Kubernetes Secret (`>= 32` random bytes), never in `orion.yaml` or git.
   - Rotate `ORION_JWT_SECRET` on a regular schedule and keep agent token TTLs short (`ttl <= 900` seconds recommended).
   - Never expose `ORION_JWT_SECRET`, `ORION_LOCAL_TOKEN`, or raw `DATABASE_URL` credentials in agent prompts, MCP instructions, or tool responses.
4. **No In-Process Code Execution:** `orion-gate` executes only parsed read-only `SELECT` / `WITH` SQL statements; there is no Python sandbox or `exec()` runtime inside the open-source firewall.
