"""Reproducible AST policy validation latency benchmark for Orion Gate.

Measures CPU time of `SQLPolicyGateway.validate(...)` only (parsing with sqlglot,
schema/column policy checks, tenant predicate injection, and SQL rendering).
Does NOT include database network latency or query execution time.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from uuid import uuid4

from orion_gate.authz.connectors import EffectiveAccessScope, TenantFilter
from orion_gate.models import Connector
from orion_gate.security.schema_projection import SchemaProjectionService
from orion_gate.security.sql_policy import SQLPolicyGateway, SQLValidationContext


RAW_SCHEMA = """
Table: orders (250,000 rows)
  - id: uuid
  - org_id: text
  - customer_id: uuid
  - email: text
  - amount: numeric
  - status: text
  - created_at: timestamp
Table: customers (50,000 rows)
  - id: uuid
  - org_id: text
  - company_name: text
  - email: text
  - phone: text
  - password_hash: text
"""

SAMPLE_QUERIES = (
    ("simple_select", "SELECT id, email, amount FROM orders WHERE status = 'paid' ORDER BY amount DESC"),
    (
        "join_aggregate",
        (
            "SELECT c.company_name, COUNT(o.id) AS order_count, SUM(o.amount) AS total_revenue "
            "FROM orders o INNER JOIN customers c ON o.customer_id = c.id "
            "WHERE o.status = 'paid' GROUP BY c.company_name ORDER BY total_revenue DESC"
        ),
    ),
    (
        "cte_union_blocked",
        (
            "WITH paid AS (SELECT id, amount FROM orders WHERE org_id = 'org_acme') "
            "SELECT id, amount FROM paid WHERE amount > 100 OR 1 = 1"
        ),
    ),
)


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, max(0, int(round((pct / 100.0) * (len(sorted_values) - 1)))))
    return sorted_values[index]


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine() or "unknown"


def run_benchmark(iterations: int = 3000, warmup: int = 60) -> dict[str, object]:
    workspace_id = uuid4()
    connector_id = uuid4()
    connector = Connector(
        id=connector_id,
        workspace_id=workspace_id,
        name="bench-postgres",
        type="postgres",
        secret_id="inline",
    )
    scope = EffectiveAccessScope(
        workspace_id=str(workspace_id),
        surface="gateway",
        principal_type="api_key",
        user_id="bench",
        member_id=None,
        role="member",
        connector_id=str(connector_id),
        connector_access_level="query",
        external_tenant_id="org_acme",
        allowed_tables=("orders", "customers"),
        denied_columns=("password_hash", "customers.password_hash"),
        tenant_filters=(
            TenantFilter(table="orders", column="org_id", value="org_acme", required=True),
            TenantFilter(table="customers", column="org_id", value="org_acme", required=True),
        ),
        allow_raw_rows=True,
        allow_sql_visibility=True,
        max_result_rows=100,
    )
    projected = SchemaProjectionService().project_schema(connector, RAW_SCHEMA, scope)
    ctx = SQLValidationContext(
        dialect="postgres",
        scope=scope,
        projected_schema=projected,
        connector_type="postgres",
        auto_inject_tenant_filters=True,
    )
    gateway = SQLPolicyGateway()

    for i in range(warmup):
        _, sql = SAMPLE_QUERIES[i % len(SAMPLE_QUERIES)]
        gateway.validate(sql, ctx)

    all_latencies_ms: list[float] = []
    per_query_ms: dict[str, list[float]] = {name: [] for name, _ in SAMPLE_QUERIES}

    for i in range(iterations):
        name, sql = SAMPLE_QUERIES[i % len(SAMPLE_QUERIES)]
        t0 = time.perf_counter()
        gateway.validate(sql, ctx)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        all_latencies_ms.append(elapsed_ms)
        per_query_ms[name].append(elapsed_ms)

    all_sorted = sorted(all_latencies_ms)
    breakdown = {}
    for name, values in per_query_ms.items():
        s = sorted(values)
        breakdown[name] = {
            "runs": len(s),
            "p50_ms": round(statistics.median(s), 3),
            "p95_ms": round(percentile(s, 95), 3),
            "p99_ms": round(percentile(s, 99), 3),
        }

    return {
        "scope": "SQLPolicyGateway.validate AST validation & rewrite only (excludes DB execution)",
        "iterations": iterations,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": _cpu_model(),
        "warmup_iterations": warmup,
        "overall": {
            "p50_ms": round(statistics.median(all_sorted), 3),
            "p95_ms": round(percentile(all_sorted, 95), 3),
            "p99_ms": round(percentile(all_sorted, 99), 3),
            "mean_ms": round(statistics.fmean(all_sorted), 3),
        },
        "queries": breakdown,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Orion Gate SQL AST policy validation latency.")
    parser.add_argument("--iterations", type=int, default=3000, help="Measured validation runs (default: 3000)")
    parser.add_argument("--warmup", type=int, default=60, help="Warmup runs before timing (default: 60)")
    args = parser.parse_args()
    result = run_benchmark(iterations=max(1, args.iterations), warmup=max(0, args.warmup))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
