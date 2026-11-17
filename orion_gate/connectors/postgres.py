"""Postgres connector for Orion."""

from __future__ import annotations

import json
import re
import traceback
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import pandas as pd
import psycopg2
from psycopg2 import pool

from orion_gate.connectors.base import BaseConnector
from orion_gate.connectors.pool_manager import get_or_create_postgres_pool
from orion_gate.cache import sync_cache_get, sync_cache_set
from orion_gate.security.result_policy import ResultPolicyGateway, ResultValidationContext
from orion_gate.security.sql_policy import SQLPolicyGateway
from orion_gate.verification.service import VerificationContext, VerificationService


FORBIDDEN_SQL_PATTERNS = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "TRUNCATE",
    "GRANT",
)
POSTGRES_TIMEOUT_MS = 30_000
POSTGRES_ROW_LIMIT = 10_000


def _ensure_sslmode(connection_string: str) -> str:
    parsed = urlparse(connection_string)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.setdefault("sslmode", "require")
    return urlunparse(parsed._replace(query=urlencode(query)))


class PostgresConnector(BaseConnector):
    """Connector implementation for Postgres-compatible databases."""

    def __init__(
        self,
        connection_string: str,
        allowed_tables: list[str] | None = None,
        connector_id: str | None = None,
    ) -> None:
        self.connection_string = _ensure_sslmode(connection_string)
        self.allowed_tables = set(allowed_tables or [])
        self.connector_id = connector_id
        self._pool: pool.ThreadedConnectionPool | None = None
        self._owns_pool = connector_id == "test-only"

    @property
    def pool(self) -> pool.ThreadedConnectionPool:
        existing = getattr(self, "_pool", None)
        if existing is not None:
            return existing
        created = get_or_create_postgres_pool(
            self.connection_string,
            cacheable=not getattr(self, "_owns_pool", False),
            minconn=1,
            maxconn=5,
        )
        self._pool = created
        return created

    @pool.setter
    def pool(self, value: pool.ThreadedConnectionPool) -> None:
        self._pool = value

    def close(self) -> None:
        if getattr(self, "_owns_pool", False) and getattr(self, "_pool", None) is not None:
            try:
                self._pool.closeall()
            except Exception:
                pass
            self._pool = None

    def _get_connection(self):
        conn = self.pool.getconn()
        conn.autocommit = True
        policy_context = getattr(self, "sql_policy_context", None)
        timeout_ms = POSTGRES_TIMEOUT_MS
        if policy_context is not None:
            timeout_ms = max(1, int(policy_context.scope.max_execution_seconds)) * 1000
        with conn.cursor() as cursor:
            cursor.execute(
                "SET statement_timeout TO %s",
                (timeout_ms,),
            )
        return conn

    def _put_connection(self, conn) -> None:
        self.pool.putconn(conn)

    def _allowed_table_clause(self, tables: list[str]) -> list[str]:
        if not self.allowed_tables:
            return tables
        return [table for table in tables if table in self.allowed_tables]

    def get_schema(self) -> str:
        cache_key = f"connector_schema:{self.connector_id}" if self.connector_id else None
        if cache_key:
            cached_schema = self._cache_lookup(cache_key)
            if cached_schema:
                return cached_schema

        conn = self._get_connection()
        try:
            catalog_df = pd.read_sql(
                """
                SELECT
                    t.table_name AS table_name,
                    GREATEST(COALESCE(s.n_live_tup, c.reltuples::bigint, 0), 0) AS approx_rows,
                    col.column_name AS column_name,
                    col.data_type AS data_type
                FROM information_schema.tables t
                JOIN pg_namespace n
                  ON n.nspname = t.table_schema
                JOIN pg_class c
                  ON c.relnamespace = n.oid AND c.relname = t.table_name
                LEFT JOIN pg_stat_user_tables s
                  ON s.relid = c.oid
                LEFT JOIN information_schema.columns col
                  ON col.table_schema = t.table_schema AND col.table_name = t.table_name
                WHERE t.table_schema = 'public'
                  AND t.table_type = 'BASE TABLE'
                ORDER BY t.table_name, col.ordinal_position
                """,
                conn,
            )
            if catalog_df.empty:
                return ""

            allowed = set(self._allowed_table_clause(catalog_df["table_name"].drop_duplicates().tolist()))
            schema_chunks: list[str] = []
            for table_name, group in catalog_df.groupby("table_name", sort=False):
                if table_name not in allowed:
                    continue
                approx_rows = int(group.iloc[0]["approx_rows"] or 0)
                schema_chunks.append(f"Table: {table_name} ({approx_rows:,} rows)")
                for _, row in group.iterrows():
                    col_name = row.get("column_name")
                    if pd.notna(col_name) and col_name:
                        schema_chunks.append(f"  - {col_name}: {row['data_type']}")

            schema = "\n".join(schema_chunks).strip()
            if cache_key and schema:
                self._cache_store(cache_key, schema)
            return schema
        finally:
            self._put_connection(conn)

    def execute_query(self, sql: str) -> tuple[pd.DataFrame, str]:
        stripped = sql.strip()
        if not stripped.upper().startswith(("SELECT", "WITH")):
            return pd.DataFrame(), "ERROR: Orion Gate only executes read-only SELECT/WITH SQL queries."
        return self._execute_sql(stripped)


    def execute_sql(self, sql: str) -> tuple[pd.DataFrame, str]:
        return self._execute_sql(sql.strip())

    def _execute_sql(self, sql: str) -> tuple[pd.DataFrame, str]:
        safe_sql, policy_error = self._apply_sql_policy(sql)
        if policy_error:
            return pd.DataFrame(), policy_error

        conn = self._get_connection()
        try:
            sql_to_execute = safe_sql or sql
            sql_decision = getattr(self, "last_sql_policy_decision", None)
            if sql_decision is not None:
                referenced_tables = {
                    table_ref.split(".")[-1]
                    for table_ref in sql_decision.tables_referenced
                    if table_ref
                }
            else:
                table_refs = re.findall(
                    r'FROM\s+"?([a-zA-Z_][\w]*)"?|JOIN\s+"?([a-zA-Z_][\w]*)"?',
                    sql_to_execute,
                    flags=re.IGNORECASE,
                )
                referenced_tables = {match[0] or match[1] for match in table_refs if match[0] or match[1]}
            if self.allowed_tables and not referenced_tables.issubset(self.allowed_tables):
                return pd.DataFrame(), "ERROR: Query references tables outside allowed_tables"

            limited_sql = f"SELECT * FROM ({sql_to_execute.rstrip().rstrip(';')}) AS orion_query LIMIT {POSTGRES_ROW_LIMIT}"
            cost_error = self._check_explain_cost(conn, limited_sql)
            if cost_error:
                return pd.DataFrame(), cost_error
            df = pd.read_sql(limited_sql, conn)
            return self._apply_result_policy(df)
        except Exception:
            return pd.DataFrame(), f"ERROR: {traceback.format_exc().strip()}"
        finally:
            self._put_connection(conn)

    def _apply_sql_policy(self, sql: str) -> tuple[str | None, str | None]:
        policy_context = getattr(self, "sql_policy_context", None)
        if policy_context is None:
            return sql, None
        decision = SQLPolicyGateway().validate(sql, policy_context)
        self.last_sql_policy_decision = decision
        if not decision.allowed:
            return None, decision.safe_error_message
        return decision.safe_sql or decision.normalized_sql or sql, None

    def _apply_result_policy(self, df: pd.DataFrame) -> tuple[pd.DataFrame, str]:
        policy_context = getattr(self, "sql_policy_context", None)
        if policy_context is None:
            return df, df.to_string(index=False)
        gateway = ResultPolicyGateway()
        decision = gateway.validate(
            df,
            ResultValidationContext(
                scope=policy_context.scope,
                projected_schema=policy_context.projected_schema,
                sql_policy_decision=getattr(self, "last_sql_policy_decision", None),
                connector_type=policy_context.connector_type,
                connector_id=policy_context.scope.connector_id,
            ),
        )
        self.last_result_policy_decision = decision
        verification = VerificationService().verify(
            VerificationContext(
                scope=policy_context.scope,
                projected_schema=policy_context.projected_schema,
                sql_policy_decision=getattr(self, "last_sql_policy_decision", None),
                result_policy_decision=decision,
                safe_result=decision.safe_result,
                connector_type=policy_context.connector_type,
            )
        )
        self.last_verification_result = verification
        if not decision.allowed or decision.safe_result is None:
            return pd.DataFrame(), decision.safe_error_message
        safe_df = decision.safe_result.to_dataframe()
        return safe_df, "\n\n".join(
            (
                gateway.to_model_text(decision.safe_result),
                verification.to_model_text(),
            )
        )

    def _execution_timeout_seconds(self) -> int:
        policy_context = getattr(self, "sql_policy_context", None)
        if policy_context is None:
            return 30
        return max(1, int(policy_context.scope.max_execution_seconds))

    def _check_explain_cost(self, conn: Any, sql: str) -> str | None:
        policy_context = getattr(self, "sql_policy_context", None)
        max_cost = (
            getattr(policy_context.scope, "max_query_cost", None)
            if policy_context is not None
            else None
        )
        if max_cost is None or not hasattr(conn, "cursor"):
            return None
        try:
            with conn.cursor() as cursor:
                cursor.execute(f"EXPLAIN (FORMAT JSON) {sql}")
                row = cursor.fetchone()
            if not row:
                return None
            plan_payload = row[0]
            if isinstance(plan_payload, str):
                plan_payload = json.loads(plan_payload)
            if isinstance(plan_payload, list) and plan_payload:
                total_cost = float(plan_payload[0].get("Plan", {}).get("Total Cost", 0.0))
                if total_cost > float(max_cost):
                    return (
                        "ERROR: Query cost exceeds policy threshold. Narrow filters or "
                        "joins before re-running."
                    )
        except Exception:
            return None
        return None

    def test_connection(self) -> bool:
        conn = None
        try:
            conn = psycopg2.connect(self.connection_string)
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            return True
        except Exception as exc:
            raise ValueError(f"Could not connect: {exc}") from exc
        finally:
            if conn is not None:
                conn.close()

    def get_sample(self, table: str, n: int = 5) -> pd.DataFrame:
        if self.allowed_tables and table not in self.allowed_tables:
            raise ValueError(f"Table {table} is not allowed for this connector")

        conn = self._get_connection()
        try:
            return pd.read_sql(
                f'SELECT * FROM "{table}" LIMIT %s',
                conn,
                params=(n,),
            )
        finally:
            self._put_connection(conn)

    def _cache_lookup(self, key: str) -> str | None:
        return sync_cache_get(key)

    def _cache_store(self, key: str, value: str) -> None:
        sync_cache_set(key, value, ttl_seconds=60 * 60)

    def _build_table_frames(self, conn) -> dict[str, pd.DataFrame]:
        if getattr(self, "sql_policy_context", None) is not None:
            return {}

        table_names: list[str]
        if self.allowed_tables:
            table_names = sorted(self.allowed_tables)
        else:
            table_names = self._fetch_public_tables(conn)

        table_frames: dict[str, pd.DataFrame] = {}
        for table_name in table_names[:5]:
            safe_name = self._sanitize_identifier(table_name)
            if not safe_name:
                continue
            table_frames[safe_name] = pd.read_sql(
                f'SELECT * FROM "{table_name}" LIMIT {POSTGRES_ROW_LIMIT}',
                conn,
            )
        return table_frames

    def _fetch_public_tables(self, conn) -> list[str]:
        tables_df = pd.read_sql(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name
            """,
            conn,
        )
        return tables_df["table_name"].tolist()

    def _sanitize_identifier(self, value: str) -> str:
        sanitized = re.sub(r"\W+", "_", value).strip("_")
        if not sanitized or sanitized[0].isdigit():
            sanitized = f"table_{sanitized}" if sanitized else ""
        return sanitized
