"""MySQL connector for Orion."""

from __future__ import annotations

import json
import re
import traceback
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import pandas as pd
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from orion_gate.connectors.base import BaseConnector
from orion_gate.connectors.pool_manager import get_or_create_mysql_engine
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
    "EXECUTE",
)
MYSQL_TIMEOUT_SECONDS = 30
MYSQL_ROW_LIMIT = 10_000
MYSQL_SSL_CA = "/etc/ssl/certs/ca-certificates.crt"


def _normalize_mysql_connection_string(connection_string: str) -> str:
    if connection_string.startswith("mysql://"):
        connection_string = connection_string.replace("mysql://", "mysql+pymysql://", 1)

    parsed = urlparse(connection_string)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        query.setdefault("ssl_verify_cert", "true")
        query.setdefault("ssl_ca", MYSQL_SSL_CA)
    return urlunparse(parsed._replace(query=urlencode(query)))


class MySQLConnector(BaseConnector):
    """Connector implementation for MySQL-compatible databases."""

    def __init__(
        self,
        connection_string: str,
        allowed_tables: list[str] | None = None,
        connector_id: str | None = None,
    ) -> None:
        self.connection_string = _normalize_mysql_connection_string(connection_string)
        self.allowed_tables = set(allowed_tables or [])
        self.connector_id = connector_id
        parsed = urlparse(self.connection_string)
        connect_args: dict[str, Any] = {}
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            connect_args["ssl"] = {"ca": MYSQL_SSL_CA}
        self._connect_args = connect_args
        self._engine: Engine | None = None
        self._owns_engine = connector_id == "test-only"

    @property
    def engine(self) -> Engine:
        existing = getattr(self, "_engine", None)
        if existing is not None:
            return existing
        created = get_or_create_mysql_engine(
            self.connection_string,
            connect_args=getattr(self, "_connect_args", {}),
            cacheable=not getattr(self, "_owns_engine", False),
            pool_size=3,
            max_overflow=2,
        )
        self._engine = created
        return created

    @engine.setter
    def engine(self, value: Engine) -> None:
        self._engine = value

    def close(self) -> None:
        if getattr(self, "_owns_engine", False) and getattr(self, "_engine", None) is not None:
            try:
                self._engine.dispose()
            except Exception:
                pass
            self._engine = None

    def get_schema(self) -> str:
        cache_key = f"connector_schema:{self.connector_id}" if self.connector_id else None
        if cache_key:
            cached_schema = self._cache_lookup(cache_key)
            if cached_schema:
                return cached_schema

        with self.engine.connect() as conn:
            catalog_df = pd.read_sql(
                text(
                    """
                    SELECT
                        t.TABLE_NAME AS table_name,
                        COALESCE(t.TABLE_ROWS, 0) AS approx_rows,
                        c.COLUMN_NAME AS column_name,
                        c.COLUMN_TYPE AS data_type
                    FROM INFORMATION_SCHEMA.TABLES t
                    LEFT JOIN INFORMATION_SCHEMA.COLUMNS c
                      ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
                    WHERE t.TABLE_SCHEMA = DATABASE()
                      AND t.TABLE_TYPE = 'BASE TABLE'
                    ORDER BY t.TABLE_NAME, c.ORDINAL_POSITION
                    """
                ),
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

    def execute_query(self, sql: str) -> tuple[pd.DataFrame, str]:
        stripped = sql.strip()
        if not stripped.upper().startswith(("SELECT", "WITH")):
            return pd.DataFrame(), "ERROR: Orion Gate only executes read-only SELECT/WITH SQL queries."
        return self._execute_sql(stripped)


    def test_connection(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError as exc:
            message = str(exc)
            if "Access denied" in message:
                raise ValueError("Could not connect: access denied (wrong credentials)") from exc
            if "Unknown database" in message:
                raise ValueError("Could not connect: unknown database") from exc
            if "Can't connect to MySQL server" in message or "Connection refused" in message:
                raise ValueError("Could not connect: can't connect to MySQL server") from exc
            if "ssl" in message.lower():
                raise ValueError(
                    "Could not connect: SSL required. PlanetScale requires SSL. "
                    "Add ?ssl_ca=/etc/ssl/certs/ca-certificates.crt to your connection string"
                ) from exc
            raise ValueError(f"Could not connect: {message}") from exc

    def get_sample(self, table: str, n: int = 5) -> pd.DataFrame:
        if self.allowed_tables and table not in self.allowed_tables:
            raise ValueError(f"Table {table} is not allowed for this connector")

        with self.engine.connect() as conn:
            return pd.read_sql(
                text(f"SELECT * FROM `{table}` LIMIT :limit_value"),
                conn,
                params={"limit_value": int(n)},
            )

    def execute_sql(self, sql: str) -> tuple[pd.DataFrame, str]:
        return self._execute_sql(sql.strip())

    def _execute_sql(self, sql: str) -> tuple[pd.DataFrame, str]:
        safe_sql, policy_error = self._apply_sql_policy(sql)
        if policy_error:
            return pd.DataFrame(), policy_error

        try:
            sql_decision = getattr(self, "last_sql_policy_decision", None)
            if sql_decision is not None:
                referenced_tables = {
                    table_ref.split(".")[-1]
                    for table_ref in sql_decision.tables_referenced
                    if table_ref
                }
            else:
                referenced_tables = self._extract_referenced_tables(sql)
            if self.allowed_tables and not referenced_tables.issubset(self.allowed_tables):
                return pd.DataFrame(), "ERROR: Query references tables outside allowed_tables"

            sql_to_execute = safe_sql or sql
            limited_sql = f"SELECT * FROM ({sql_to_execute.rstrip().rstrip(';')}) AS orion_query LIMIT {MYSQL_ROW_LIMIT}"
            with self.engine.connect() as conn:
                self._apply_session_timeout(conn)
                cost_error = self._check_explain_cost(conn, limited_sql)
                if cost_error:
                    return pd.DataFrame(), cost_error
                df = pd.read_sql(text(limited_sql), conn)
            return self._apply_result_policy(df)
        except Exception:
            return pd.DataFrame(), f"ERROR: {traceback.format_exc().strip()}"

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
            return MYSQL_TIMEOUT_SECONDS
        return max(1, int(policy_context.scope.max_execution_seconds))

    def _apply_session_timeout(self, conn: Any) -> None:
        if not hasattr(conn, "execute"):
            return
        timeout_seconds = self._execution_timeout_seconds()
        timeout_ms = timeout_seconds * 1000
        try:
            conn.execute(text("SET SESSION max_execution_time = :ms"), {"ms": timeout_ms})
        except Exception:
            try:
                conn.execute(text("SET SESSION max_statement_time = :sec"), {"sec": timeout_seconds})
            except Exception:
                return

    def _check_explain_cost(self, conn: Any, sql: str) -> str | None:
        policy_context = getattr(self, "sql_policy_context", None)
        max_cost = (
            getattr(policy_context.scope, "max_query_cost", None)
            if policy_context is not None
            else None
        )
        if max_cost is None or not hasattr(conn, "execute"):
            return None
        try:
            result = conn.execute(text(f"EXPLAIN FORMAT=JSON {sql}"))
            row = result.fetchone()
            if not row:
                return None
            payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            if isinstance(payload, dict):
                cost_str = (
                    payload.get("query_block", {})
                    .get("cost_info", {})
                    .get("query_cost")
                )
                if cost_str is not None and float(cost_str) > float(max_cost):
                    return (
                        "ERROR: Query cost exceeds policy threshold. Narrow filters or "
                        "joins before re-running."
                    )
        except Exception:
            return None
        return None

    def _allowed_table_clause(self, tables: list[str]) -> list[str]:
        if not self.allowed_tables:
            return tables
        return [table for table in tables if table in self.allowed_tables]

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
                text(f"SELECT * FROM `{table_name}` LIMIT {MYSQL_ROW_LIMIT}"),
                conn,
            )
        return table_frames

    def _fetch_public_tables(self, conn) -> list[str]:
        tables_df = pd.read_sql(
            text(
                """
                SELECT TABLE_NAME AS table_name
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
                ORDER BY TABLE_NAME
                """
            ),
            conn,
        )
        return tables_df["table_name"].tolist()

    def _extract_referenced_tables(self, sql: str) -> set[str]:
        table_refs = re.findall(
            r"FROM\s+`?([a-zA-Z_][\w]*)`?|JOIN\s+`?([a-zA-Z_][\w]*)`?",
            sql,
            flags=re.IGNORECASE,
        )
        return {match[0] or match[1] for match in table_refs if match[0] or match[1]}

    def _sanitize_identifier(self, value: str) -> str:
        sanitized = re.sub(r"\W+", "_", value).strip("_")
        if not sanitized or sanitized[0].isdigit():
            sanitized = f"table_{sanitized}" if sanitized else ""
        return sanitized

    def _cache_lookup(self, key: str) -> str | None:
        return sync_cache_get(key)

    def _cache_store(self, key: str, value: str) -> None:
        sync_cache_set(key, value, ttl_seconds=60 * 60)
