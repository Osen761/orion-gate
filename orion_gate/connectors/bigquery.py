"""BigQuery connector for Orion."""

from __future__ import annotations

import inspect
import re
import traceback
from typing import Any

import pandas as pd
from google.cloud import bigquery
from google.oauth2 import service_account

from orion_gate.connectors.base import BaseConnector
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
BIGQUERY_TIMEOUT_SECONDS = 60
BIGQUERY_ROW_LIMIT = 10_000
BIGQUERY_READONLY_SCOPES = ["https://www.googleapis.com/auth/bigquery.readonly"]


class BigQueryConnector(BaseConnector):
    """Connector implementation for Google BigQuery datasets."""

    def __init__(
        self,
        service_account_json: dict[str, Any],
        project_id: str,
        dataset_ids: list[str] | None = None,
        connector_id: str | None = None,
    ) -> None:
        self.service_account_json = service_account_json
        self.project_id = project_id
        self.dataset_ids = set(dataset_ids or [])
        self.connector_id = connector_id

        try:
            credentials = service_account.Credentials.from_service_account_info(
                service_account_json,
                scopes=BIGQUERY_READONLY_SCOPES,
            )
        except Exception as exc:
            raise ValueError(f"Could not connect: invalid service account JSON: {exc}") from exc

        try:
            self.client = bigquery.Client(
                project=self.project_id,
                credentials=credentials,
            )
        except Exception as exc:
            raise ValueError(f"Could not connect: {exc}") from exc

    def get_schema(self) -> str:
        cache_key = f"connector_schema:{self.connector_id}" if self.connector_id else None
        if cache_key:
            cached_schema = self._cache_lookup(cache_key)
            if cached_schema:
                return cached_schema

        schema_chunks: list[str] = []
        for dataset in self._list_datasets():
            table_items = list(self.client.list_tables(dataset.reference))
            if not table_items:
                continue

            schema_chunks.append(f"Dataset: {dataset.dataset_id}")
            for table_item in table_items:
                table = self.client.get_table(table_item.reference)
                row_count = table.num_rows or 0
                schema_chunks.append(
                    f"Table: {table.table_id} ({int(row_count):,} rows)"
                )
                for field in table.schema:
                    schema_chunks.append(f"  - {field.name}: {field.field_type}")

        schema = "\n".join(schema_chunks).strip()
        if cache_key and schema:
            self._cache_store(cache_key, schema)
        return schema

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

        try:
            sql_to_execute = safe_sql or sql
            referenced_datasets = self._extract_referenced_datasets(sql_to_execute)
            if self.dataset_ids and referenced_datasets and not referenced_datasets.issubset(self.dataset_ids):
                return pd.DataFrame(), "ERROR: Query references datasets outside dataset_ids"

            limited_sql = f"SELECT * FROM ({sql_to_execute.rstrip().rstrip(';')}) AS orion_query LIMIT {BIGQUERY_ROW_LIMIT}"
            query_kwargs: dict[str, Any] = {}
            policy_context = getattr(self, "sql_policy_context", None)
            max_bytes_billed = (
                getattr(policy_context.scope, "max_bytes_billed", None)
                if policy_context is not None
                else None
            )
            if max_bytes_billed is None and policy_context is not None:
                max_bytes_billed = 1_000_000_000
            if max_bytes_billed is not None:
                try:
                    sig = inspect.signature(self.client.query)
                    if "job_config" in sig.parameters or any(
                        p.kind == inspect.Parameter.VAR_KEYWORD
                        for p in sig.parameters.values()
                    ):
                        query_kwargs["job_config"] = bigquery.QueryJobConfig(
                            maximum_bytes_billed=int(max_bytes_billed)
                        )
                except (TypeError, ValueError):
                    pass

            query_job = self.client.query(limited_sql, **query_kwargs)
            try:
                rows = query_job.result(timeout=self._execution_timeout_seconds())
            except Exception:
                if hasattr(query_job, "cancel"):
                    try:
                        query_job.cancel()
                    except Exception:
                        pass
                raise
            df = rows.to_dataframe()
            return self._apply_result_policy(df)
        except Exception as exc:
            error_text = str(exc)
            if "bytes billed" in error_text.lower() or "resources exceeded" in error_text.lower():
                error_text = f"{error_text} Note: BigQuery charges by bytes scanned; consider filtering partitions or narrowing selected columns."
            return pd.DataFrame(), f"ERROR: {error_text}"

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
            return BIGQUERY_TIMEOUT_SECONDS
        return max(1, int(policy_context.scope.max_execution_seconds))

    def test_connection(self) -> bool:
        try:
            datasets = list(self.client.list_datasets(project=self.project_id))
            if self.dataset_ids:
                visible_dataset_ids = {dataset.dataset_id for dataset in datasets}
                missing = sorted(self.dataset_ids - visible_dataset_ids)
                if missing:
                    raise ValueError(
                        f"Could not connect: datasets not found or not accessible: {', '.join(missing)}"
                    )
            return True
        except ValueError:
            raise
        except Exception as exc:
            message = str(exc)
            if "403" in message or "permission" in message.lower():
                raise ValueError(
                    "Could not connect: insufficient permissions. The service account needs BigQuery Data Viewer access."
                ) from exc
            if "404" in message or "not found" in message.lower():
                raise ValueError(f"Could not connect: project not found: {self.project_id}") from exc
            raise ValueError(f"Could not connect: {message}") from exc

    def get_sample(self, table: str, n: int = 5) -> pd.DataFrame:
        qualified_table = self._resolve_table_name(table)
        sql = f"SELECT * FROM `{qualified_table}` LIMIT {int(n)}"
        df, output = self._execute_sql(sql)
        if output.startswith("ERROR:"):
            raise ValueError(output.removeprefix("ERROR: ").strip())
        return df

    def _list_datasets(self) -> list[bigquery.DatasetListItem]:
        datasets = list(self.client.list_datasets(project=self.project_id))
        if not self.dataset_ids:
            return datasets
        return [dataset for dataset in datasets if dataset.dataset_id in self.dataset_ids]

    def _build_table_frames(self) -> dict[str, pd.DataFrame]:
        if getattr(self, "sql_policy_context", None) is not None:
            return {}

        table_frames: dict[str, pd.DataFrame] = {}
        for dataset in self._list_datasets()[:5]:
            for table_item in list(self.client.list_tables(dataset.reference))[:5]:
                table_name = f"{dataset.dataset_id}_{table_item.table_id}"
                safe_name = self._sanitize_identifier(table_name)
                if not safe_name:
                    continue
                sql = (
                    f"SELECT * FROM `{self.project_id}.{dataset.dataset_id}.{table_item.table_id}` "
                    f"LIMIT {BIGQUERY_ROW_LIMIT}"
                )
                query_job = self.client.query(sql)
                table_frames[safe_name] = query_job.result(timeout=BIGQUERY_TIMEOUT_SECONDS).to_dataframe()
        return table_frames

    def _resolve_table_name(self, table: str) -> str:
        normalized = table.strip().strip("`")
        parts = normalized.split(".")
        if len(parts) == 3:
            project_id, dataset_id, table_id = parts
        elif len(parts) == 2:
            project_id = self.project_id
            dataset_id, table_id = parts
        elif len(parts) == 1:
            matches: list[str] = []
            for dataset in self._list_datasets():
                for table_item in self.client.list_tables(dataset.reference):
                    if table_item.table_id == normalized:
                        matches.append(f"{self.project_id}.{dataset.dataset_id}.{normalized}")
            if len(matches) != 1:
                raise ValueError(f"Table {table} is ambiguous or not accessible")
            return matches[0]
        else:
            raise ValueError(f"Invalid table name: {table}")

        if self.dataset_ids and dataset_id not in self.dataset_ids:
            raise ValueError(f"Dataset {dataset_id} is not allowed for this connector")
        return f"{project_id}.{dataset_id}.{table_id}"

    def _extract_referenced_datasets(self, sql: str) -> set[str]:
        matches = re.findall(
            r"`?([a-zA-Z0-9_\-]+)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)`?",
            sql,
            flags=re.IGNORECASE,
        )
        return {dataset_id for _, dataset_id, _ in matches}

    def _sanitize_identifier(self, value: str) -> str:
        sanitized = re.sub(r"\W+", "_", value).strip("_")
        if not sanitized or sanitized[0].isdigit():
            sanitized = f"table_{sanitized}" if sanitized else ""
        return sanitized

    def _cache_lookup(self, key: str) -> str | None:
        return sync_cache_get(key)

    def _cache_store(self, key: str, value: str) -> None:
        sync_cache_set(key, value, ttl_seconds=60 * 60)
