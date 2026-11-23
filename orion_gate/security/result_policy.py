"""Deterministic result policy gateway for connector-backed analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Literal

import pandas as pd

from orion_gate.authz.connectors import EffectiveAccessScope, TenantFilter
from orion_gate.security.schema_projection import (
    ProjectedSchema,
    SENSITIVE_COLUMN_NAMES,
)
from orion_gate.security.sql_policy import SQLPolicyDecision


ResultDecision = Literal["allowed", "redacted", "denied", "requires_review"]
ResultType = Literal["aggregate", "table", "single_value", "time_series", "unknown"]

POLICY_VERSION = "phase_1e_v1"
DEFAULT_MAX_ROWS = 10_000
MAX_COLUMNS = 50
MAX_STRING_LENGTH = 500
MAX_SERIALIZED_BYTES = 250_000

COUNT_COLUMNS = {"count", "user_count", "customer_count", "n", "total_count", "row_count"}
AGGREGATE_HINTS = {
    "avg",
    "average",
    "count",
    "cnt",
    "max",
    "mean",
    "median",
    "min",
    "n",
    "rate",
    "revenue",
    "sum",
    "total",
}
IDENTIFIER_COLUMNS = {
    "account_id",
    "address",
    "api_key",
    "card_number",
    "customer_id",
    "doc_id",
    "email",
    "id",
    "name",
    "phone",
    "token",
    "user_id",
}
PII_ALIAS_SOURCE_NAMES = {
    "address",
    "email",
    "full_name",
    "name",
    "phone",
    "ssn",
    "user_email",
} | SENSITIVE_COLUMN_NAMES
SECRET_VALUE_RE = re.compile(
    r"("
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|ok_[A-Za-z0-9_]{16,}"
    r"|sk-[A-Za-z0-9_-]{16,}"
    r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{16,}"
    r"|whsec_[A-Za-z0-9_]{16,}"
    r"|(?:postgres(?:ql)?|mysql|redis|rediss)://[^\s\"'<>]+"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{16,}"
    r"|\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}"
    r"|[A-Za-z0-9_]*(?:access|refresh|auth|api|client)?_?(?:token|secret|password|private_key)[A-Za-z0-9_]*['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9._+/=-]{8,}"
    r"|\b\d{3}-\d{2}-\d{4}\b"
    r")",
    flags=re.IGNORECASE | re.DOTALL,
)
RAW_EMAIL_VALUE_RE = re.compile(
    r"\b(?!\S*\*\*\*@)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
RAW_PHONE_VALUE_RE = re.compile(
    r"(?<!\w)(?:"
    r"\+[1-9]\d{0,2}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"
    r"|(?:\+1[\s.-]?)?\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}"
    r"|[2-9]\d{2}[-.]\d{3}[-.]\d{4}"
    r")\b"
)
CARD_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?:\d{4}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?|\d{4}[ -]?\d{6}[ -]?\d{5}|\d{13,19})(?!\d)"
)


def _passes_luhn(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit() or len(set(digits)) == 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        num = int(ch)
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def _scrub_card_numbers(value: str) -> tuple[str, int]:
    hits = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal hits
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if _passes_luhn(digits):
            hits += 1
            return "[REDACTED_CARD]"
        return raw

    return CARD_CANDIDATE_RE.sub(_replace, value), hits


@dataclass(frozen=True)
class ResultPolicyViolation:
    """One deterministic result policy violation."""

    code: str
    message: str
    severity: str = "error"


@dataclass(frozen=True)
class ResultColumn:
    """One safe result column."""

    name: str
    dtype: str


@dataclass(frozen=True)
class ResultShape:
    """Original and returned result dimensions."""

    original_row_count: int
    returned_row_count: int
    original_column_count: int
    returned_column_count: int


@dataclass(frozen=True)
class SafeQueryResult:
    """Model-safe query result payload."""

    columns: tuple[ResultColumn, ...]
    rows: tuple[dict[str, Any], ...]
    row_count: int
    column_count: int
    truncated: bool
    redacted: bool
    warnings: tuple[str, ...]
    result_type: ResultType

    def to_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(list(self.rows), columns=[column.name for column in self.columns])


@dataclass(frozen=True)
class ResultValidationContext:
    """Context required to validate returned query results."""

    scope: EffectiveAccessScope
    projected_schema: ProjectedSchema
    sql_policy_decision: SQLPolicyDecision | None = None
    connector_type: str | None = None
    connector_id: str | None = None
    pii_masking: dict[str, str] | None = None


@dataclass(frozen=True)
class ResultPolicyDecision:
    """Result of validating and redacting a query result."""

    allowed: bool
    decision: ResultDecision
    reason: str
    violations: tuple[ResultPolicyViolation, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    original_row_count: int = 0
    returned_row_count: int = 0
    original_column_count: int = 0
    returned_column_count: int = 0
    redacted_columns: tuple[str, ...] = field(default_factory=tuple)
    denied_columns: tuple[str, ...] = field(default_factory=tuple)
    sensitive_columns_detected: tuple[str, ...] = field(default_factory=tuple)
    small_group_warnings: tuple[str, ...] = field(default_factory=tuple)
    safe_result: SafeQueryResult | None = None
    scope_version: str | None = None
    policy_version: str = POLICY_VERSION

    @property
    def safe_error_message(self) -> str:
        return (
            "ERROR: Result policy denied this result. Ask a narrower aggregate "
            "question using visible, non-sensitive fields."
        )


def _normalize_identifier(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().strip('"`[]').lower()


def _column_base_name(value: str) -> str:
    return _normalize_identifier(value).split(".")[-1]


def _scope_values(values: tuple[str, ...] | None) -> set[str] | None:
    if values is None:
        return None
    return {_normalize_identifier(value) for value in values}


def _is_sensitive_column_name(column_name: str) -> bool:
    normalized = _column_base_name(column_name).replace("-", "_")
    return normalized in SENSITIVE_COLUMN_NAMES or normalized in {
        "api_token",
        "auth_token",
        "credential",
        "credentials",
        "jwt",
        "password",
        "password_hash",
        "private_key",
        "secret",
        "token",
        "email",
        "phone",
        "address",
        "ssn",
    }


def _is_identifier_column(column_name: str) -> bool:
    normalized = _column_base_name(column_name).replace("-", "_")
    return normalized in IDENTIFIER_COLUMNS or normalized.endswith("_id")


def _has_aggregate_hint(column_name: str) -> bool:
    normalized = _column_base_name(column_name).replace("-", "_")
    return normalized in AGGREGATE_HINTS or any(
        normalized.startswith(f"{hint}_") or normalized.endswith(f"_{hint}")
        for hint in AGGREGATE_HINTS
    )


def _is_count_column(column_name: str) -> bool:
    return _column_base_name(column_name).replace("-", "_") in COUNT_COLUMNS


def _sql_count_columns(context: ResultValidationContext | None) -> set[str]:
    if context is None or context.sql_policy_decision is None:
        return set()
    return {
        _column_base_name(col)
        for col in (getattr(context.sql_policy_decision, "count_output_columns", ()) or ())
        if col
    }


def _projected_columns(projected_schema: ProjectedSchema) -> tuple[set[str], set[str]]:
    all_columns: set[str] = set()
    qualified_columns: set[str] = set()
    for item in projected_schema.schema_json.get("objects", []):
        if not isinstance(item, dict):
            continue
        object_names = {
            _normalize_identifier(str(item.get("name") or "")),
            _normalize_identifier(str(item.get("qualified_name") or "")),
        }
        object_names = {name for name in object_names if name}
        for column in item.get("columns", []):
            if not isinstance(column, dict):
                continue
            column_name = _normalize_identifier(str(column.get("name") or ""))
            if not column_name or column_name == "no visible columns":
                continue
            all_columns.add(column_name)
            for object_name in object_names:
                qualified_columns.add(f"{object_name}.{column_name}")
    return all_columns, qualified_columns


def _json_safe(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        return str(value)
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if value is None:
        return None
    if isinstance(value, (pd.Timestamp, datetime, date)):
        return value.isoformat()
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return value


def _tenant_filters(scope: EffectiveAccessScope) -> tuple[TenantFilter, ...]:
    filters: list[TenantFilter] = []
    for item in getattr(scope, "tenant_filters", ()):
        if isinstance(item, TenantFilter):
            if item.required:
                filters.append(item)
        elif isinstance(item, dict):
            try:
                tenant_filter = TenantFilter(**item)
            except TypeError:
                continue
            if tenant_filter.required:
                filters.append(tenant_filter)
    return tuple(filters)


class ResultPolicyGateway:
    """Validate, redact, and serialize query results before model exposure."""

    def validate(
        self,
        result: pd.DataFrame,
        context: ResultValidationContext,
    ) -> ResultPolicyDecision:
        """Return a deterministic policy decision for a query result."""

        original = result.copy()
        safe = result.copy()
        original_row_count = int(len(original.index))
        original_column_count = int(len(original.columns))
        violations: list[ResultPolicyViolation] = []
        warnings: list[str] = []
        redacted_columns: list[str] = []
        denied_columns: list[str] = []
        sensitive_columns: list[str] = []
        small_group_warnings: list[str] = []

        result_type = self.classify_result(original)
        projected_names, projected_qualified = _projected_columns(context.projected_schema)
        allowed_columns = _scope_values(context.scope.allowed_columns)
        denied_scope_columns = _scope_values(context.scope.denied_columns) or set()

        if original_column_count > MAX_COLUMNS:
            return self._deny(
                context,
                original,
                "requires_review",
                "Result requires review.",
                (ResultPolicyViolation("too_many_columns", "Result has too many columns."),),
                warnings=tuple(warnings),
                result_type=result_type,
            )

        tenant_check = self._apply_tenant_result_checks(safe, context)
        if tenant_check[0] is None:
            return self._deny(
                context,
                original,
                "denied",
                "Result denied by tenant policy.",
                (
                    ResultPolicyViolation(
                        "tenant_result_mismatch",
                        "A result contained data outside the required tenant scope.",
                    ),
                ),
                result_type=result_type,
            )
        safe, tenant_redactions, tenant_warnings = tenant_check
        if tenant_redactions:
            redacted_columns.extend(tenant_redactions)
            warnings.extend(tenant_warnings)

        safe, yaml_masked_columns = self._apply_yaml_column_masking(safe, context)
        if yaml_masked_columns:
            redacted_columns.extend(yaml_masked_columns)
            warnings.append("Declarative PII masking rules were applied to result columns.")

        unsafe_columns = self._unsafe_columns(
            safe,
            projected_names,
            projected_qualified,
            allowed_columns,
            denied_scope_columns,
            context,
            violations,
            denied_columns,
            sensitive_columns,
            pre_masked_columns=set(yaml_masked_columns),
        )
        if unsafe_columns:
            if len(unsafe_columns) >= len(safe.columns):
                return self._deny(
                    context,
                    original,
                    "denied",
                    "Result denied by column policy.",
                    tuple(violations),
                    denied_columns=tuple(sorted(set(denied_columns))),
                    sensitive_columns=tuple(sorted(set(sensitive_columns))),
                    result_type=result_type,
                )
            safe = safe.drop(columns=unsafe_columns)
            redacted_columns.extend(str(column) for column in unsafe_columns)
            warnings.append("Some sensitive result columns were redacted.")

        alias_violation = self._alias_sensitive_violation(context, safe)
        if alias_violation is not None:
            return self._deny(
                context,
                original,
                "requires_review",
                "Result requires review.",
                (alias_violation,),
                warnings=tuple(warnings),
                redacted_columns=tuple(sorted(set(redacted_columns))),
                sensitive_columns=tuple(sorted(set(sensitive_columns))),
                result_type=result_type,
            )

        if self._raw_rows_blocked(safe, context.scope, result_type):
            return self._deny(
                context,
                original,
                "denied",
                "Raw rows are not allowed for this scope.",
                (
                    ResultPolicyViolation(
                        "raw_rows_denied",
                        "Raw row-like results are not allowed for this scope.",
                    ),
                ),
                warnings=tuple(warnings),
                redacted_columns=tuple(sorted(set(redacted_columns))),
                result_type=result_type,
            )

        safe, value_redactions = self._redact_sensitive_values(safe, context)
        if value_redactions:
            warnings.append("Some sensitive result values were redacted.")

        safe, tenant_value_redactions = self._redact_tenant_values(safe, context)
        if tenant_value_redactions:
            warnings.append("Tenant values were redacted.")

        safe, cell_truncations = self._truncate_long_strings(safe)
        if cell_truncations:
            warnings.append("Some long result values were truncated.")

        safe, suppressed_groups = self._suppress_small_groups(safe, context.scope, context)
        if suppressed_groups:
            small_group_warnings.append("Small groups were suppressed.")
            warnings.append("Small groups were suppressed.")
            if safe.empty:
                return self._deny(
                    context,
                    original,
                    "denied",
                    "Result denied by minimum group size.",
                    (
                        ResultPolicyViolation(
                            "minimum_group_size",
                            "All groups were below the minimum group size.",
                        ),
                    ),
                    warnings=tuple(warnings),
                    small_group_warnings=tuple(small_group_warnings),
                    result_type=result_type,
                )

        max_rows = max(1, int(context.scope.max_result_rows or DEFAULT_MAX_ROWS))
        truncated = False
        if len(safe.index) > max_rows:
            safe = safe.head(max_rows)
            truncated = True
            warnings.append(f"Result was truncated to {max_rows} rows.")

        serialized_too_large = self._serialized_size(safe) > MAX_SERIALIZED_BYTES
        if serialized_too_large:
            return self._deny(
                context,
                original,
                "requires_review",
                "Result requires review.",
                (ResultPolicyViolation("result_too_large", "Serialized result is too large."),),
                warnings=tuple(warnings),
                redacted_columns=tuple(sorted(set(redacted_columns))),
                result_type=result_type,
            )

        safe_result = self._safe_result(
            safe,
            result_type,
            truncated=truncated,
            redacted=bool(redacted_columns or value_redactions),
            warnings=tuple(warnings),
        )
        decision: ResultDecision = "allowed"
        reason = "Result policy allowed result."
        if redacted_columns or value_redactions or tenant_value_redactions:
            decision = "redacted"
            reason = "Result policy redacted result."
        elif truncated:
            reason = "Result policy truncated result."

        return ResultPolicyDecision(
            allowed=True,
            decision=decision,
            reason=reason,
            warnings=tuple(warnings),
            original_row_count=original_row_count,
            returned_row_count=safe_result.row_count,
            original_column_count=original_column_count,
            returned_column_count=safe_result.column_count,
            redacted_columns=tuple(sorted(set(redacted_columns))),
            denied_columns=tuple(sorted(set(denied_columns))),
            sensitive_columns_detected=tuple(sorted(set(sensitive_columns))),
            small_group_warnings=tuple(small_group_warnings),
            safe_result=safe_result,
            scope_version=context.scope.scope_version,
        )

    def classify_result(self, result: pd.DataFrame) -> ResultType:
        if result.shape == (1, 1):
            return "single_value"
        if result.empty:
            return "table"

        columns = [_normalize_identifier(str(column)) for column in result.columns]
        date_like_columns = [
            column
            for column in result.columns
            if pd.api.types.is_datetime64_any_dtype(result[column])
            or _column_base_name(str(column)) in {"date", "day", "month", "week", "created_at"}
        ]
        numeric_columns = [
            column for column in result.columns if pd.api.types.is_numeric_dtype(result[column])
        ]
        if date_like_columns and numeric_columns:
            return "time_series"

        aggregate_columns = [column for column in columns if _has_aggregate_hint(column)]
        count_columns = [column for column in columns if _is_count_column(column)]
        if aggregate_columns or count_columns:
            return "aggregate"

        identifier_columns = [column for column in columns if _is_identifier_column(column)]
        if identifier_columns or len(result.index) > 1:
            return "table"
        return "unknown"

    def to_model_text(self, safe_result: SafeQueryResult) -> str:
        """Serialize a safe result for model/tool output."""

        lines: list[str] = []
        if safe_result.warnings:
            lines.append("Warnings:")
            for warning in safe_result.warnings:
                lines.append(f"- {warning}")
        df = safe_result.to_dataframe()
        if df.empty:
            lines.append("No rows returned.")
        else:
            lines.append(df.to_string(index=False))
        return "\n".join(lines).strip()

    def _apply_yaml_column_masking(
        self,
        result: pd.DataFrame,
        context: ResultValidationContext,
    ) -> tuple[pd.DataFrame, list[str]]:
        from orion_gate.security.orion_yaml import apply_yaml_pii_masking, get_active_orion_yaml

        masking_rules = dict(context.pii_masking or {})
        if not masking_rules:
            active_yaml = get_active_orion_yaml()
            if active_yaml is not None and active_yaml.policy.pii_masking:
                masking_rules = dict(active_yaml.policy.pii_masking)
        if not masking_rules or result.empty and len(result.columns) == 0:
            return result, []

        referenced_tables = (
            context.sql_policy_decision.tables_referenced
            if context.sql_policy_decision is not None
            else ()
        )
        col_names = [str(col) for col in result.columns]
        raw_rows = result.to_dict(orient="records")
        masked_rows, masked_cols = apply_yaml_pii_masking(
            raw_rows,
            col_names,
            masking_rules,
            referenced_tables=referenced_tables,
        )
        if not masked_cols:
            return result, []
        masked_df = pd.DataFrame(masked_rows, columns=col_names)
        return masked_df, masked_cols

    def _unsafe_columns(
        self,
        result: pd.DataFrame,
        projected_names: set[str],
        projected_qualified: set[str],
        allowed_columns: set[str] | None,
        denied_scope_columns: set[str],
        context: ResultValidationContext,
        violations: list[ResultPolicyViolation],
        denied_columns: list[str],
        sensitive_columns: list[str],
        pre_masked_columns: set[str] | None = None,
    ) -> list[str]:
        unsafe: list[str] = []
        masked_set = pre_masked_columns or set()
        sql_columns = set(context.sql_policy_decision.columns_referenced) if context.sql_policy_decision else set()
        sql_tables = set(context.sql_policy_decision.tables_referenced) if context.sql_policy_decision else set()
        sql_base_columns = {_column_base_name(column) for column in sql_columns}
        sql_count_columns = _sql_count_columns(context)
        for column in result.columns:
            raw_name = str(column)
            normalized = _normalize_identifier(raw_name)
            base = _column_base_name(raw_name)
            candidates = {normalized, base}
            candidates.update(value for value in sql_columns if _column_base_name(value) == base)
            for tbl in sql_tables:
                norm_tbl = _normalize_identifier(tbl)
                if norm_tbl:
                    candidates.add(f"{norm_tbl}.{base}")
                    if "." in norm_tbl:
                        candidates.add(f"{norm_tbl.split('.')[-1]}.{base}")

            if denied_scope_columns and candidates & denied_scope_columns:
                unsafe.append(raw_name)
                denied_columns.append(raw_name)
                violations.append(ResultPolicyViolation("column_denied", "A denied column was returned."))
                continue
            if raw_name in masked_set:
                continue
            if _is_sensitive_column_name(raw_name):
                unsafe.append(raw_name)
                denied_columns.append(raw_name)
                sensitive_columns.append(raw_name)
                violations.append(ResultPolicyViolation("sensitive_column", "A sensitive column was returned."))
                if projected_names and base not in projected_names:
                    violations.append(
                        ResultPolicyViolation(
                            "column_not_visible",
                            "A returned column is outside the projected schema.",
                        )
                    )
                continue
            is_sql_count = base in sql_count_columns
            if allowed_columns is not None and not (candidates & allowed_columns):
                if not (_has_aggregate_hint(raw_name) or is_sql_count):
                    unsafe.append(raw_name)
                    denied_columns.append(raw_name)
                    violations.append(
                        ResultPolicyViolation(
                            "column_not_allowed",
                            "A returned column is outside allowed scope.",
                        )
                    )
                    continue
            if projected_names and base not in projected_names:
                if _has_aggregate_hint(raw_name) or is_sql_count or base in sql_base_columns:
                    continue
                unsafe.append(raw_name)
                denied_columns.append(raw_name)
                violations.append(
                    ResultPolicyViolation(
                        "column_not_visible",
                        "A returned column is outside the projected schema.",
                    )
                )
                continue
            if projected_qualified and normalized in projected_qualified:
                continue
        return unsafe

    def _alias_sensitive_violation(
        self,
        context: ResultValidationContext,
        safe: pd.DataFrame,
    ) -> ResultPolicyViolation | None:
        sql_decision = context.sql_policy_decision
        if sql_decision is None:
            return None
        protected_names = set(PII_ALIAS_SOURCE_NAMES) | {
            _column_base_name(col).replace("-", "_")
            for col in (getattr(context.scope, "pii_masking_columns", ()) or ())
            if col
        }
        source_columns = (
            sql_decision.non_aggregate_columns_referenced
            if getattr(sql_decision, "non_aggregate_columns_referenced", None)
            else sql_decision.columns_referenced
        )
        returned_bases = {_column_base_name(str(column)) for column in safe.columns}
        for source in source_columns:
            base = _column_base_name(source).replace("-", "_")
            if base in protected_names and base not in returned_bases:
                return ResultPolicyViolation(
                    "alias_sensitive_column",
                    "Sensitive source column lineage is aliased and requires review.",
                )
        return None

    def _apply_tenant_result_checks(
        self,
        result: pd.DataFrame,
        context: ResultValidationContext,
    ) -> tuple[pd.DataFrame | None, list[str], list[str]]:
        tenant_filters = _tenant_filters(context.scope)
        if not tenant_filters or result.empty:
            return result, [], []
        safe = result.copy()
        redacted_columns: list[str] = []
        warnings: list[str] = []
        for tenant_filter in tenant_filters:
            expected = str(tenant_filter.value)
            matching_columns = [
                column
                for column in safe.columns
                if _column_base_name(str(column)) == _normalize_identifier(tenant_filter.column)
            ]
            for column in matching_columns:
                values = [str(value) for value in safe[column].dropna().tolist()]
                if any(value != expected for value in values):
                    return None, [], []
                safe = safe.drop(columns=[column])
                redacted_columns.append(str(column))
                warnings.append("Tenant scope column was redacted.")
        return safe, redacted_columns, warnings

    def _redact_tenant_values(
        self,
        result: pd.DataFrame,
        context: ResultValidationContext,
    ) -> tuple[pd.DataFrame, int]:
        tenant_values = {
            str(tenant_filter.value)
            for tenant_filter in _tenant_filters(context.scope)
            if tenant_filter.value is not None
        }
        if not tenant_values:
            return result, 0
        redacted = result.copy()
        count = 0
        for column in redacted.columns:
            if not (pd.api.types.is_object_dtype(redacted[column]) or pd.api.types.is_string_dtype(redacted[column])):
                continue
            values: list[Any] = []
            for value in redacted[column].tolist():
                if isinstance(value, str) and value in tenant_values:
                    values.append("[REDACTED]")
                    count += 1
                else:
                    values.append(value)
            redacted[column] = values
        return redacted, count

    def _raw_rows_blocked(
        self,
        result: pd.DataFrame,
        scope: EffectiveAccessScope,
        result_type: ResultType,
    ) -> bool:
        if scope.allow_raw_rows:
            return False
        if result.empty:
            return False
        columns = [_column_base_name(str(column)).replace("-", "_") for column in result.columns]
        identifier_count = sum(1 for column in columns if _is_identifier_column(column))
        pii_column_present = bool(set(columns) & {"email", "name", "phone", "address"})
        if identifier_count >= 2 or pii_column_present:
            return True
        if len(result.index) > 25 and identifier_count >= 1:
            return True
        if result_type not in {"table", "unknown"}:
            return False
        return False

    def _redact_sensitive_values(
        self,
        result: pd.DataFrame,
        context: ResultValidationContext | None = None,
    ) -> tuple[pd.DataFrame, int]:
        redacted = result.copy()
        count = 0
        scrub_raw_pii = (
            context is not None and not bool(getattr(context.scope, "allow_raw_pii", True))
        )
        for column in redacted.columns:
            if not (pd.api.types.is_object_dtype(redacted[column]) or pd.api.types.is_string_dtype(redacted[column])):
                continue
            values: list[Any] = []
            for value in redacted[column].tolist():
                if isinstance(value, str):
                    if SECRET_VALUE_RE.search(value):
                        values.append("[REDACTED]")
                        count += 1
                        continue
                    updated = value
                    changed = False
                    if scrub_raw_pii:
                        if RAW_EMAIL_VALUE_RE.search(updated):
                            updated = RAW_EMAIL_VALUE_RE.sub("[REDACTED_EMAIL]", updated)
                            changed = True
                        if RAW_PHONE_VALUE_RE.search(updated):
                            updated = RAW_PHONE_VALUE_RE.sub("[REDACTED_PHONE]", updated)
                            changed = True
                        updated, card_hits = _scrub_card_numbers(updated)
                        if card_hits:
                            changed = True
                    values.append(updated)
                    if changed:
                        count += 1
                else:
                    values.append(value)
            redacted[column] = values
        return redacted, count

    def _truncate_long_strings(self, result: pd.DataFrame) -> tuple[pd.DataFrame, int]:
        truncated = result.copy()
        count = 0
        for column in truncated.columns:
            if not (pd.api.types.is_object_dtype(truncated[column]) or pd.api.types.is_string_dtype(truncated[column])):
                continue
            values: list[Any] = []
            for value in truncated[column].tolist():
                if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
                    values.append(value[:MAX_STRING_LENGTH] + "...[TRUNCATED]")
                    count += 1
                else:
                    values.append(value)
            truncated[column] = values
        return truncated, count

    def _suppress_small_groups(
        self,
        result: pd.DataFrame,
        scope: EffectiveAccessScope,
        context: ResultValidationContext | None = None,
    ) -> tuple[pd.DataFrame, int]:
        minimum_group_size = getattr(scope, "minimum_group_size", None)
        if minimum_group_size is None:
            return result, 0
        threshold = int(minimum_group_size)
        sql_count_columns = _sql_count_columns(context)
        count_columns = [
            column
            for column in result.columns
            if _is_count_column(str(column)) or _column_base_name(str(column)) in sql_count_columns
        ]
        if not count_columns:
            return result, 0
        mask = pd.Series([True] * len(result.index), index=result.index)
        numeric_series: list[pd.Series] = []
        for column in count_columns:
            numeric = pd.to_numeric(result[column], errors="coerce")
            numeric_series.append(numeric)
            mask = mask & (numeric >= threshold)
        if len(numeric_series) >= 2:
            for idx in range(len(numeric_series)):
                for jdx in range(idx + 1, len(numeric_series)):
                    diff = (numeric_series[idx] - numeric_series[jdx]).abs()
                    mask = mask & ~((diff > 0) & (diff < threshold))
        suppressed = int((~mask).sum())
        return result[mask].reset_index(drop=True), suppressed

    def _serialized_size(self, result: pd.DataFrame) -> int:
        rows = [
            {str(column): _json_safe(row[column]) for column in result.columns}
            for _, row in result.iterrows()
        ]
        return len(json.dumps(rows, sort_keys=True, default=str).encode("utf-8"))

    def _safe_result(
        self,
        result: pd.DataFrame,
        result_type: ResultType,
        *,
        truncated: bool,
        redacted: bool,
        warnings: tuple[str, ...],
    ) -> SafeQueryResult:
        safe_rows: list[dict[str, Any]] = []
        for _, row in result.iterrows():
            safe_rows.append(
                {str(column): _json_safe(row[column]) for column in result.columns}
            )
        return SafeQueryResult(
            columns=tuple(
                ResultColumn(name=str(column), dtype=str(result[column].dtype))
                for column in result.columns
            ),
            rows=tuple(safe_rows),
            row_count=int(len(result.index)),
            column_count=int(len(result.columns)),
            truncated=truncated,
            redacted=redacted,
            warnings=warnings,
            result_type=result_type,
        )

    def _deny(
        self,
        context: ResultValidationContext,
        original: pd.DataFrame,
        decision: ResultDecision,
        reason: str,
        violations: tuple[ResultPolicyViolation, ...],
        *,
        warnings: tuple[str, ...] = (),
        denied_columns: tuple[str, ...] = (),
        redacted_columns: tuple[str, ...] = (),
        sensitive_columns: tuple[str, ...] = (),
        small_group_warnings: tuple[str, ...] = (),
        result_type: ResultType = "unknown",
    ) -> ResultPolicyDecision:
        return ResultPolicyDecision(
            allowed=False,
            decision=decision,
            reason=reason,
            violations=violations,
            warnings=warnings,
            original_row_count=int(len(original.index)),
            returned_row_count=0,
            original_column_count=int(len(original.columns)),
            returned_column_count=0,
            redacted_columns=redacted_columns,
            denied_columns=denied_columns,
            sensitive_columns_detected=sensitive_columns,
            small_group_warnings=small_group_warnings,
            safe_result=None,
            scope_version=context.scope.scope_version,
        )
