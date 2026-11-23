"""Deterministic SQL policy gateway for connector-backed analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import Scope, build_scope

from orion_gate.authz.connectors import EffectiveAccessScope, TenantFilter
from orion_gate.security.schema_projection import (
    ProjectedSchema,
    SENSITIVE_COLUMN_NAMES,
    _is_json_column_type,
)


SQLDialect = Literal["postgres", "mysql", "bigquery"]
SQLStatementType = Literal["select", "with", "set_operation", "unsupported"]

POLICY_VERSION = "phase_1d_v1"
MAX_SQL_LENGTH = 10_000
MAX_JOINS = 8
MAX_CTES = 8
MAX_REFERENCED_TABLES = 12
DEFAULT_MAX_ROWS = 10_000

DENIED_STATEMENT_PREFIXES = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "TRUNCATE",
    "CREATE",
    "GRANT",
    "REVOKE",
    "COPY",
    "CALL",
    "EXEC",
    "EXECUTE",
    "MERGE",
    "REPLACE",
    "SET",
)
SYSTEM_SCHEMAS = {
    "information_schema",
    "pg_catalog",
    "mysql",
    "sys",
    "performance_schema",
}
UNSAFE_FUNCTIONS = {
    "benchmark",
    "current_database",
    "current_schema",
    "current_setting",
    "current_user",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "database",
    "database_to_xml",
    "database_to_xml_and_xmlschema",
    "database_to_xmlschema",
    "dblink",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_exec",
    "dblink_open",
    "dblink_send_query",
    "generate_series",
    "generate_subscripts",
    "get_lock",
    "http_get",
    "http_post",
    "inet_client_addr",
    "inet_server_addr",
    "is_free_lock",
    "is_used_lock",
    "load_file",
    "load_xml",
    "lo_create",
    "lo_export",
    "lo_from_bytea",
    "lo_get",
    "lo_import",
    "lo_open",
    "lo_put",
    "lo_unlink",
    "loread",
    "lowrite",
    "pg_advisory_lock",
    "pg_cancel_backend",
    "pg_create_restore_point",
    "pg_current_logfile",
    "pg_export_snapshot",
    "pg_log_backend_memory_contexts",
    "pg_ls_archive_statusdir",
    "pg_ls_dir",
    "pg_ls_logdir",
    "pg_ls_tmpdir",
    "pg_ls_waldir",
    "pg_read_binary_file",
    "pg_read_file",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_stat_file",
    "pg_switch_wal",
    "pg_terminate_backend",
    "pg_try_advisory_lock",
    "query_to_xml",
    "query_to_xml_and_xmlschema",
    "query_to_xmlschema",
    "regexp_split_to_table",
    "release_lock",
    "schema_to_xml",
    "schema_to_xml_and_xmlschema",
    "schema_to_xmlschema",
    "session_user",
    "set_config",
    "sleep",
    "sys_eval",
    "sys_exec",
    "table_to_xml",
    "table_to_xml_and_xmlschema",
    "table_to_xmlschema",
    "user",
    "version",
    "waitfor",
    "xmlparse",
    "xp_cmdshell",
}
SENSITIVE_ALIAS_SOURCE_COLUMNS = {
    "address",
    "email",
    "full_name",
    "name",
    "phone",
    "ssn",
    "user_email",
} | SENSITIVE_COLUMN_NAMES
OBFUSCATION_FUNCTIONS = {
    "array_agg",
    "array_to_string",
    "ascii",
    "base64",
    "bit_length",
    "btrim",
    "char",
    "chr",
    "concat",
    "concat_ws",
    "convert",
    "convert_from",
    "convert_to",
    "decode",
    "encode",
    "format",
    "from_base64",
    "group_concat",
    "hex",
    "initcap",
    "left",
    "lower",
    "lpad",
    "ltrim",
    "md5",
    "mid",
    "octet_length",
    "overlay",
    "pad",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "regexp_matches",
    "regexp_replace",
    "repeat",
    "replace",
    "reverse",
    "right",
    "rpad",
    "rtrim",
    "sha1",
    "sha2",
    "sha256",
    "sha512",
    "split_part",
    "string_agg",
    "string_to_array",
    "substr",
    "substring",
    "to_ascii",
    "to_base64",
    "to_hex",
    "translate",
    "trim",
    "unhex",
    "unicode",
    "upper",
}
BINARY_CAST_TYPES = {
    "binary",
    "blob",
    "bytea",
    "bytes",
    "json",
    "jsonb",
    "varbinary",
}
JSON_EXTRACT_FUNCTIONS = {
    "json_extract",
    "json_extract_array",
    "json_extract_path",
    "json_extract_path_text",
    "json_extract_scalar",
    "json_query",
    "json_query_array",
    "json_unquote",
    "json_value",
    "json_value_array",
    "jsonb_extract_path",
    "jsonb_extract_path_text",
    "jsonb_path_query",
    "jsonb_path_query_first",
}
JSON_SERIALIZATION_FUNCTIONS = {
    "json_agg",
    "json_build_object",
    "json_object",
    "json_object_agg",
    "jsonb_agg",
    "jsonb_build_object",
    "jsonb_object_agg",
    "row_to_json",
    "to_json",
    "to_json_string",
    "to_jsonb",
}
SENSITIVE_JSON_PATH_TOKENS = {
    "access_token",
    "address",
    "api_key",
    "api_secret",
    "api_token",
    "auth_token",
    "card_cvc",
    "card_last_four",
    "card_number",
    "client_secret",
    "credential",
    "credentials",
    "email",
    "jwt",
    "national_id",
    "password",
    "password_hash",
    "phone",
    "private_key",
    "refresh_token",
    "salt",
    "secret",
    "secret_key",
    "ssn",
    "token",
}
NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:[^()\\]|\\.)*(?:\+|\*|\{\d+,?\d*\})(?:[^()\\]|\\.)*\)(?:\+|\*|\{\d+,?\d*\})"
)


@dataclass(frozen=True)
class SQLPolicyViolation:
    """One deterministic SQL policy violation."""

    code: str
    message: str
    severity: str = "error"


@dataclass(frozen=True)
class SQLValidationContext:
    """Context required to validate a generated SQL statement."""

    dialect: SQLDialect
    scope: EffectiveAccessScope
    projected_schema: ProjectedSchema
    connector_type: str | None = None
    auto_inject_tenant_filters: bool = False


@dataclass(frozen=True)
class SQLPolicyDecision:
    """Result of validating and rewriting a SQL statement."""

    allowed: bool
    decision_id: str
    reason: str
    violations: tuple[SQLPolicyViolation, ...] = field(default_factory=tuple)
    normalized_sql: str | None = None
    safe_sql: str | None = None
    tables_referenced: tuple[str, ...] = field(default_factory=tuple)
    columns_referenced: tuple[str, ...] = field(default_factory=tuple)
    non_aggregate_columns_referenced: tuple[str, ...] = field(default_factory=tuple)
    count_output_columns: tuple[str, ...] = field(default_factory=tuple)
    has_group_by_or_aggregate: bool = False
    json_paths_referenced: tuple[str, ...] = field(default_factory=tuple)
    statement_type: SQLStatementType = "unsupported"
    row_limit_applied: bool = False
    tenant_predicates_injected: bool = False
    injected_predicates_count: int = 0
    max_rows: int = DEFAULT_MAX_ROWS
    timeout_seconds: int = 30
    scope_version: str | None = None
    policy_version: str = POLICY_VERSION

    @property
    def safe_error_message(self) -> str:
        return (
            "ERROR: SQL policy denied this query. Use only visible projected "
            "schema, explicit columns, and read-only SELECT statements."
        )


def _normalize_identifier(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().strip('"`[]').lower()


def _compact_identifier(value: str | None) -> str:
    return _normalize_identifier(value).replace("-", "_")


def _scope_values(values: tuple[str, ...] | None) -> set[str] | None:
    if values is None:
        return None
    return {_normalize_identifier(value) for value in values}


def _table_candidates(table: exp.Table) -> set[str]:
    name = _normalize_identifier(table.name)
    db = _normalize_identifier(table.db)
    catalog = _normalize_identifier(table.catalog)
    candidates = {value for value in (name, db, catalog) if value}
    if db and name:
        candidates.add(f"{db}.{name}")
    if catalog and db and name:
        candidates.add(f"{catalog}.{db}.{name}")
    return candidates


def _is_system_reference(candidates: set[str]) -> bool:
    for value in candidates:
        parts = {_compact_identifier(part) for part in value.split(".") if part}
        if parts & SYSTEM_SCHEMAS:
            return True
        if "information_schema" in parts:
            return True
    return False


def _cte_names(expression: exp.Expression) -> set[str]:
    names: set[str] = set()
    for cte in expression.find_all(exp.CTE):
        alias = _normalize_identifier(cte.alias)
        if alias:
            names.add(alias)
    return names


def _table_aliases(expression: exp.Expression) -> dict[str, set[str]]:
    aliases: dict[str, set[str]] = {}
    ctes = _cte_names(expression)
    for table in expression.find_all(exp.Table):
        if _normalize_identifier(table.name) in ctes and not table.db and not table.catalog:
            continue
        alias = _normalize_identifier(table.alias)
        if alias:
            aliases[alias] = _table_candidates(table)
    return aliases


def _select_aliases(expression: exp.Expression) -> set[str]:
    aliases: set[str] = set()
    for alias in expression.find_all(exp.Alias):
        alias_name = _normalize_identifier(alias.alias)
        if alias_name:
            aliases.add(alias_name)
    return aliases


def _projected_schema_index(
    projected_schema: ProjectedSchema,
) -> tuple[set[str], dict[str, set[str]], set[str], dict[str, str]]:
    table_names: set[str] = set()
    columns_by_table: dict[str, set[str]] = {}
    all_columns: set[str] = set()
    column_types: dict[str, str] = {}

    for item in projected_schema.schema_json.get("objects", []):
        if not isinstance(item, dict):
            continue
        names = {
            _normalize_identifier(str(item.get("name") or "")),
            _normalize_identifier(str(item.get("qualified_name") or "")),
        }
        parent = _normalize_identifier(str(item.get("parent") or ""))
        if parent and item.get("name"):
            names.add(f"{parent}.{_normalize_identifier(str(item['name']))}")
        names = {name for name in names if name}
        table_names.update(names)

        object_columns: set[str] = set()
        for column in item.get("columns", []):
            if not isinstance(column, dict):
                continue
            column_name = _normalize_identifier(str(column.get("name") or ""))
            if not column_name or column_name == "no visible columns":
                continue
            column_type = _normalize_identifier(str(column.get("type") or ""))
            object_columns.add(column_name)
            all_columns.add(column_name)
            if column_type:
                column_types.setdefault(column_name, column_type)
                for name in names:
                    column_types[f"{name}.{column_name}"] = column_type
        for name in names:
            columns_by_table.setdefault(name, set()).update(object_columns)

    return table_names, columns_by_table, all_columns, column_types


def _build_scope_tree(expression: exp.Expression) -> Scope | None:
    try:
        return build_scope(expression)
    except Exception:
        return None


def _scope_select_map(root_scope: Scope | None) -> dict[int, Scope]:
    if root_scope is None:
        return {}
    mapping: dict[int, Scope] = {}
    for scope_node in root_scope.traverse():
        mapping[id(scope_node.expression)] = scope_node
    return mapping


def _scope_direct_tables(
    select: exp.Select,
    scope_node: Scope | None,
    cte_names: set[str],
) -> list[exp.Table]:
    if scope_node is not None:
        seen_ids: set[int] = set()
        tables: list[exp.Table] = []
        for source in scope_node.sources.values():
            if isinstance(source, exp.Table) and source.find_ancestor(exp.Select) is select:
                if id(source) not in seen_ids:
                    seen_ids.add(id(source))
                    tables.append(source)
        return tables
    return [
        table
        for table in select.find_all(exp.Table)
        if table.find_ancestor(exp.Select) is select
        and not (_normalize_identifier(table.name) in cte_names and not table.db and not table.catalog)
    ]


def _table_alias_columns(node: exp.Expression | None) -> list[str]:
    if not isinstance(node, (exp.CTE, exp.Subquery)):
        return []
    alias = node.args.get("alias")
    if not isinstance(alias, exp.TableAlias):
        return []
    columns = alias.args.get("columns") or ()
    return [_normalize_identifier(getattr(col, "name", None) or str(col)) for col in columns]


def _scope_output_columns(scope_node: Scope) -> set[str]:
    expr = scope_node.expression
    explicit_cols = [col for col in _table_alias_columns(expr.parent) if col]
    if explicit_cols:
        return set(explicit_cols)
    if isinstance(expr, exp.Union):
        cols: set[str] = set()
        for child_scope in scope_node.union_scopes:
            cols.update(_scope_output_columns(child_scope))
        return cols
    if not isinstance(expr, exp.Select):
        return set()
    cols: set[str] = set()
    for projection in expr.expressions:
        if isinstance(projection, exp.Alias):
            alias = _normalize_identifier(projection.alias)
            if alias:
                cols.add(alias)
        elif isinstance(projection, exp.Column):
            name = _normalize_identifier(projection.name)
            if name and name != "*":
                cols.add(name)
    return cols


def _resolve_column_source(
    table_name: str,
    scope_node: Scope | None,
) -> tuple[set[str], Scope | None, bool]:
    """Return (table_candidates, source_scope, matched_in_scope)."""

    if not table_name or scope_node is None:
        return set(), None, False
    current: Scope | None = scope_node
    while current is not None:
        if table_name in current.sources:
            source = current.sources[table_name]
            if isinstance(source, exp.Table):
                return _table_candidates(source), None, True
            if isinstance(source, Scope):
                return set(), source, True
        current = current.parent
    return set(), None, False


def _is_counting_expression(node: exp.Expression) -> bool:
    if isinstance(node, (exp.Count, exp.ApproxDistinct)):
        return True
    if isinstance(node, exp.Sum):
        inner = node.this
        if isinstance(inner, exp.Literal) and not inner.is_string:
            return True
        if isinstance(inner, exp.Case):
            outcomes: list[exp.Expression] = []
            for if_node in inner.args.get("ifs") or ():
                if isinstance(if_node, exp.If) and if_node.args.get("true") is not None:
                    outcomes.append(if_node.args["true"])
            if inner.args.get("default") is not None:
                outcomes.append(inner.args["default"])
            if outcomes and all(
                (isinstance(o, exp.Literal) and not o.is_string) or isinstance(o, exp.Null)
                for o in outcomes
            ):
                return True
        if isinstance(inner, exp.If):
            outcomes = [
                expr
                for expr in (inner.args.get("true"), inner.args.get("false"))
                if expr is not None
            ]
            if outcomes and all(
                (isinstance(o, exp.Literal) and not o.is_string) or isinstance(o, exp.Null)
                for o in outcomes
            ):
                return True
    if isinstance(node, (exp.Func, exp.Anonymous)):
        name = _function_name(node) if isinstance(node, exp.Func) else _normalize_identifier(node.name)
        if name in {"count", "count_if", "countif", "approx_count_distinct"}:
            return True
    return False


def _extract_count_and_aggregate_info(expression: exp.Expression) -> tuple[tuple[str, ...], bool]:
    count_cols: set[str] = set()
    has_agg_or_group = bool(expression.find_all(exp.Group))

    for select in expression.find_all(exp.Select):
        if select.args.get("group"):
            has_agg_or_group = True
        for projection in select.expressions:
            target = projection.this if isinstance(projection, exp.Alias) else projection
            if any(_is_counting_expression(node) for node in target.walk()):
                has_agg_or_group = True
                if isinstance(projection, exp.Alias):
                    alias = _normalize_identifier(projection.alias)
                    if alias:
                        count_cols.add(alias)
                elif isinstance(target, (exp.Count, exp.ApproxDistinct)):
                    count_cols.add("count")
                elif isinstance(target, (exp.Func, exp.Anonymous)):
                    fn_name = (
                        _function_name(target)
                        if isinstance(target, exp.Func)
                        else _normalize_identifier(target.name)
                    )
                    if fn_name:
                        count_cols.add(fn_name)
            elif any(isinstance(node, exp.AggFunc) for node in target.walk()):
                has_agg_or_group = True

    return tuple(sorted(count_cols)), has_agg_or_group


def _extract_json_path(node: exp.Expression) -> str | None:
    if isinstance(node, exp.JSONPath):
        parts: list[str] = []
        for expr in node.expressions:
            if isinstance(expr, exp.JSONPathRoot):
                continue
            if isinstance(expr, exp.JSONPathKey):
                key = _normalize_identifier(str(expr.this))
                if key:
                    parts.append(key)
            elif isinstance(expr, exp.JSONPathSubscript):
                parts.append(f"[{expr.this}]")
            else:
                return None
        return ".".join(parts) if parts else None
    if isinstance(node, exp.Literal) and node.is_string:
        raw = str(node.this).strip()
        if raw.startswith("{") and raw.endswith("}"):
            parts = [
                _normalize_identifier(part)
                for part in raw[1:-1].split(",")
                if _normalize_identifier(part)
            ]
            return ".".join(parts) if parts else None
        if raw.startswith("$."):
            raw = raw[2:]
        elif raw == "$":
            return ""
        normalized = _normalize_identifier(raw).lstrip("$.")
        return normalized or None
    return None


def _numeric_literal(node: exp.Expression) -> float | None:
    if isinstance(node, exp.Literal) and not node.is_string:
        try:
            return float(node.this)
        except (TypeError, ValueError):
            return None
    return None


def _is_tautology_condition(condition: exp.Expression) -> bool:
    unwrapped = condition
    while isinstance(unwrapped, exp.Paren):
        unwrapped = unwrapped.this
    if isinstance(unwrapped, exp.Boolean):
        return bool(unwrapped.this)
    if isinstance(unwrapped, exp.Not):
        inner = unwrapped.this
        while isinstance(inner, exp.Paren):
            inner = inner.this
        if isinstance(inner, exp.Boolean):
            return not bool(inner.this)
        return False
    if isinstance(unwrapped, exp.Or):
        return _is_tautology_condition(unwrapped.left) or _is_tautology_condition(unwrapped.right)
    if isinstance(unwrapped, exp.And):
        return _is_tautology_condition(unwrapped.left) and _is_tautology_condition(unwrapped.right)
    if isinstance(unwrapped, (exp.EQ, exp.NEQ, exp.LT, exp.LTE, exp.GT, exp.GTE)):
        left = unwrapped.left
        right = unwrapped.right
        if isinstance(unwrapped, exp.EQ) and isinstance(left, exp.Column) and isinstance(right, exp.Column):
            if (
                _normalize_identifier(left.table) == _normalize_identifier(right.table)
                and _normalize_identifier(left.name) == _normalize_identifier(right.name)
            ):
                return True
        if isinstance(left, exp.Literal) and isinstance(right, exp.Literal):
            lnum = _numeric_literal(left)
            rnum = _numeric_literal(right)
            if lnum is not None and rnum is not None:
                if isinstance(unwrapped, exp.EQ):
                    return lnum == rnum
                if isinstance(unwrapped, exp.NEQ):
                    return lnum != rnum
                if isinstance(unwrapped, exp.LT):
                    return lnum < rnum
                if isinstance(unwrapped, exp.LTE):
                    return lnum <= rnum
                if isinstance(unwrapped, exp.GT):
                    return lnum > rnum
                if isinstance(unwrapped, exp.GTE):
                    return lnum >= rnum
            lstr = str(left.this)
            rstr = str(right.this)
            if isinstance(unwrapped, exp.EQ):
                return lstr == rstr
            if isinstance(unwrapped, exp.NEQ):
                return lstr != rstr
            if isinstance(unwrapped, exp.LT):
                return lstr < rstr
            if isinstance(unwrapped, exp.LTE):
                return lstr <= rstr
            if isinstance(unwrapped, exp.GT):
                return lstr > rstr
            if isinstance(unwrapped, exp.GTE):
                return lstr >= rstr
    return False


def _function_name(function: exp.Func) -> str:
    if isinstance(function, exp.Anonymous):
        return _normalize_identifier(function.name)
    sql_name = function.sql_name()
    if sql_name:
        return _normalize_identifier(sql_name)
    return _normalize_identifier(getattr(function, "name", ""))


def _extract_limit_value(expression: exp.Expression) -> int | None:
    limit = expression.args.get("limit")
    if not isinstance(limit, exp.Limit):
        return None
    limit_expression = limit.args.get("expression")
    if isinstance(limit_expression, exp.Literal) and not limit_expression.is_string:
        try:
            return int(limit_expression.this)
        except (TypeError, ValueError):
            return None
    return None


def _set_limit(expression: exp.Expression, max_rows: int) -> exp.Expression:
    limited = expression.copy()
    limited.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
    return limited


def _wrap_with_limit(sql: str, max_rows: int, dialect: SQLDialect) -> str:
    alias = "orion_policy_query"
    if dialect == "mysql":
        return f"SELECT * FROM ({sql.rstrip().rstrip(';')}) AS {alias} LIMIT {max_rows}"
    return f"SELECT * FROM ({sql.rstrip().rstrip(';')}) AS {alias} LIMIT {max_rows}"


def _decision_id(sql: str, context: SQLValidationContext, allowed: bool) -> str:
    payload = "|".join(
        (
            POLICY_VERSION,
            context.dialect,
            context.scope.scope_version,
            context.projected_schema.projection_hash,
            "allowed" if allowed else "denied",
            sql,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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


def _tenant_filter_matches_table(tenant_filter: TenantFilter, candidates: set[str]) -> bool:
    table = _normalize_identifier(tenant_filter.table)
    if not table:
        return False
    for candidate in candidates:
        if candidate == table or candidate.endswith(f".{table}") or table.endswith(f".{candidate}"):
            return True
    return False


def _tenant_table_tokens(table: exp.Table) -> set[str]:
    alias = _normalize_identifier(table.alias)
    if alias:
        return {alias}
    tokens = set(_table_candidates(table))
    name = _normalize_identifier(table.name)
    if name:
        tokens.add(name)
    return {token for token in tokens if token}


def _literal_value(expression: exp.Expression) -> str | None:
    if isinstance(expression, exp.Literal):
        return str(expression.this)
    return None


def _tenant_comparison_parts(
    comparison: exp.Expression,
) -> tuple[exp.Column | None, str | None] | None:
    if not isinstance(comparison, (exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE)):
        return None
    left = comparison.left
    right = comparison.right
    if isinstance(left, exp.Column):
        return left, _literal_value(right)
    if isinstance(right, exp.Column):
        return right, _literal_value(left)
    return None


def _tenant_column_matches(
    column: exp.Column,
    table: exp.Table,
    direct_tables: list[exp.Table],
    tenant_filter: TenantFilter,
) -> bool:
    if _normalize_identifier(column.name) != _normalize_identifier(tenant_filter.column):
        return False
    column_table = _normalize_identifier(column.table)
    if not column_table:
        return len(direct_tables) == 1
    return column_table in _tenant_table_tokens(table)


def _top_level_conjuncts(expression: exp.Expression) -> list[exp.Expression]:
    """Return top-level AND conjuncts without descending into OR or NOT."""

    if isinstance(expression, exp.Where):
        return _top_level_conjuncts(expression.this)
    if isinstance(expression, exp.Paren):
        return _top_level_conjuncts(expression.this)
    if isinstance(expression, exp.And):
        return _top_level_conjuncts(expression.left) + _top_level_conjuncts(expression.right)
    return [expression]


def _left_join_for_table(table: exp.Table, select: exp.Select) -> exp.Join | None:
    join = table.find_ancestor(exp.Join)
    if (
        join is not None
        and join.find_ancestor(exp.Select) is select
        and join.this is table
        and _normalize_identifier(join.side) == "left"
        and join.args.get("on") is not None
    ):
        return join
    return None


def _clause_references_tenant_column(
    clause: exp.Expression | None,
    select: exp.Select,
    table: exp.Table,
    direct_tables: list[exp.Table],
    tenant_filter: TenantFilter,
) -> bool:
    if clause is None:
        return False
    body = clause.this if isinstance(clause, exp.Where) else clause
    for col in body.find_all(exp.Column):
        if col.find_ancestor(exp.Select) is not select:
            continue
        if _tenant_column_matches(col, table, direct_tables, tenant_filter):
            return True
    return False


def _tenant_predicate_status(
    clause: exp.Expression,
    select: exp.Select,
    table: exp.Table,
    direct_tables: list[exp.Table],
    tenant_filter: TenantFilter,
) -> str:
    body = clause.this if isinstance(clause, exp.Where) else clause
    saw_tenant_column = False
    for col in body.find_all(exp.Column):
        if col.find_ancestor(exp.Select) is not select:
            continue
        if not _tenant_column_matches(col, table, direct_tables, tenant_filter):
            continue
        saw_tenant_column = True

        or_ancestor = col.find_ancestor(exp.Or)
        if or_ancestor is not None and or_ancestor.find_ancestor(exp.Select) is select:
            return "or_denied"

        not_ancestor = col.find_ancestor(exp.Not)
        if not_ancestor is not None and not_ancestor.find_ancestor(exp.Select) is select:
            return "invalid_operator"

        parent = col.parent
        if not isinstance(parent, exp.EQ):
            return "invalid_operator"
        parts = _tenant_comparison_parts(parent)
        if parts is None or parts[1] is None:
            return "wrong_value"
        if parts[1] != str(tenant_filter.value):
            return "wrong_value"

    top_conjuncts = _top_level_conjuncts(body)
    for conjunct in top_conjuncts:
        if not isinstance(conjunct, exp.EQ):
            continue
        if conjunct.find_ancestor(exp.Select) is not select:
            continue
        parts = _tenant_comparison_parts(conjunct)
        if parts is None or parts[0] is None or parts[1] is None:
            continue
        if _tenant_column_matches(parts[0], table, direct_tables, tenant_filter) and parts[1] == str(
            tenant_filter.value
        ):
            return "ok"

    if any(isinstance(conjunct, exp.Or) for conjunct in top_conjuncts):
        return "or_denied"
    return "wrong_value" if saw_tenant_column else "missing"


class SQLPolicyGateway:
    """Validate and rewrite generated SQL before connector execution."""

    def inject_tenant_predicates(
        self,
        sql: str,
        scope: EffectiveAccessScope,
        *,
        dialect: SQLDialect = "postgres",
    ) -> tuple[str, int]:
        """Deterministically inject required tenant predicates into SQL ASTs.

        Existing unauthorized tenant values, non-equality operators, or OR-weakened
        tenant predicates are intentionally left untouched so validation denies them.
        """

        parsed = sqlglot.parse(sql.strip(), read=dialect)
        if len(parsed) != 1 or parsed[0] is None:
            return sql, 0
        rewritten, injected_count = self._inject_tenant_predicates_ast(parsed[0], scope)
        return rewritten.sql(dialect=dialect), injected_count

    def _inject_tenant_predicates_ast(
        self,
        expression: exp.Expression,
        scope: EffectiveAccessScope,
    ) -> tuple[exp.Expression, int]:
        tenant_filters = _tenant_filters(scope)
        if not tenant_filters:
            return expression, 0

        rewritten = expression.copy()
        cte_names = _cte_names(rewritten)
        scope_map = _scope_select_map(_build_scope_tree(rewritten))
        injected_count = 0

        for select in rewritten.find_all(exp.Select):
            scope_node = scope_map.get(id(select))
            direct_tables = _scope_direct_tables(select, scope_node, cte_names)
            if not direct_tables:
                continue

            for table in direct_tables:
                candidates = _table_candidates(table)
                matching_filters = [
                    tenant_filter
                    for tenant_filter in tenant_filters
                    if _tenant_filter_matches_table(tenant_filter, candidates)
                ]
                if not matching_filters:
                    continue

                left_join = _left_join_for_table(table, select)
                qualifier = table.alias or table.name

                for tenant_filter in matching_filters:
                    if tenant_filter.value is None:
                        continue
                    where_clause = select.args.get("where")
                    if _clause_references_tenant_column(
                        where_clause, select, table, direct_tables, tenant_filter
                    ):
                        continue
                    if left_join is not None and _clause_references_tenant_column(
                        left_join.args.get("on"), select, table, direct_tables, tenant_filter
                    ):
                        continue

                    predicate = exp.EQ(
                        this=exp.column(tenant_filter.column, table=qualifier),
                        expression=exp.Literal.string(str(tenant_filter.value)),
                    )
                    if left_join is not None:
                        existing_on = left_join.args["on"]
                        wrapped_on = (
                            existing_on
                            if isinstance(existing_on, exp.Paren)
                            else exp.Paren(this=existing_on.copy())
                        )
                        left_join.set("on", exp.And(this=wrapped_on, expression=predicate))
                    elif where_clause is None:
                        select.set("where", exp.Where(this=predicate))
                    else:
                        existing_where = where_clause.this
                        wrapped_where = (
                            existing_where
                            if isinstance(existing_where, exp.Paren)
                            else exp.Paren(this=existing_where.copy())
                        )
                        select.set("where", exp.Where(this=exp.And(this=wrapped_where, expression=predicate)))
                    injected_count += 1

        return rewritten, injected_count

    def validate(self, sql: str, context: SQLValidationContext) -> SQLPolicyDecision:
        """Return a deterministic policy decision for candidate SQL."""

        candidate = sql.strip()
        max_rows = max(1, int(context.scope.max_result_rows or DEFAULT_MAX_ROWS))
        timeout_seconds = max(1, int(context.scope.max_execution_seconds or 30))
        base_kwargs: dict[str, Any] = {
            "max_rows": max_rows,
            "timeout_seconds": timeout_seconds,
            "scope_version": context.scope.scope_version,
        }

        early_violations = self._early_violations(candidate)
        if early_violations:
            return self._deny(candidate, context, early_violations, **base_kwargs)

        try:
            parsed = sqlglot.parse(candidate, read=context.dialect)
        except sqlglot.errors.SqlglotError:
            return self._deny(
                candidate,
                context,
                (SQLPolicyViolation("unparseable_sql", "SQL could not be parsed."),),
                **base_kwargs,
            )

        if len(parsed) != 1:
            return self._deny(
                candidate,
                context,
                (SQLPolicyViolation("multiple_statements", "Only one SQL statement is allowed."),),
                **base_kwargs,
            )

        expression = parsed[0]
        normalized_sql = expression.sql(dialect=context.dialect)
        statement_type = self._statement_type(expression)
        if statement_type == "unsupported":
            return self._deny(
                normalized_sql,
                context,
                (SQLPolicyViolation("non_read_only_statement", "Only read-only SELECT statements are allowed."),),
                normalized_sql=normalized_sql,
                **base_kwargs,
            )

        violations: list[SQLPolicyViolation] = []
        cte_names = _cte_names(expression)
        root_scope = _build_scope_tree(expression)
        scope_map = _scope_select_map(root_scope)
        table_aliases = _table_aliases(expression)
        select_aliases = _select_aliases(expression)
        (
            projected_tables,
            columns_by_table,
            all_columns,
            column_types,
        ) = _projected_schema_index(context.projected_schema)
        allowed_tables = _scope_values(context.scope.allowed_tables)
        denied_tables = _scope_values(context.scope.denied_tables) or set()
        allowed_columns = _scope_values(context.scope.allowed_columns)
        denied_columns = _scope_values(context.scope.denied_columns) or set()
        protected_columns = (
            set(SENSITIVE_ALIAS_SOURCE_COLUMNS)
            | {_normalize_identifier(col) for col in getattr(context.scope, "pii_masking_columns", ()) if col}
            | denied_columns
        )

        table_refs = self._validate_tables(
            expression,
            projected_tables,
            allowed_tables,
            denied_tables,
            cte_names,
            scope_map,
            violations,
        )
        column_refs, non_agg_column_refs = self._validate_columns(
            expression,
            columns_by_table,
            all_columns,
            allowed_columns,
            denied_columns,
            table_aliases,
            cte_names,
            select_aliases,
            root_scope,
            scope_map,
            violations,
        )
        self._validate_star_projection(expression, violations)
        self._validate_functions(expression, protected_columns, violations)
        json_paths = self._validate_json_access(
            expression,
            context,
            column_types,
            scope_map,
            table_aliases,
            violations,
        )
        self._validate_sensitive_transforms(
            expression,
            protected_columns,
            scope_map,
            table_aliases,
            violations,
        )
        self._validate_sensitive_aliases(
            expression,
            protected_columns,
            scope_map,
            table_aliases,
            violations,
        )

        injected_count = 0
        if context.auto_inject_tenant_filters and not violations:
            expression, injected_count = self._inject_tenant_predicates_ast(expression, context.scope)
            cte_names = _cte_names(expression)
            root_scope = _build_scope_tree(expression)
            scope_map = _scope_select_map(root_scope)

        self._validate_tenant_filters(expression, context.scope, cte_names, scope_map, violations)
        self._validate_complexity(
            candidate,
            expression,
            table_refs,
            allow_cross_joins=bool(getattr(context.scope, "allow_cross_joins", False)),
            violations=violations,
        )
        count_output_columns, has_group_or_agg = _extract_count_and_aggregate_info(expression)

        if violations:
            return self._deny(
                normalized_sql,
                context,
                tuple(violations),
                normalized_sql=normalized_sql,
                tables_referenced=tuple(sorted(table_refs)),
                columns_referenced=tuple(sorted(column_refs)),
                non_aggregate_columns_referenced=tuple(sorted(non_agg_column_refs)),
                count_output_columns=count_output_columns,
                has_group_by_or_aggregate=has_group_or_agg,
                json_paths_referenced=json_paths,
                statement_type=statement_type,
                **base_kwargs,
            )

        rewritten_sql = expression.sql(dialect=context.dialect)
        safe_sql, row_limit_applied = self._safe_limited_sql(
            expression,
            rewritten_sql,
            max_rows,
            context.dialect,
        )
        return SQLPolicyDecision(
            allowed=True,
            decision_id=_decision_id(safe_sql, context, True),
            reason=(
                "SQL policy injected tenant isolation predicates and allowed query."
                if injected_count > 0
                else "SQL policy allowed query."
            ),
            normalized_sql=normalized_sql,
            safe_sql=safe_sql,
            tables_referenced=tuple(sorted(table_refs)),
            columns_referenced=tuple(sorted(column_refs)),
            non_aggregate_columns_referenced=tuple(sorted(non_agg_column_refs)),
            count_output_columns=count_output_columns,
            has_group_by_or_aggregate=has_group_or_agg,
            json_paths_referenced=json_paths,
            statement_type=statement_type,
            row_limit_applied=row_limit_applied,
            tenant_predicates_injected=injected_count > 0,
            injected_predicates_count=injected_count,
            **base_kwargs,
        )

    def _early_violations(self, sql: str) -> tuple[SQLPolicyViolation, ...]:
        violations: list[SQLPolicyViolation] = []
        if not sql:
            violations.append(SQLPolicyViolation("empty_sql", "SQL is required."))
            return tuple(violations)
        if len(sql) > MAX_SQL_LENGTH:
            violations.append(SQLPolicyViolation("sql_too_long", "SQL exceeds policy length limit."))

        first_token = re.match(r"^\s*(\w+)", sql)
        if first_token and first_token.group(1).upper() in DENIED_STATEMENT_PREFIXES:
            violations.append(
                SQLPolicyViolation(
                    "non_read_only_statement",
                    "Only read-only SELECT statements are allowed.",
                )
            )
        if re.search(r"\b(INTO\s+OUTFILE|INTO\s+DUMPFILE)\b", sql, flags=re.IGNORECASE):
            violations.append(SQLPolicyViolation("unsafe_output_clause", "Unsafe output clauses are not allowed."))
        unsafe_prefixes = "|".join(re.escape(prefix) for prefix in DENIED_STATEMENT_PREFIXES)
        for comment in re.findall(r"(--[^\n]*|/\*.*?\*/)", sql, flags=re.DOTALL):
            if re.search(rf"\b({unsafe_prefixes})\b", comment, flags=re.IGNORECASE):
                violations.append(
                    SQLPolicyViolation(
                        "unsafe_comment",
                        "SQL comments cannot contain unsafe statements.",
                    )
                )
                break
        return tuple(violations)

    def _statement_type(self, expression: exp.Expression) -> SQLStatementType:
        disallowed_nested = (
            exp.Insert,
            exp.Update,
            exp.Delete,
            exp.Drop,
            exp.Create,
            exp.Alter,
            exp.Merge,
            exp.Command,
            exp.Into,
        )
        if any(expression.find_all(*disallowed_nested)):
            return "unsupported"
        if isinstance(expression, exp.Select):
            return "with" if expression.args.get("with_") else "select"
        if isinstance(expression, (exp.Union, exp.Except, exp.Intersect)):
            return "set_operation"
        return "unsupported"

    def _validate_tables(
        self,
        expression: exp.Expression,
        projected_tables: set[str],
        allowed_tables: set[str] | None,
        denied_tables: set[str],
        cte_names: set[str],
        scope_map: dict[int, Scope],
        violations: list[SQLPolicyViolation],
    ) -> set[str]:
        referenced: set[str] = set()
        for table in expression.find_all(exp.Table):
            if isinstance(table.this, exp.Expression) and not isinstance(table.this, exp.Identifier):
                violations.append(
                    SQLPolicyViolation("unsafe_function", "Table-valued functions are not allowed.")
                )
                continue

            name = _normalize_identifier(table.name)
            select = table.find_ancestor(exp.Select)
            scope_node = scope_map.get(id(select)) if select is not None else None
            if scope_node is not None and not table.db and not table.catalog:
                alias_or_name = _normalize_identifier(table.alias) or name
                source_entry = scope_node.sources.get(alias_or_name) or scope_node.sources.get(name)
                if isinstance(source_entry, Scope):
                    continue
                if source_entry is None and name in cte_names:
                    # Only skip when there is no physical table reference in scope.
                    continue
            elif name in cte_names and not table.db and not table.catalog:
                continue

            candidates = _table_candidates(table)
            primary = max(candidates, key=len) if candidates else name
            if primary:
                referenced.add(primary)

            if _is_system_reference(candidates):
                violations.append(
                    SQLPolicyViolation(
                        "metadata_table_denied",
                        "System metadata schemas are not queryable.",
                    )
                )
                continue
            if denied_tables and candidates & denied_tables:
                violations.append(SQLPolicyViolation("table_denied", "Referenced table is denied."))
                continue
            if allowed_tables is not None and not (candidates & allowed_tables):
                violations.append(
                    SQLPolicyViolation("table_not_allowed", "Referenced table is outside allowed scope.")
                )
                continue
            if projected_tables and not (candidates & projected_tables):
                violations.append(
                    SQLPolicyViolation(
                        "table_not_visible",
                        "Referenced table is not present in the projected schema.",
                    )
                )
        return referenced

    def _column_candidates_for_node(
        self,
        column: exp.Column,
        scope_map: dict[int, Scope],
        table_aliases: dict[str, set[str]],
    ) -> tuple[str, set[str], set[str], Scope | None]:
        column_name = _normalize_identifier(column.name)
        table_name = _normalize_identifier(column.table)
        select = column.find_ancestor(exp.Select)
        scope_node = scope_map.get(id(select)) if select is not None else None

        table_candidates, source_scope, matched_in_scope = _resolve_column_source(table_name, scope_node)
        if not matched_in_scope and table_name:
            table_candidates = table_aliases.get(table_name, {table_name})
        elif not table_name and scope_node is not None:
            for src in scope_node.sources.values():
                if isinstance(src, exp.Table):
                    table_candidates.update(_table_candidates(src))

        candidates = {column_name}
        for tc in table_candidates:
            if tc:
                candidates.add(f"{tc}.{column_name}")
        return column_name, candidates, table_candidates, source_scope

    def _validate_columns(
        self,
        expression: exp.Expression,
        columns_by_table: dict[str, set[str]],
        all_columns: set[str],
        allowed_columns: set[str] | None,
        denied_columns: set[str],
        table_aliases: dict[str, set[str]],
        cte_names: set[str],
        select_aliases: set[str],
        root_scope: Scope | None,
        scope_map: dict[int, Scope],
        violations: list[SQLPolicyViolation],
    ) -> tuple[set[str], set[str]]:
        referenced: set[str] = set()
        non_agg_referenced: set[str] = set()

        for column in expression.find_all(exp.Column):
            column_name = _normalize_identifier(column.name)
            if not column_name or column_name == "*":
                continue
            table_name = _normalize_identifier(column.table)

            select = column.find_ancestor(exp.Select)
            scope_node = scope_map.get(id(select)) if select is not None else root_scope
            local_aliases: set[str] = set()
            if select is not None:
                for proj in select.expressions:
                    if isinstance(proj, exp.Alias) and proj.alias:
                        local_aliases.add(_normalize_identifier(proj.alias))
            elif root_scope is not None:
                local_aliases = select_aliases

            if not table_name and column_name in local_aliases:
                # Only treat as a select-list alias when referenced outside the projection definition itself
                in_clause = column.find_ancestor(exp.Order, exp.Group, exp.Having)
                if in_clause is not None or column_name not in all_columns:
                    continue

            ref_token = f"{table_name}.{column_name}" if table_name else column_name
            referenced.add(ref_token)
            inside_count_agg = False
            agg_ancestor = column.find_ancestor(exp.AggFunc)
            if agg_ancestor is not None and _is_counting_expression(agg_ancestor):
                inside_count_agg = True
            if not inside_count_agg:
                non_agg_referenced.add(ref_token)

            candidates = {column_name}
            table_candidates, source_scope, matched_in_scope = _resolve_column_source(
                table_name, scope_node
            )
            if not matched_in_scope:
                if table_name and table_name in cte_names and scope_node is None:
                    table_candidates = set()
                elif table_name:
                    table_candidates = table_aliases.get(table_name, {table_name})

            inferred_tables: set[str] = set()
            from_derived_scope = source_scope is not None
            if not table_name and scope_node is not None:
                for src in scope_node.sources.values():
                    if isinstance(src, exp.Table):
                        tcs = _table_candidates(src)
                        if not columns_by_table or any(
                            column_name in columns_by_table.get(tc, set()) for tc in tcs
                        ):
                            inferred_tables.update(tcs)
                    elif isinstance(src, Scope):
                        if column_name in _scope_output_columns(src):
                            from_derived_scope = True

            for table_candidate in (table_candidates or inferred_tables):
                if table_candidate:
                    candidates.add(f"{table_candidate}.{column_name}")

            if denied_columns and candidates & denied_columns:
                violations.append(SQLPolicyViolation("column_denied", "Referenced column is denied."))
                continue
            if (
                allowed_columns is not None
                and not from_derived_scope
                and not (candidates & allowed_columns)
            ):
                violations.append(
                    SQLPolicyViolation("column_not_allowed", "Referenced column is outside allowed scope.")
                )
                continue

            if source_scope is not None:
                cte_cols = _scope_output_columns(source_scope)
                if cte_cols and column_name not in cte_cols:
                    violations.append(
                        SQLPolicyViolation(
                            "column_not_visible",
                            "Referenced column is not present in the projected schema.",
                        )
                    )
                continue

            if table_candidates:
                known = any(
                    column_name in columns_by_table.get(table_candidate, set())
                    for table_candidate in table_candidates
                )
                if columns_by_table and not known:
                    violations.append(
                        SQLPolicyViolation(
                            "column_not_visible",
                            "Referenced column is not present in the projected schema.",
                        )
                    )
                continue

            if not table_name and scope_node is not None and scope_node.sources:
                scoped_table_cols: set[str] = set()
                has_physical_table = False
                has_scope_source = False
                for src in scope_node.sources.values():
                    if isinstance(src, exp.Table):
                        has_physical_table = True
                        for tc in _table_candidates(src):
                            scoped_table_cols.update(columns_by_table.get(tc, set()))
                    elif isinstance(src, Scope):
                        has_scope_source = True
                        scoped_table_cols.update(_scope_output_columns(src))
                # For correlated subqueries, also check parent scopes' tables
                parent_scope = scope_node.parent
                while parent_scope is not None:
                    for src in parent_scope.sources.values():
                        if isinstance(src, exp.Table):
                            for tc in _table_candidates(src):
                                scoped_table_cols.update(columns_by_table.get(tc, set()))
                        elif isinstance(src, Scope):
                            scoped_table_cols.update(_scope_output_columns(src))
                    parent_scope = parent_scope.parent

                if (has_physical_table or has_scope_source) and columns_by_table:
                    if column_name not in scoped_table_cols:
                        violations.append(
                            SQLPolicyViolation(
                                "column_not_visible",
                                "Referenced column is not present in the projected schema.",
                            )
                        )
                    continue

            if all_columns and column_name not in all_columns:
                violations.append(
                    SQLPolicyViolation(
                        "column_not_visible",
                        "Referenced column is not present in the projected schema.",
                    )
                )
        return referenced, non_agg_referenced

    def _validate_star_projection(
        self,
        expression: exp.Expression,
        violations: list[SQLPolicyViolation],
    ) -> None:
        for select in expression.find_all(exp.Select):
            for projection in select.expressions:
                if isinstance(projection, exp.Star):
                    violations.append(SQLPolicyViolation("select_star_denied", "SELECT * is not allowed."))
                    return
                if isinstance(projection, exp.Column) and any(projection.find_all(exp.Star)):
                    violations.append(SQLPolicyViolation("select_star_denied", "SELECT * is not allowed."))
                    return
                if isinstance(projection, exp.Alias) and isinstance(projection.this, exp.Column):
                    if any(projection.this.find_all(exp.Star)):
                        violations.append(SQLPolicyViolation("select_star_denied", "SELECT * is not allowed."))
                        return

    def _validate_functions(
        self,
        expression: exp.Expression,
        protected_columns: set[str],
        violations: list[SQLPolicyViolation],
    ) -> None:
        if any(expression.find_all(exp.ExplodingGenerateSeries)):
            violations.append(
                SQLPolicyViolation("unsafe_function", "Unsafe SQL functions are not allowed.")
            )
        for function in expression.find_all(exp.Func):
            if _function_name(function) in UNSAFE_FUNCTIONS:
                violations.append(
                    SQLPolicyViolation("unsafe_function", "Unsafe SQL functions are not allowed.")
                )
        for function in expression.find_all(exp.Anonymous):
            if _normalize_identifier(function.name) in UNSAFE_FUNCTIONS:
                violations.append(
                    SQLPolicyViolation("unsafe_function", "Unsafe SQL functions are not allowed.")
                )
        regex_nodes = (
            exp.RegexpLike,
            exp.RegexpILike,
            exp.RegexpReplace,
            exp.RegexpExtract,
            exp.RegexpSplit,
        )
        for node in expression.find_all(*regex_nodes):
            pattern_expr = node.args.get("expression")
            if not isinstance(pattern_expr, exp.Literal) or not pattern_expr.is_string:
                violations.append(
                    SQLPolicyViolation("unsafe_regex_denied", "Dynamic regex patterns are not allowed.")
                )
                continue
            pattern_text = str(pattern_expr.this or "")
            if len(pattern_text) > 200 or NESTED_QUANTIFIER_RE.search(pattern_text):
                violations.append(
                    SQLPolicyViolation(
                        "unsafe_regex_denied",
                        "Complex or backtracking regex patterns are not allowed.",
                    )
                )
                continue
            target_expr = node.this
            if target_expr is not None:
                for col in target_expr.find_all(exp.Column):
                    if _normalize_identifier(col.name) in protected_columns:
                        violations.append(
                            SQLPolicyViolation(
                                "unsafe_regex_denied",
                                "Regex matching is not allowed on sensitive or masked columns.",
                            )
                        )
                        break

    def _validate_json_access(
        self,
        expression: exp.Expression,
        context: SQLValidationContext,
        column_types: dict[str, str],
        scope_map: dict[int, Scope],
        table_aliases: dict[str, set[str]],
        violations: list[SQLPolicyViolation],
    ) -> tuple[str, ...]:
        allow_json_columns = bool(getattr(context.scope, "allow_json_columns", False))
        allowed_json_paths = {
            _normalize_identifier(path).lstrip("$.")
            for path in (getattr(context.scope, "allowed_json_paths", ()) or ())
            if _normalize_identifier(path).lstrip("$.")
        }
        authorized_column_ids: set[int] = set()
        extracted_paths: set[str] = set()

        for fn in expression.find_all(exp.Func, exp.Anonymous):
            fn_name = (
                _function_name(fn)
                if isinstance(fn, exp.Func)
                else _normalize_identifier(fn.name)
            )
            if fn_name in JSON_SERIALIZATION_FUNCTIONS and not allow_json_columns:
                violations.append(
                    SQLPolicyViolation(
                        "json_serialization_denied",
                        "JSON row/object serialization functions are not allowed.",
                    )
                )

        json_extract_types = (
            exp.JSONExtract,
            exp.JSONExtractScalar,
            exp.JSONBExtract,
            exp.JSONBExtractScalar,
            exp.JSONExtractArray,
            exp.JSONValue,
        )
        json_nodes: list[exp.Expression] = list(expression.find_all(*json_extract_types))
        for fn in expression.find_all(exp.Func, exp.Anonymous):
            fn_name = (
                _function_name(fn)
                if isinstance(fn, exp.Func)
                else _normalize_identifier(fn.name)
            )
            if fn_name in JSON_EXTRACT_FUNCTIONS and fn not in json_nodes:
                json_nodes.append(fn)

        for node in json_nodes:
            if isinstance(node, exp.Anonymous):
                target_arg = node.expressions[0] if node.expressions else None
            else:
                target_arg = node.this
            if not isinstance(target_arg, exp.Expression):
                continue
            target_cols = list(target_arg.find_all(exp.Column))
            if not target_cols:
                continue

            # Extract dotted JSON path
            path_str: str | None = None
            path_expr = node.args.get("expression")
            if path_expr is not None:
                path_str = _extract_json_path(path_expr)
            elif isinstance(node, exp.Anonymous) and len(node.expressions) >= 2:
                if len(node.expressions) == 2:
                    path_str = _extract_json_path(node.expressions[1])
                else:
                    parts = []
                    for arg in node.expressions[1:]:
                        part = _extract_json_path(arg)
                        if part is None:
                            parts = []
                            break
                        parts.append(part)
                    path_str = ".".join(parts) if parts else None

            if not path_str:
                if not allow_json_columns:
                    violations.append(
                        SQLPolicyViolation(
                            "json_path_denied",
                            "Dynamic or unresolvable JSON path extraction is not allowed.",
                        )
                    )
                continue

            for col in target_cols:
                col_name, _, table_candidates, _ = self._column_candidates_for_node(
                    col, scope_map, table_aliases
                )
                candidate_paths = {f"{col_name}.{path_str}"}
                for tc in table_candidates:
                    if tc:
                        candidate_paths.add(f"{tc}.{col_name}.{path_str}")
                extracted_paths.update(candidate_paths)

                if candidate_paths & allowed_json_paths:
                    authorized_column_ids.add(id(col))
                    continue

                if not allow_json_columns:
                    violations.append(
                        SQLPolicyViolation(
                            "json_path_not_allowed",
                            "JSON path extraction requires explicit path allowlisting.",
                        )
                    )
                    continue

                path_tokens = {
                    _compact_identifier(seg)
                    for seg in re.split(r"[.\[\]]+", path_str)
                    if seg
                }
                if path_tokens & SENSITIVE_JSON_PATH_TOKENS:
                    violations.append(
                        SQLPolicyViolation(
                            "json_sensitive_path_denied",
                            "Sensitive JSON keys cannot be extracted without explicit allowlisting.",
                        )
                    )

        if not allow_json_columns and column_types:
            for col in expression.find_all(exp.Column):
                if id(col) in authorized_column_ids:
                    continue
                if col.find_ancestor(*json_extract_types) is not None:
                    continue
                col_name, candidates, table_candidates, _ = self._column_candidates_for_node(
                    col, scope_map, table_aliases
                )
                col_type = ""
                for tc in table_candidates:
                    if f"{tc}.{col_name}" in column_types:
                        col_type = column_types[f"{tc}.{col_name}"]
                        break
                if not col_type and not table_candidates:
                    col_type = column_types.get(col_name, "")
                if not _is_json_column_type(col_type):
                    continue
                # Allow COUNT(metadata) or metadata IS [NOT] NULL; block selecting, casting, or comparing raw JSON
                if isinstance(col.parent, (exp.Is, exp.Not)) or col.find_ancestor(exp.Count) is not None:
                    continue
                violations.append(
                    SQLPolicyViolation(
                        "json_column_denied",
                        "Raw JSON/JSONB columns cannot be projected or cast directly.",
                    )
                )

        return tuple(sorted(extracted_paths))

    def _validate_sensitive_transforms(
        self,
        expression: exp.Expression,
        protected_columns: set[str],
        scope_map: dict[int, Scope],
        table_aliases: dict[str, set[str]],
        violations: list[SQLPolicyViolation],
    ) -> None:
        if not protected_columns:
            return

        def _has_protected_column(node: exp.Expression) -> bool:
            for col in node.find_all(exp.Column):
                col_name, candidates, _, _ = self._column_candidates_for_node(
                    col, scope_map, table_aliases
                )
                if col_name in protected_columns or (candidates & protected_columns):
                    return True
            return False

        for fn in expression.find_all(exp.Func, exp.Anonymous):
            fn_name = (
                _function_name(fn)
                if isinstance(fn, exp.Func)
                else _normalize_identifier(fn.name)
            )
            if fn_name in OBFUSCATION_FUNCTIONS and _has_protected_column(fn):
                violations.append(
                    SQLPolicyViolation(
                        "sensitive_transform_denied",
                        "Sensitive or masked columns cannot be encoded, hashed, or string-transformed.",
                    )
                )

        for dpipe in expression.find_all(exp.DPipe):
            if _has_protected_column(dpipe):
                violations.append(
                    SQLPolicyViolation(
                        "sensitive_transform_denied",
                        "Sensitive or masked columns cannot be concatenated or string-transformed.",
                    )
                )

        for array_expr in expression.find_all(exp.Array):
            if _has_protected_column(array_expr):
                violations.append(
                    SQLPolicyViolation(
                        "sensitive_transform_denied",
                        "Sensitive or masked columns cannot be wrapped in arrays.",
                    )
                )

        for cast in expression.find_all(exp.Cast, exp.TryCast):
            to_type = _normalize_identifier(cast.to.sql() if cast.to else "")
            base_to_type = re.split(r"[\s(<]", to_type, maxsplit=1)[0]
            if base_to_type in BINARY_CAST_TYPES and _has_protected_column(cast):
                violations.append(
                    SQLPolicyViolation(
                        "sensitive_transform_denied",
                        "Sensitive or masked columns cannot be cast to binary or JSON types.",
                    )
                )

    def _check_sensitive_alias_source(
        self,
        source: exp.Expression,
        alias_name: str,
        protected_columns: set[str],
        scope_map: dict[int, Scope],
        table_aliases: dict[str, set[str]],
        violations: list[SQLPolicyViolation],
    ) -> None:
        if _is_counting_expression(source) and not any(
            isinstance(node, (exp.Case, exp.If)) for node in source.walk()
        ):
            return
        for col in source.find_all(exp.Column):
            if col.find_ancestor(exp.Count, exp.ApproxDistinct) is not None:
                continue
            col_name, candidates, _, _ = self._column_candidates_for_node(
                col, scope_map, table_aliases
            )
            if (col_name in protected_columns or (candidates & protected_columns)) and alias_name != col_name:
                violations.append(
                    SQLPolicyViolation(
                        "sensitive_alias_denied",
                        "Sensitive source columns cannot be hidden behind aliases.",
                    )
                )
                return

    def _validate_sensitive_aliases(
        self,
        expression: exp.Expression,
        protected_columns: set[str],
        scope_map: dict[int, Scope],
        table_aliases: dict[str, set[str]],
        violations: list[SQLPolicyViolation],
    ) -> None:
        for alias in expression.find_all(exp.Alias):
            source = alias.this
            if source is None:
                continue
            alias_name = _normalize_identifier(alias.alias)
            if not alias_name:
                continue
            self._check_sensitive_alias_source(
                source, alias_name, protected_columns, scope_map, table_aliases, violations
            )

        for container in expression.find_all(exp.CTE, exp.Subquery):
            alias_cols = _table_alias_columns(container)
            if not alias_cols or container.this is None:
                continue
            branches = (
                list(container.this.find_all(exp.Select))
                if isinstance(container.this, exp.Union)
                else ([container.this] if isinstance(container.this, exp.Select) else [])
            )
            for branch in branches:
                if branch.find_ancestor(exp.CTE, exp.Subquery) is not container and branch is not container.this:
                    # Only inspect direct branches belonging to this CTE/Subquery, not nested subqueries.
                    parent_union = branch.parent
                    if not isinstance(parent_union, exp.Union):
                        continue
                for idx, alias_name in enumerate(alias_cols):
                    if not alias_name or idx >= len(branch.expressions):
                        continue
                    projection = branch.expressions[idx]
                    source = projection.this if isinstance(projection, exp.Alias) else projection
                    if source is not None:
                        self._check_sensitive_alias_source(
                            source,
                            alias_name,
                            protected_columns,
                            scope_map,
                            table_aliases,
                            violations,
                        )

    def _validate_tenant_filters(
        self,
        expression: exp.Expression,
        scope: EffectiveAccessScope,
        cte_names: set[str],
        scope_map: dict[int, Scope],
        violations: list[SQLPolicyViolation],
    ) -> None:
        tenant_filters = _tenant_filters(scope)
        if not tenant_filters:
            return
        for select in expression.find_all(exp.Select):
            scope_node = scope_map.get(id(select))
            direct_tables = _scope_direct_tables(select, scope_node, cte_names)
            if not direct_tables:
                continue
            where = select.args.get("where")
            for table in direct_tables:
                candidates = _table_candidates(table)
                matching_filters = [
                    tenant_filter
                    for tenant_filter in tenant_filters
                    if _tenant_filter_matches_table(tenant_filter, candidates)
                ]
                if not matching_filters:
                    continue
                left_join = _left_join_for_table(table, select)
                for tenant_filter in matching_filters:
                    status = self._evaluate_table_tenant_filter(
                        where=where,
                        left_join=left_join,
                        select=select,
                        table=table,
                        direct_tables=direct_tables,
                        tenant_filter=tenant_filter,
                    )
                    if status == "missing":
                        violations.append(
                            SQLPolicyViolation(
                                "tenant_predicate_missing",
                                "A required tenant predicate is missing.",
                            )
                        )
                    elif status == "or_denied":
                        violations.append(
                            SQLPolicyViolation(
                                "tenant_or_denied",
                                "OR conditions cannot weaken required tenant predicates.",
                            )
                        )
                    elif status == "wrong_value":
                        violations.append(
                            SQLPolicyViolation(
                                "tenant_predicate_wrong_value",
                                "A tenant predicate used an unauthorized value.",
                            )
                        )
                    elif status == "invalid_operator":
                        violations.append(
                            SQLPolicyViolation(
                                "tenant_predicate_invalid",
                                "Tenant predicates must use equality.",
                            )
                        )

    def _evaluate_table_tenant_filter(
        self,
        *,
        where: exp.Expression | None,
        left_join: exp.Join | None,
        select: exp.Select,
        table: exp.Table,
        direct_tables: list[exp.Table],
        tenant_filter: TenantFilter,
    ) -> str:
        where_status = (
            _tenant_predicate_status(where, select, table, direct_tables, tenant_filter)
            if where is not None
            else "missing"
        )
        if where_status in {"wrong_value", "invalid_operator"}:
            return where_status
        if where_status == "or_denied" and _clause_references_tenant_column(
            where, select, table, direct_tables, tenant_filter
        ):
            return "or_denied"

        if left_join is not None and left_join.args.get("on") is not None:
            on_status = _tenant_predicate_status(
                left_join.args["on"], select, table, direct_tables, tenant_filter
            )
            if on_status == "ok":
                return "ok"
            if on_status != "missing":
                return on_status

        return where_status

    def _validate_complexity(
        self,
        sql: str,
        expression: exp.Expression,
        table_refs: set[str],
        *,
        allow_cross_joins: bool,
        violations: list[SQLPolicyViolation],
    ) -> None:
        if len(sql) > MAX_SQL_LENGTH:
            violations.append(SQLPolicyViolation("sql_too_long", "SQL exceeds policy length limit."))
        joins = list(expression.find_all(exp.Join))
        if len(joins) > MAX_JOINS:
            violations.append(SQLPolicyViolation("too_many_joins", "SQL exceeds join complexity limit."))
        if not allow_cross_joins:
            for join in joins:
                kind = _normalize_identifier(join.kind)
                method = _normalize_identifier(join.method)
                on_clause = join.args.get("on")
                using_clause = join.args.get("using")
                if kind == "cross" or kind == "natural" or method == "natural" or (
                    on_clause is None and using_clause is None
                ):
                    violations.append(
                        SQLPolicyViolation(
                            "cross_join_denied",
                            "CROSS JOIN, NATURAL JOIN, and implicit Cartesian joins are not allowed.",
                        )
                    )
                    break
                if on_clause is not None and _is_tautology_condition(on_clause):
                    violations.append(
                        SQLPolicyViolation(
                            "cross_join_denied",
                            "Tautology JOIN predicates are not allowed.",
                        )
                    )
                    break
        if any(expression.find_all(exp.Lock)):
            violations.append(
                SQLPolicyViolation(
                    "locking_clause_denied",
                    "Row-locking clauses (FOR UPDATE / FOR SHARE) are not allowed.",
                )
            )
        ctes = list(expression.find_all(exp.CTE))
        if len(ctes) > MAX_CTES:
            violations.append(SQLPolicyViolation("too_many_ctes", "SQL exceeds CTE complexity limit."))
        if len(table_refs) > MAX_REFERENCED_TABLES:
            violations.append(
                SQLPolicyViolation("too_many_tables", "SQL references too many tables.")
            )
        with_clause = expression.args.get("with_")
        if isinstance(with_clause, exp.With) and with_clause.args.get("recursive"):
            violations.append(SQLPolicyViolation("recursive_cte_denied", "Recursive CTEs are not allowed."))

    def _safe_limited_sql(
        self,
        expression: exp.Expression,
        normalized_sql: str,
        max_rows: int,
        dialect: SQLDialect,
    ) -> tuple[str, bool]:
        existing_limit = _extract_limit_value(expression)
        if isinstance(expression, exp.Select):
            if existing_limit is not None and existing_limit <= max_rows:
                return normalized_sql, False
            limited = _set_limit(expression, max_rows)
            return limited.sql(dialect=dialect), True

        if existing_limit is not None and existing_limit <= max_rows:
            return normalized_sql, False
        return _wrap_with_limit(normalized_sql, max_rows, dialect), True

    def _deny(
        self,
        sql: str,
        context: SQLValidationContext,
        violations: tuple[SQLPolicyViolation, ...],
        *,
        normalized_sql: str | None = None,
        tables_referenced: tuple[str, ...] = (),
        columns_referenced: tuple[str, ...] = (),
        non_aggregate_columns_referenced: tuple[str, ...] = (),
        count_output_columns: tuple[str, ...] = (),
        has_group_by_or_aggregate: bool = False,
        json_paths_referenced: tuple[str, ...] = (),
        statement_type: SQLStatementType = "unsupported",
        max_rows: int,
        timeout_seconds: int,
        scope_version: str | None,
    ) -> SQLPolicyDecision:
        return SQLPolicyDecision(
            allowed=False,
            decision_id=_decision_id(sql, context, False),
            reason="SQL policy denied query.",
            violations=violations,
            normalized_sql=normalized_sql,
            safe_sql=None,
            tables_referenced=tables_referenced,
            columns_referenced=columns_referenced,
            non_aggregate_columns_referenced=non_aggregate_columns_referenced,
            count_output_columns=count_output_columns,
            has_group_by_or_aggregate=has_group_by_or_aggregate,
            json_paths_referenced=json_paths_referenced,
            statement_type=statement_type,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
            scope_version=scope_version,
        )
