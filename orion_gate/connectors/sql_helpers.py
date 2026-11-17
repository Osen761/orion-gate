"""Shared helper validation for SQL connector tools."""

from __future__ import annotations

from typing import Any


READ_SQL_USAGE_MESSAGE = (
    'read_sql expects SQL as read_sql("SELECT ...") or '
    'read_sql(query="SELECT ...").'
)


class SQLHelperUsageError(ValueError):
    """Raised for safe SQL helper usage errors."""


def resolve_read_sql_query(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Return the one SQL string supplied to read_sql, or raise a safe error."""

    unexpected = set(kwargs) - {"query"}
    if unexpected:
        raise SQLHelperUsageError(READ_SQL_USAGE_MESSAGE)
    if len(args) > 1 or (args and "query" in kwargs):
        raise SQLHelperUsageError(READ_SQL_USAGE_MESSAGE)
    if args:
        sql = args[0]
    elif "query" in kwargs:
        sql = kwargs["query"]
    else:
        raise SQLHelperUsageError(READ_SQL_USAGE_MESSAGE)
    if not isinstance(sql, str) or not sql.strip():
        raise SQLHelperUsageError(READ_SQL_USAGE_MESSAGE)
    return sql
