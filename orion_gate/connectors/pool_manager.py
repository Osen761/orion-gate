"""Bounded, thread-safe connection pool and engine registry with lazy SQL driver imports."""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import OrderedDict
from typing import Any


logger = logging.getLogger(__name__)

MAX_CACHED_CONNECTOR_POOLS = 32

_lock = threading.Lock()
_postgres_pools: OrderedDict[str, Any] = OrderedDict()
_mysql_engines: OrderedDict[str, Any] = OrderedDict()


def _cache_key(prefix: str, dsn: str) -> str:
    digest = hashlib.sha256(f"{prefix}:{dsn}".encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


def _close_postgres_pool_safely(pg_pool: Any) -> None:
    try:
        pg_pool.closeall()
    except Exception:
        logger.debug("Ignoring error while closing Postgres connector pool", exc_info=True)


def _dispose_mysql_engine_safely(engine: Any) -> None:
    try:
        engine.dispose()
    except Exception:
        logger.debug("Ignoring error while disposing MySQL connector engine", exc_info=True)


def get_or_create_postgres_pool(
    dsn: str,
    *,
    cacheable: bool = True,
    minconn: int = 1,
    maxconn: int = 5,
) -> Any:
    """Return a shared Postgres connection pool, evicting the oldest entry if full."""

    from psycopg2 import pool as psycopg2_pool

    if not cacheable:
        return psycopg2_pool.ThreadedConnectionPool(minconn=minconn, maxconn=maxconn, dsn=dsn)

    key = _cache_key("postgres", dsn)
    evicted: Any = None
    with _lock:
        existing = _postgres_pools.get(key)
        if existing is not None and not getattr(existing, "closed", False):
            _postgres_pools.move_to_end(key)
            return existing
        if existing is not None:
            _postgres_pools.pop(key, None)

        created = psycopg2_pool.ThreadedConnectionPool(minconn=minconn, maxconn=maxconn, dsn=dsn)
        _postgres_pools[key] = created
        if len(_postgres_pools) > MAX_CACHED_CONNECTOR_POOLS:
            _, evicted = _postgres_pools.popitem(last=False)

    if evicted is not None:
        _close_postgres_pool_safely(evicted)
    return created


def get_or_create_mysql_engine(
    dsn: str,
    *,
    connect_args: dict[str, Any] | None = None,
    cacheable: bool = True,
    pool_size: int = 3,
    max_overflow: int = 2,
) -> Any:
    """Return a shared SQLAlchemy MySQL engine, evicting the oldest entry if full."""

    from sqlalchemy import create_engine

    if not cacheable:
        return create_engine(
            dsn,
            pool_size=1,
            max_overflow=0,
            pool_pre_ping=True,
            connect_args=connect_args or {},
        )

    key = _cache_key("mysql", dsn)
    evicted: Any = None
    with _lock:
        existing = _mysql_engines.get(key)
        if existing is not None:
            _mysql_engines.move_to_end(key)
            return existing

        created = create_engine(
            dsn,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,
            connect_args=connect_args or {},
        )
        _mysql_engines[key] = created
        if len(_mysql_engines) > MAX_CACHED_CONNECTOR_POOLS:
            _, evicted = _mysql_engines.popitem(last=False)

    if evicted is not None:
        _dispose_mysql_engine_safely(evicted)
    return created


def close_all_connector_pools() -> None:
    """Close all cached Postgres pools and MySQL engines during application shutdown."""

    with _lock:
        pg_pools = list(_postgres_pools.values())
        mysql_engines = list(_mysql_engines.values())
        _postgres_pools.clear()
        _mysql_engines.clear()

    for pg_pool in pg_pools:
        _close_postgres_pool_safely(pg_pool)
    for engine in mysql_engines:
        _dispose_mysql_engine_safely(engine)
