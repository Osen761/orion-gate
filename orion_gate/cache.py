"""Bounded cache helpers for Orion Gate (optional Redis with thread-safe local TTL store)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any

from orion_gate.config import settings

try:
    import redis as sync_redis
except ImportError:  # pragma: no cover - redis extra not installed
    sync_redis = None  # type: ignore[assignment]

try:
    from upstash_redis import Redis as UpstashRedis
except ImportError:  # pragma: no cover - upstash-redis optional
    UpstashRedis = None  # type: ignore[misc,assignment]


MAX_LOCAL_CACHE_KEYS = 4096
_local_lock = threading.Lock()
_local_ttl_cache: OrderedDict[str, tuple[str, float]] = OrderedDict()

upstash_redis_client = None
if (
    UpstashRedis is not None
    and settings.UPSTASH_REDIS_REST_URL
    and settings.UPSTASH_REDIS_REST_TOKEN
):
    upstash_redis_client = UpstashRedis(
        url=settings.UPSTASH_REDIS_REST_URL,
        token=settings.UPSTASH_REDIS_REST_TOKEN,
    )

_sync_redis_client: Any = None


def _get_sync_redis_client() -> Any:
    global _sync_redis_client
    if sync_redis is None or not settings.REDIS_URL:
        return None
    if _sync_redis_client is None:
        _sync_redis_client = sync_redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
    return _sync_redis_client


def _local_get(key: str) -> str | None:
    now = time.monotonic()
    with _local_lock:
        entry = _local_ttl_cache.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at <= now:
            _local_ttl_cache.pop(key, None)
            return None
        _local_ttl_cache.move_to_end(key)
        return value


def _local_set(key: str, value: str, ttl_seconds: int) -> None:
    expires_at = time.monotonic() + max(1, ttl_seconds)
    with _local_lock:
        _local_ttl_cache[key] = (value, expires_at)
        _local_ttl_cache.move_to_end(key)
        while len(_local_ttl_cache) > MAX_LOCAL_CACHE_KEYS:
            _local_ttl_cache.popitem(last=False)


def sync_cache_get(key: str) -> str | None:
    """Return a cached string value synchronously via Redis/Upstash or in-process TTL cache."""

    if upstash_redis_client is not None:
        try:
            value = upstash_redis_client.get(key)
            if value is not None:
                return str(value)
        except Exception:
            pass

    client = _get_sync_redis_client()
    if client is not None:
        try:
            value = client.get(key)
            if value is not None:
                return str(value)
        except Exception:
            pass

    return _local_get(key)


def sync_cache_set(key: str, value: str, ttl_seconds: int = 3600) -> None:
    """Store a cached string value synchronously via Redis/Upstash and in-process TTL cache."""

    _local_set(key, value, ttl_seconds)
    if upstash_redis_client is not None:
        try:
            upstash_redis_client.set(key, value, ex=ttl_seconds)
            return
        except Exception:
            pass

    client = _get_sync_redis_client()
    if client is not None:
        try:
            client.set(key, value, ex=ttl_seconds)
        except Exception:
            return
