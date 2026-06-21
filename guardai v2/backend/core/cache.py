"""
GuardAI Backend — Cache Layer

Provides a simple TTL cache interface. Uses Redis when REDIS_URL is configured
(required for multi-instance deployments behind App Runner / ALB), otherwise
falls back to an in-process dict (fine for a single-instance MVP / beta).
"""

import json
import time
import logging
from typing import Any, Optional

from core.config import settings

logger = logging.getLogger("guardai.cache")

_memory_store: dict[str, tuple[float, Any]] = {}

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not settings.REDIS_URL:
        return None
    try:
        import redis.asyncio as redis  # lazy import — optional dependency
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        return _redis_client
    except ImportError:
        logger.warning("redis package not installed — falling back to in-memory cache")
        return None


async def cache_get(key: str) -> Optional[Any]:
    client = _get_redis()
    if client is not None:
        try:
            raw = await client.get(key)
            return json.loads(raw) if raw else None
        except Exception as exc:
            logger.warning("Redis GET failed (%s) — falling back to memory cache", exc)

    entry = _memory_store.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if time.time() > expires_at:
        _memory_store.pop(key, None)
        return None
    return value


async def cache_set(key: str, value: Any, ttl_seconds: int) -> None:
    client = _get_redis()
    if client is not None:
        try:
            await client.set(key, json.dumps(value), ex=ttl_seconds)
            return
        except Exception as exc:
            logger.warning("Redis SET failed (%s) — falling back to memory cache", exc)

    # Prevent unbounded growth in memory fallback mode
    if len(_memory_store) > 50_000:
        _memory_store.clear()
    _memory_store[key] = (time.time() + ttl_seconds, value)
