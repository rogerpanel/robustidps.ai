"""
Redis caching layer for sub-100ms responses.

Caches benchmark analytics, prediction results, and frequently-accessed
data with configurable TTLs. Falls back gracefully to in-memory cache
when Redis is unavailable.

Usage:
    from redis_cache import cache

    # Decorator-based caching
    @cache.cached("analytics", ttl=300)
    async def get_analytics():
        return expensive_computation()

    # Manual get/set
    cache.set("key", value, ttl=60)
    result = cache.get("key")
"""

import json
import time
import hashlib
import logging
import os
from typing import Any, Callable
from functools import wraps

logger = logging.getLogger("robustidps.cache")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "300"))  # 5 minutes


class InMemoryFallback:
    """Simple in-memory TTL cache used when Redis is unavailable."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[float, float, Any]] = {}  # key -> (created, ttl, value)

    def get(self, key: str) -> Any | None:
        if key in self._store:
            created, ttl, val = self._store[key]
            if time.time() - created < ttl:
                return val
            del self._store[key]
        return None

    def set(self, key: str, value: Any, ttl: float = CACHE_DEFAULT_TTL) -> None:
        self._store[key] = (time.time(), ttl, value)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def flush(self) -> None:
        self._store.clear()

    def keys_count(self) -> int:
        self._evict_expired()
        return len(self._store)

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [k for k, (c, t, _) in self._store.items() if now - c >= t]
        for k in expired:
            del self._store[k]


class RedisCache:
    """Redis-backed cache with in-memory fallback.

    All operations are non-blocking and never raise exceptions to callers.
    If Redis is down, the in-memory fallback handles requests seamlessly.
    """

    def __init__(self) -> None:
        self._redis = None
        self._fallback = InMemoryFallback()
        self._redis_available = False
        self._connect_attempted = False

    def _connect(self) -> None:
        """Lazy-connect to Redis on first use."""
        if self._connect_attempted:
            return
        self._connect_attempted = True
        try:
            import redis
            self._redis = redis.Redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=1,
                retry_on_timeout=True,
            )
            self._redis.ping()
            self._redis_available = True
            logger.info("Redis cache connected: %s", REDIS_URL)
        except Exception as e:
            self._redis = None
            self._redis_available = False
            logger.warning("Redis unavailable (%s), using in-memory fallback", e)

    def get(self, key: str) -> Any | None:
        """Get a cached value by key."""
        self._connect()
        if self._redis_available:
            try:
                raw = self._redis.get(f"ridps:{key}")
                if raw is not None:
                    return json.loads(raw)
                return None
            except Exception:
                pass
        return self._fallback.get(key)

    def set(self, key: str, value: Any, ttl: int = CACHE_DEFAULT_TTL) -> None:
        """Set a cached value with TTL (seconds)."""
        self._connect()
        serialized = json.dumps(value, default=str)
        if self._redis_available:
            try:
                self._redis.setex(f"ridps:{key}", ttl, serialized)
                return
            except Exception:
                pass
        self._fallback.set(key, value, ttl)

    def delete(self, key: str) -> None:
        """Delete a cached key."""
        self._connect()
        if self._redis_available:
            try:
                self._redis.delete(f"ridps:{key}")
            except Exception:
                pass
        self._fallback.delete(key)

    def flush_prefix(self, prefix: str) -> int:
        """Delete all keys matching a prefix. Returns count deleted."""
        self._connect()
        count = 0
        if self._redis_available:
            try:
                cursor = 0
                while True:
                    cursor, keys = self._redis.scan(cursor, match=f"ridps:{prefix}*", count=100)
                    if keys:
                        count += self._redis.delete(*keys)
                    if cursor == 0:
                        break
            except Exception:
                pass
        return count

    def cached(self, prefix: str, ttl: int = CACHE_DEFAULT_TTL):
        """Decorator to cache function results.

        Cache key is derived from prefix + function args hash.

        Usage:
            @cache.cached("analytics", ttl=300)
            async def get_analytics():
                return expensive_computation()
        """
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Build cache key from args
                key_data = f"{prefix}:{func.__name__}:{args}:{sorted(kwargs.items())}"
                cache_key = f"{prefix}:{hashlib.md5(key_data.encode()).hexdigest()[:12]}"

                # Try cache first
                result = self.get(cache_key)
                if result is not None:
                    return result

                # Cache miss — compute and store
                result = await func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result
            return wrapper
        return decorator

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        self._connect()
        info: dict[str, Any] = {
            "backend": "redis" if self._redis_available else "in-memory",
            "available": self._redis_available,
        }
        if self._redis_available:
            try:
                redis_info = self._redis.info("memory")
                info["used_memory_mb"] = round(redis_info.get("used_memory", 0) / 1024 / 1024, 2)
                info["keys"] = self._redis.dbsize()
            except Exception:
                pass
        else:
            info["keys"] = self._fallback.keys_count()
        return info


# Singleton instance
cache = RedisCache()
