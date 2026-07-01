"""
Response cache.

Threat-intel answers change slowly (an IP's reputation today ≈ an hour from now)
but quotas are tight, so caching is the single biggest lever for staying under
the rate limit. We key on the full request signature and expire by TTL chosen per
endpoint (IP reputation ~1h, CVE data ~24h).

`TTLCache` is async-safe and in-memory (per-process). The `Cache` protocol lets a
Redis-backed implementation drop in for multi-worker deployments without touching
the clients — a shared cache also means worker A's lookup spares worker B a call.
The clock is injectable so expiry is testable without sleeping.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any, Protocol


class Cache(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl: float) -> None: ...


class TTLCache:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic, max_entries: int = 10_000):
        self._store: dict[str, tuple[float, Any]] = {}
        self._clock = clock
        self._max = max_entries
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self._clock() >= expires_at:
                self._store.pop(key, None)   # lazy eviction
                return None
            return value

    async def set(self, key: str, value: Any, ttl: float) -> None:
        async with self._lock:
            if len(self._store) >= self._max:
                self._evict_oldest()
            self._store[key] = (self._clock() + ttl, value)

    def _evict_oldest(self) -> None:
        # cheap eviction: drop the entry with the nearest expiry
        oldest = min(self._store, key=lambda k: self._store[k][0])
        self._store.pop(oldest, None)


class NullCache:
    """Disables caching (always misses) — useful in tests that count requests."""

    async def get(self, key: str) -> Any | None:
        return None

    async def set(self, key: str, value: Any, ttl: float) -> None:
        return None
