"""
Client-side rate limiting (token bucket).

Each provider publishes a quota (e.g. VirusTotal free = 4 requests/min, AbuseIPDB
free = 1000/day, NVD = 5 req/30s without a key). Exceeding it earns a 429 — or,
worse, a temporary ban. A token bucket smooths our call rate to stay under the
limit: the bucket holds up to `capacity` tokens and refills at `refill_rate`
tokens/second; each request spends one token, and `acquire()` waits when the
bucket is empty.

`clock` and `sleep` are injectable so the limiter is testable deterministically
(a fake clock advances time without real waiting).
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class TokenBucket:
    def __init__(
        self,
        capacity: int,
        refill_rate: float,                 # tokens per second
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._tokens = float(capacity)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.refill_rate)
        self._updated = now

    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking: spend tokens if available, else return False."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    async def acquire(self, tokens: int = 1) -> None:
        """Block until `tokens` are available, then spend them."""
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await self._sleep(deficit / self.refill_rate)

    @classmethod
    def per_minute(cls, n: int, **kw) -> "TokenBucket":
        return cls(capacity=n, refill_rate=n / 60.0, **kw)

    @classmethod
    def per_day(cls, n: int, *, burst: int = 10, **kw) -> "TokenBucket":
        return cls(capacity=burst, refill_rate=n / 86_400.0, **kw)

    @classmethod
    def per_seconds(cls, n: int, seconds: float, **kw) -> "TokenBucket":
        return cls(capacity=n, refill_rate=n / seconds, **kw)
