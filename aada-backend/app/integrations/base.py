"""
BaseAPIClient — shared HTTP machinery for every external integration.

One place handles the cross-cutting concerns so each provider client only has to
describe its auth header and parse its responses:

  - CACHING        check the cache before the network; store successful responses.
  - RATE LIMITING  acquire a token from the bucket before every real request.
  - RETRIES        exponential backoff with jitter on 429 and 5xx, honoring any
                   Retry-After header; bounded by max_retries.
  - ERROR MAPPING  HTTP status / transport failure → typed IntegrationError.
  - OBSERVABILITY  a small stats counter (requests / cache_hits / retries).

`transport` and `sleep` are injectable so tests run fully offline (httpx
MockTransport) and deterministically (no real backoff waits).
"""
from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from app.integrations.cache import Cache, NullCache
from app.integrations.exceptions import (
    AuthenticationError,
    IntegrationError,
    InvalidResponseError,
    NotFoundError,
    RateLimitError,
    UpstreamError,
)
from app.integrations.rate_limit import TokenBucket
from app.logging_config import get_logger

logger = get_logger(__name__)


class BaseAPIClient:
    provider: str = "base"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        cache: Cache | None = None,
        rate_limiter: TokenBucket | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_cap: float = 8.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.api_key = api_key
        self._cache = cache or NullCache()
        self._limiter = rate_limiter
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._sleep = sleep
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, transport=transport)
        self.stats = {"requests": 0, "cache_hits": 0, "retries": 0}

    # Subclasses override to inject their auth scheme.
    def _auth_headers(self) -> dict[str, str]:
        return {}

    async def _get(self, path: str, *, params: dict | None = None, cache_ttl: float | None = None) -> Any:
        return await self._request("GET", path, params=params, cache_ttl=cache_ttl)

    async def _request(
        self, method: str, path: str, *, params: dict | None = None,
        json: dict | None = None, cache_ttl: float | None = None,
    ) -> Any:
        cache_key = f"{self.provider}:{method}:{path}:{sorted((params or {}).items())}"

        if cache_ttl:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                self.stats["cache_hits"] += 1
                return cached

        attempt = 0
        while True:
            if self._limiter is not None:
                await self._limiter.acquire()

            self.stats["requests"] += 1
            try:
                resp = await self._client.request(
                    method, path, params=params, json=json, headers=self._auth_headers(),
                )
            except httpx.RequestError as e:
                if attempt < self._max_retries:
                    attempt += 1
                    self.stats["retries"] += 1
                    await self._sleep(self._backoff(attempt))
                    continue
                raise UpstreamError(f"network error: {e}", provider=self.provider) from e

            if resp.status_code == 200:
                data = self._parse_json(resp)
                if cache_ttl:
                    await self._cache.set(cache_key, data, cache_ttl)
                return data

            # Retryable: 429 (rate limited) and 5xx (transient upstream).
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < self._max_retries:
                    attempt += 1
                    self.stats["retries"] += 1
                    await self._sleep(self._retry_after(resp) or self._backoff(attempt))
                    continue

            raise self._map_error(resp)

    # ── helpers ──
    def _backoff(self, attempt: int) -> float:
        wait = min(self._backoff_cap, self._backoff_base * (2 ** (attempt - 1)))
        return wait + random.uniform(0, wait * 0.25)   # full-ish jitter

    @staticmethod
    def _retry_after(resp: httpx.Response) -> float | None:
        raw = resp.headers.get("Retry-After")
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    def _map_error(self, resp: httpx.Response) -> IntegrationError:
        code = resp.status_code
        body = resp.text[:300]
        if code in (401, 403):
            return AuthenticationError(f"auth failed ({code}): {body}", provider=self.provider, status=code)
        if code == 404:
            return NotFoundError(f"not found ({code})", provider=self.provider, status=code)
        if code == 429:
            return RateLimitError(f"rate limited: {body}", provider=self.provider,
                                  retry_after=self._retry_after(resp))
        return UpstreamError(f"upstream error ({code}): {body}", provider=self.provider, status=code)

    def _parse_json(self, resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except ValueError as e:
            raise InvalidResponseError(f"invalid JSON from {self.provider}", provider=self.provider) from e

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
