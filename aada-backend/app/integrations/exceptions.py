"""
Typed integration errors.

Every external call funnels HTTP/network failures into this small hierarchy so
callers (and the enrichment service) can react by *kind* — retry a transient
upstream error, surface an auth misconfiguration loudly, back off on a rate
limit — without parsing status codes everywhere.
"""
from __future__ import annotations


class IntegrationError(Exception):
    """Base for all external-API failures."""

    def __init__(self, message: str, *, provider: str | None = None, status: int | None = None):
        super().__init__(message)
        self.provider = provider
        self.status = status


class AuthenticationError(IntegrationError):
    """401/403 — missing, invalid, or unauthorized API key."""


class RateLimitError(IntegrationError):
    """429 — quota exhausted. `retry_after` is seconds to wait, if the API said so."""

    def __init__(self, message: str, *, provider=None, status=429, retry_after: float | None = None):
        super().__init__(message, provider=provider, status=status)
        self.retry_after = retry_after


class NotFoundError(IntegrationError):
    """404 — the indicator/resource is not known to the provider."""


class UpstreamError(IntegrationError):
    """5xx or a network/transport failure after retries were exhausted."""


class InvalidResponseError(IntegrationError):
    """The response was not the shape we expected (parse failure)."""
