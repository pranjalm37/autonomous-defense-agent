"""
VirusTotal API v3 client.

Auth:   header `x-apikey: <API_KEY>`.
Quota:  free tier = 4 requests/min and 500/day (the bucket below matches the
        per-minute cap; a daily cap should be enforced at the account level).
Docs:   https://docs.virustotal.com/reference/overview
"""
from __future__ import annotations

from app.integrations.base import BaseAPIClient
from app.integrations.cache import Cache
from app.integrations.exceptions import InvalidResponseError
from app.integrations.rate_limit import TokenBucket
from app.integrations.schemas import FileReport, IPReputation, verdict_for

BASE_URL = "https://www.virustotal.com/api/v3"
IP_TTL = 3600       # 1 hour
FILE_TTL = 86_400   # 24 hours (a hash verdict rarely changes)


class VirusTotalClient(BaseAPIClient):
    provider = "virustotal"

    def __init__(self, api_key: str, *, cache: Cache | None = None,
                 rate_limiter: TokenBucket | None = None, **kw):
        super().__init__(
            base_url=BASE_URL, api_key=api_key, cache=cache,
            rate_limiter=rate_limiter or TokenBucket.per_minute(4),  # free tier
            **kw,
        )

    def _auth_headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key or ""}

    async def lookup_ip(self, ip: str) -> IPReputation:
        data = await self._get(f"/ip_addresses/{ip}", cache_ttl=IP_TTL)
        attrs = self._attrs(data)
        stats = attrs.get("last_analysis_stats", {})
        score = self._score(stats)
        return IPReputation(
            ip=ip,
            malicious_score=score,
            verdict=verdict_for(score),
            categories=sorted({v for v in (attrs.get("categories") or {}).values()}),
            total_reports=stats.get("malicious", 0) + stats.get("suspicious", 0),
            country=attrs.get("country"),
            sources=["VirusTotal"],
            raw=data,
        )

    async def lookup_file(self, file_hash: str) -> FileReport:
        data = await self._get(f"/files/{file_hash}", cache_ttl=FILE_TTL)
        attrs = self._attrs(data)
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 0
        return FileReport(
            sha256=attrs.get("sha256", file_hash),
            malicious=malicious,
            suspicious=stats.get("suspicious", 0),
            total_engines=total,
            verdict="malicious" if malicious else "clean",
            names=attrs.get("names", [])[:10],
            sources=["VirusTotal"],
            raw=data,
        )

    # ── helpers ──
    @staticmethod
    def _attrs(data: dict) -> dict:
        try:
            return data["data"]["attributes"]
        except (KeyError, TypeError) as e:
            raise InvalidResponseError("unexpected VirusTotal response shape",
                                       provider="virustotal") from e

    @staticmethod
    def _score(stats: dict) -> int:
        # Score over engines that returned a *definitive* verdict. "undetected"
        # usually means an engine has no signature, not that it vouched the
        # indicator is clean — including it would dilute real detections away.
        definitive = (stats.get("malicious", 0) + stats.get("suspicious", 0)
                      + stats.get("harmless", 0))
        if not definitive:
            return 0
        flagged = stats.get("malicious", 0) + 0.5 * stats.get("suspicious", 0)
        return int(round(100 * flagged / definitive))
