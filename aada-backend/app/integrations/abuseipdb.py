"""
AbuseIPDB API v2 client.

Auth:   header `Key: <API_KEY>` (plus `Accept: application/json`).
Quota:  free tier = 1000 checks/day.
Docs:   https://docs.abuseipdb.com/

AbuseIPDB already returns a 0-100 `abuseConfidenceScore`, which maps directly onto
our malicious_score. Report categories come back as integer ids; we translate the
common ones to readable labels.
"""
from __future__ import annotations

from app.integrations.base import BaseAPIClient
from app.integrations.cache import Cache
from app.integrations.exceptions import InvalidResponseError
from app.integrations.rate_limit import TokenBucket
from app.integrations.schemas import IPReputation, verdict_for

BASE_URL = "https://api.abuseipdb.com/api/v2"
IP_TTL = 3600

# https://www.abuseipdb.com/categories
_CATEGORIES = {
    3: "fraud_orders", 4: "ddos", 5: "ftp_brute_force", 9: "open_proxy",
    10: "web_spam", 11: "email_spam", 14: "port_scan", 15: "hacking",
    18: "brute_force", 19: "bad_web_bot", 20: "exploited_host",
    21: "web_app_attack", 22: "ssh", 23: "iot_targeted",
}


class AbuseIPDBClient(BaseAPIClient):
    provider = "abuseipdb"

    def __init__(self, api_key: str, *, cache: Cache | None = None,
                 rate_limiter: TokenBucket | None = None, **kw):
        super().__init__(
            base_url=BASE_URL, api_key=api_key, cache=cache,
            rate_limiter=rate_limiter or TokenBucket.per_day(1000),  # free tier
            **kw,
        )

    def _auth_headers(self) -> dict[str, str]:
        return {"Key": self.api_key or "", "Accept": "application/json"}

    async def check_ip(self, ip: str, *, max_age_days: int = 90) -> IPReputation:
        data = await self._get(
            "/check",
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
            cache_ttl=IP_TTL,
        )
        d = self._data(data)
        score = int(d.get("abuseConfidenceScore", 0))
        category_ids = self._category_ids(d)
        return IPReputation(
            ip=ip,
            malicious_score=score,
            verdict=verdict_for(score),
            categories=[_CATEGORIES.get(c, str(c)) for c in category_ids],
            total_reports=d.get("totalReports"),
            country=d.get("countryCode"),
            sources=["AbuseIPDB"],
            raw=data,
        )

    @staticmethod
    def _data(data: dict) -> dict:
        try:
            return data["data"]
        except (KeyError, TypeError) as e:
            raise InvalidResponseError("unexpected AbuseIPDB response shape",
                                       provider="abuseipdb") from e

    @staticmethod
    def _category_ids(d: dict) -> list[int]:
        ids: set[int] = set()
        for report in d.get("reports", []) or []:
            ids.update(report.get("categories", []) or [])
        return sorted(ids)
