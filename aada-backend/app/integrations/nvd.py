"""
NVD (National Vulnerability Database) API 2.0 client.

Auth:   optional header `apiKey: <API_KEY>`. The key is NOT required, but without
        it you get 5 requests/30s; with it, 50/30s. (So auth here buys throughput,
        not access — see the security notes.)
Quota:  5 req/30s anonymous, 50 req/30s with a key. NVD also asks callers to sleep
        ~6s between paged requests; our limiter enforces the per-window cap.
Docs:   https://nvd.nist.gov/developers/vulnerabilities
"""
from __future__ import annotations

from app.integrations.base import BaseAPIClient
from app.integrations.cache import Cache
from app.integrations.exceptions import InvalidResponseError
from app.integrations.rate_limit import TokenBucket
from app.integrations.schemas import CVERecord

BASE_URL = "https://services.nvd.nist.gov/rest/json"
CVE_TTL = 86_400   # 24 hours


class NVDClient(BaseAPIClient):
    provider = "nvd"

    def __init__(self, api_key: str | None = None, *, cache: Cache | None = None,
                 rate_limiter: TokenBucket | None = None, **kw):
        # With a key NVD allows 50/30s, otherwise 5/30s.
        default_limit = TokenBucket.per_seconds(50 if api_key else 5, 30.0)
        super().__init__(
            base_url=BASE_URL, api_key=api_key, cache=cache,
            rate_limiter=rate_limiter or default_limit, **kw,
        )

    def _auth_headers(self) -> dict[str, str]:
        return {"apiKey": self.api_key} if self.api_key else {}

    async def search(
        self, *, keyword: str | None = None, cve_id: str | None = None,
        cpe_name: str | None = None, max_results: int = 20,
    ) -> list[CVERecord]:
        params: dict = {"resultsPerPage": max_results}
        if keyword:
            params["keywordSearch"] = keyword
        if cve_id:
            params["cveId"] = cve_id
        if cpe_name:
            params["cpeName"] = cpe_name

        data = await self._get("/cves/2.0", params=params, cache_ttl=CVE_TTL)
        vulns = data.get("vulnerabilities")
        if vulns is None:
            raise InvalidResponseError("unexpected NVD response shape", provider="nvd")
        return [self._to_record(v.get("cve", {})) for v in vulns]

    @staticmethod
    def _to_record(cve: dict) -> CVERecord:
        # English description
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        # Prefer CVSS v3.1 → v3.0 → v2
        cvss = severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cvss = m.get("cvssData", {}).get("baseScore")
                severity = (m.get("cvssData", {}).get("baseSeverity")
                            or m.get("baseSeverity"))
                break
        refs = [r["url"] for r in cve.get("references", []) if r.get("url")]
        return CVERecord(
            id=cve.get("id", "UNKNOWN"),
            cvss=cvss,
            severity=(severity or "").lower() or None,
            description=desc,
            references=refs[:10],
            published=cve.get("published"),
            source="NVD",
            raw=cve,
        )
