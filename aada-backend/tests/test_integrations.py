"""
External-integration tests — fully offline via httpx.MockTransport.

Covers the four required behaviors (clients, error handling, rate limiting,
caching) plus response normalization and the enrichment merge. No network calls.
"""
from __future__ import annotations

import httpx
import pytest

from app.integrations.abuseipdb import AbuseIPDBClient
from app.integrations.cache import NullCache, TTLCache
from app.integrations.enrichment import EnrichmentService
from app.integrations.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    UpstreamError,
)
from app.integrations.nvd import NVDClient
from app.integrations.rate_limit import TokenBucket
from app.integrations.virustotal import VirusTotalClient

# ── Fixtures: canned API responses ────────────────────────────────────────────
VT_IP = {
    "data": {"attributes": {
        # 18 of 24 engines with a definitive verdict flag it → clearly malicious.
        "last_analysis_stats": {"malicious": 18, "suspicious": 2, "harmless": 4, "undetected": 10},
        "country": "RU", "categories": {"x": "malware"},
    }}
}
VT_FILE = {
    "data": {"attributes": {
        "sha256": "abc123", "names": ["invoice.scr"],
        "last_analysis_stats": {"malicious": 45, "suspicious": 1, "harmless": 0, "undetected": 24},
    }}
}
ABUSE_IP = {
    "data": {"abuseConfidenceScore": 97, "countryCode": "RU", "totalReports": 412,
             "reports": [{"categories": [18, 22]}]}
}
NVD_CVE = {
    "vulnerabilities": [{"cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
        "published": "2021-12-10",
    }}]
}


def _transport(handler):
    return httpx.MockTransport(handler)


async def _nosleep(_):    # make backoff instant in retry tests
    return None


# ── VirusTotal ────────────────────────────────────────────────────────────────
async def test_virustotal_parses_and_sends_auth_header():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["x-apikey"] = req.headers.get("x-apikey")
        return httpx.Response(200, json=VT_IP)

    client = VirusTotalClient("VT_KEY", transport=_transport(handler), rate_limiter=None)
    rep = await client.lookup_ip("203.0.113.66")
    assert seen["x-apikey"] == "VT_KEY"            # auth header sent
    assert rep.verdict == "malicious"
    assert rep.malicious_score == 79                # (18 + 0.5*2) / 24 definitive = 79%
    assert rep.country == "RU"
    await client.aclose()


async def test_virustotal_file_lookup():
    client = VirusTotalClient("k", transport=_transport(lambda r: httpx.Response(200, json=VT_FILE)),
                              rate_limiter=None)
    report = await client.lookup_file("abc123")
    assert report.malicious == 45 and report.verdict == "malicious"
    assert "invoice.scr" in report.names
    await client.aclose()


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
async def test_abuseipdb_maps_score_and_categories():
    seen = {}

    def handler(req):
        seen["Key"] = req.headers.get("Key")
        return httpx.Response(200, json=ABUSE_IP)

    client = AbuseIPDBClient("ABUSE_KEY", transport=_transport(handler), rate_limiter=None)
    rep = await client.check_ip("203.0.113.66")
    assert seen["Key"] == "ABUSE_KEY"
    assert rep.malicious_score == 97 and rep.verdict == "malicious"
    assert "ssh" in rep.categories and "brute_force" in rep.categories
    assert rep.total_reports == 412
    await client.aclose()


# ── NVD ───────────────────────────────────────────────────────────────────────
async def test_nvd_search_parses_cvss_and_description():
    client = NVDClient(transport=_transport(lambda r: httpx.Response(200, json=NVD_CVE)),
                       rate_limiter=None)
    cves = await client.search(keyword="log4j")
    assert len(cves) == 1
    assert cves[0].id == "CVE-2021-44228"
    assert cves[0].cvss == 10.0 and cves[0].severity == "critical"
    await client.aclose()


async def test_nvd_quota_differs_with_key():
    with_key = NVDClient("KEY", transport=_transport(lambda r: httpx.Response(200, json=NVD_CVE)))
    without = NVDClient(None, transport=_transport(lambda r: httpx.Response(200, json=NVD_CVE)))
    assert with_key._limiter.capacity == 50      # 50/30s with a key
    assert without._limiter.capacity == 5        # 5/30s anonymous


# ── Error handling ────────────────────────────────────────────────────────────
async def test_401_maps_to_authentication_error():
    client = VirusTotalClient("bad", transport=_transport(lambda r: httpx.Response(401, text="forbidden")),
                              rate_limiter=None)
    with pytest.raises(AuthenticationError):
        await client.lookup_ip("1.2.3.4")
    await client.aclose()


async def test_404_maps_to_not_found():
    client = VirusTotalClient("k", transport=_transport(lambda r: httpx.Response(404)),
                              rate_limiter=None)
    with pytest.raises(NotFoundError):
        await client.lookup_ip("1.2.3.4")
    await client.aclose()


async def test_429_retries_then_raises_rate_limit():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "0"}, text="slow down")

    client = VirusTotalClient("k", transport=_transport(handler), rate_limiter=None,
                              max_retries=2, sleep=_nosleep)
    with pytest.raises(RateLimitError):
        await client.lookup_ip("1.2.3.4")
    assert calls["n"] == 3                         # initial + 2 retries
    assert client.stats["retries"] == 2
    await client.aclose()


async def test_5xx_retries_then_upstream_error():
    client = VirusTotalClient("k", transport=_transport(lambda r: httpx.Response(503)),
                              rate_limiter=None, max_retries=1, sleep=_nosleep)
    with pytest.raises(UpstreamError):
        await client.lookup_ip("1.2.3.4")
    await client.aclose()


# ── Caching ───────────────────────────────────────────────────────────────────
async def test_cache_hit_avoids_second_request():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(200, json=VT_IP)

    client = VirusTotalClient("k", transport=_transport(handler), rate_limiter=None, cache=TTLCache())
    await client.lookup_ip("8.8.8.8")
    await client.lookup_ip("8.8.8.8")              # served from cache
    assert calls["n"] == 1
    assert client.stats["cache_hits"] == 1
    await client.aclose()


async def test_nullcache_always_calls():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(200, json=VT_IP)

    client = VirusTotalClient("k", transport=_transport(handler), rate_limiter=None, cache=NullCache())
    await client.lookup_ip("8.8.8.8")
    await client.lookup_ip("8.8.8.8")
    assert calls["n"] == 2
    await client.aclose()


async def test_ttl_cache_expires():
    now = {"t": 1000.0}
    cache = TTLCache(clock=lambda: now["t"])
    await cache.set("k", "v", ttl=10)
    assert await cache.get("k") == "v"
    now["t"] += 11                                 # advance past TTL
    assert await cache.get("k") is None


# ── Rate limiting ─────────────────────────────────────────────────────────────
async def test_token_bucket_limits_and_refills():
    now = {"t": 0.0}
    waited = []

    async def fake_sleep(s):
        waited.append(s)
        now["t"] += s                              # advance fake time by the wait

    bucket = TokenBucket(capacity=2, refill_rate=1.0,   # 1 token/sec
                         clock=lambda: now["t"], sleep=fake_sleep)
    assert bucket.try_acquire() and bucket.try_acquire()   # burst of 2
    assert bucket.try_acquire() is False                   # empty now
    await bucket.acquire()                                  # must wait ~1s for a refill
    assert waited and waited[0] == pytest.approx(1.0, abs=0.01)


# ── Enrichment service (merge + graceful degradation) ─────────────────────────
async def test_enrichment_merges_providers_worst_case_wins():
    vt = VirusTotalClient("k", transport=_transport(lambda r: httpx.Response(200, json=VT_IP)),
                          rate_limiter=None)
    abuse = AbuseIPDBClient("k", transport=_transport(lambda r: httpx.Response(200, json=ABUSE_IP)),
                            rate_limiter=None)
    svc = EnrichmentService(virustotal=vt, abuseipdb=abuse)
    rep = await svc.ip_reputation("203.0.113.66")
    assert rep.malicious_score == 97               # max(9, 97)
    assert set(rep.sources) == {"VirusTotal", "AbuseIPDB"}
    await svc.aclose()


async def test_enrichment_degrades_when_one_provider_fails():
    vt = VirusTotalClient("k", transport=_transport(lambda r: httpx.Response(500)),
                          rate_limiter=None, max_retries=0)
    abuse = AbuseIPDBClient("k", transport=_transport(lambda r: httpx.Response(200, json=ABUSE_IP)),
                            rate_limiter=None)
    svc = EnrichmentService(virustotal=vt, abuseipdb=abuse)
    rep = await svc.ip_reputation("203.0.113.66")  # VT 500s, AbuseIPDB still answers
    assert rep.malicious_score == 97
    assert rep.sources == ["AbuseIPDB"]
    await svc.aclose()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
