"""
EnrichmentService — one façade over all three providers.

Callers (the MCP tools, the analyst) ask for "the reputation of this IP" without
caring which feeds answered. The service fans out to whichever clients are
configured, MERGES their normalized results, and degrades gracefully: if one
provider errors or is rate-limited, the others still return an answer. A shared
cache is injected into every client so lookups are de-duplicated across providers
and calls.

Construct with `EnrichmentService.from_settings()` — it builds only the clients
whose API keys are present, so the service works with one, two, or all three.
"""
from __future__ import annotations

from app.integrations.abuseipdb import AbuseIPDBClient
from app.integrations.cache import Cache, TTLCache
from app.integrations.exceptions import IntegrationError
from app.integrations.nvd import NVDClient
from app.integrations.schemas import CVERecord, FileReport, IPReputation, verdict_for
from app.integrations.virustotal import VirusTotalClient
from app.logging_config import get_logger

logger = get_logger(__name__)


class EnrichmentService:
    def __init__(
        self, *,
        virustotal: VirusTotalClient | None = None,
        abuseipdb: AbuseIPDBClient | None = None,
        nvd: NVDClient | None = None,
    ):
        self.virustotal = virustotal
        self.abuseipdb = abuseipdb
        self.nvd = nvd

    # ── IP reputation: merge VirusTotal + AbuseIPDB ─────────────────────────────
    async def ip_reputation(self, ip: str) -> IPReputation:
        parts: list[IPReputation] = []
        if self.abuseipdb:
            parts.append(await self._safe(self.abuseipdb.check_ip(ip), "abuseipdb"))
        if self.virustotal:
            parts.append(await self._safe(self.virustotal.lookup_ip(ip), "virustotal"))
        parts = [p for p in parts if p is not None]

        if not parts:
            return IPReputation(ip=ip, malicious_score=0, verdict="unknown",
                                sources=[], raw={"note": "no provider returned data"})

        score = max(p.malicious_score for p in parts)          # worst-case wins
        categories = sorted({c for p in parts for c in p.categories})
        sources = sorted({s for p in parts for s in p.sources})
        country = next((p.country for p in parts if p.country), None)
        total = sum(p.total_reports or 0 for p in parts) or None
        return IPReputation(
            ip=ip, malicious_score=score, verdict=verdict_for(score),
            categories=categories, total_reports=total, country=country,
            sources=sources, raw={p.sources[0]: p.raw for p in parts if p.sources},
        )

    async def file_reputation(self, file_hash: str) -> FileReport | None:
        if not self.virustotal:
            return None
        return await self._safe(self.virustotal.lookup_file(file_hash), "virustotal")

    async def cve_search(self, **kwargs) -> list[CVERecord]:
        if not self.nvd:
            return []
        result = await self._safe(self.nvd.search(**kwargs), "nvd")
        return result or []

    # ── graceful degradation ────────────────────────────────────────────────────
    @staticmethod
    async def _safe(coro, provider: str):
        try:
            return await coro
        except IntegrationError as e:
            logger.warning("enrichment_provider_failed", provider=provider, error=str(e))
            return None

    async def aclose(self) -> None:
        for client in (self.virustotal, self.abuseipdb, self.nvd):
            if client is not None:
                await client.aclose()

    # ── factory ─────────────────────────────────────────────────────────────────
    @classmethod
    def from_settings(cls, *, cache: Cache | None = None) -> "EnrichmentService":
        from app.config import get_settings
        s = get_settings()
        shared = cache or TTLCache()   # one cache shared by all clients

        vt = VirusTotalClient(s.virustotal_api_key, cache=shared) \
            if getattr(s, "virustotal_api_key", None) else None
        abuse = AbuseIPDBClient(s.abuseipdb_api_key, cache=shared) \
            if getattr(s, "abuseipdb_api_key", None) else None
        # NVD works without a key (lower quota), so always enable it.
        nvd = NVDClient(getattr(s, "nvd_api_key", None), cache=shared)

        enabled = [name for name, c in
                   (("virustotal", vt), ("abuseipdb", abuse), ("nvd", nvd)) if c]
        logger.info("enrichment_service_built", providers=enabled)
        return cls(virustotal=vt, abuseipdb=abuse, nvd=nvd)
