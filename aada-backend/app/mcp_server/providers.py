"""
Data providers and action backends behind the MCP tools.

Each tool delegates to one of these so the tool handlers stay thin and the
*sources* are swappable. The defaults are offline and safe:

  - ReputationFeed / CVEDatabase / ThreatIntelFeed  — seeded JSON (production:
    AbuseIPDB / GreyNoise, the NVD API, ThreatFox / MISP).
  - SimulatedFirewall  — an in-memory blocklist. It never touches a real network
    device. A production backend (palo alto / iptables / cloud SG) implements the
    same interface and is gated behind the approval workflow.
  - EventStore  — InMemory for tests, DB-backed for the running app.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

# aada-backend/data/threat_intel  (…/app/mcp_server/providers.py → up 2)
DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "threat_intel"


# ──────────────────────────────────────────────────────────────────────────────
# IP reputation
# ──────────────────────────────────────────────────────────────────────────────
class ReputationFeed:
    def __init__(self, records: list[dict] | None = None):
        self._by_ip = {r["ip"]: r for r in (records or [])}

    @classmethod
    def load(cls, data_dir: Path = DATA_DIR) -> "ReputationFeed":
        path = data_dir / "ip_reputation.json"
        return cls(json.loads(path.read_text()) if path.exists() else [])

    def lookup(self, ip: str) -> dict:
        rec = self._by_ip.get(ip)
        if rec:
            return rec
        return {"ip": ip, "score": None, "categories": [], "sources": [],
                "notes": "No reputation data on file."}


# ──────────────────────────────────────────────────────────────────────────────
# CVE database
# ──────────────────────────────────────────────────────────────────────────────
class CVEDatabase:
    def __init__(self, records: list[dict] | None = None):
        self._records = records or []

    @classmethod
    def load(cls, data_dir: Path = DATA_DIR) -> "CVEDatabase":
        path = data_dir / "cve.json"
        return cls(json.loads(path.read_text()) if path.exists() else [])

    def search(self, *, query: str | None = None, product: str | None = None,
               cve_id: str | None = None, max_results: int = 10) -> list[dict]:
        out = []
        for cve in self._records:
            if cve_id and cve_id.upper() != cve["id"].upper():
                continue
            if product and product.lower() not in [p.lower() for p in cve.get("products", [])]:
                continue
            if query:
                hay = f"{cve['id']} {cve.get('name','')} {cve.get('description','')} " \
                      f"{' '.join(cve.get('products', []))}".lower()
                if not all(term in hay for term in query.lower().split()):
                    continue
            out.append(cve)
        out.sort(key=lambda c: c.get("cvss", 0), reverse=True)
        return out[:max_results]


# ──────────────────────────────────────────────────────────────────────────────
# Threat intelligence (actors / campaigns)
# ──────────────────────────────────────────────────────────────────────────────
class ThreatIntelFeed:
    def __init__(self, actors: list[dict] | None = None):
        self._actors = actors or []

    @classmethod
    def load(cls, data_dir: Path = DATA_DIR) -> "ThreatIntelFeed":
        path = data_dir / "threat_actors.json"
        return cls(json.loads(path.read_text()) if path.exists() else [])

    def match_indicator(self, indicator: str) -> list[dict]:
        ind = indicator.lower()
        hits = []
        for a in self._actors:
            pools = (a.get("associated_ips", []) + a.get("associated_hashes", [])
                     + a.get("associated_domains", []))
            if any(ind == str(x).lower() for x in pools):
                hits.append(a)
        return hits


# ──────────────────────────────────────────────────────────────────────────────
# Firewall backend (SAFE default: simulated, in-memory)
# ──────────────────────────────────────────────────────────────────────────────
class FirewallBackend(Protocol):
    def block(self, ip: str, reason: str, ttl_minutes: int | None) -> dict: ...
    def unblock(self, ip: str) -> dict: ...
    def list_blocked(self) -> list[dict]: ...
    def is_blocked(self, ip: str) -> bool: ...


class SimulatedFirewall:
    """In-memory blocklist. Never touches a real device. Production swaps this
    for a real backend that is gated behind the approval workflow."""

    def __init__(self):
        self._blocked: dict[str, dict] = {}

    def block(self, ip: str, reason: str, ttl_minutes: int | None) -> dict:
        entry = {
            "ip": ip, "reason": reason, "ttl_minutes": ttl_minutes,
            "blocked_at": datetime.now(timezone.utc).isoformat(), "simulated": True,
        }
        self._blocked[ip] = entry
        return entry

    def unblock(self, ip: str) -> dict:
        removed = self._blocked.pop(ip, None)
        return {"ip": ip, "removed": removed is not None, "simulated": True}

    def list_blocked(self) -> list[dict]:
        return list(self._blocked.values())

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked


# ──────────────────────────────────────────────────────────────────────────────
# Event store (log search)
# ──────────────────────────────────────────────────────────────────────────────
class EventStore(Protocol):
    async def search(self, *, source_ip: str | None, username: str | None,
                     event_type: str | None, hostname: str | None,
                     limit: int) -> list[dict]: ...


class InMemoryEventStore:
    def __init__(self, events: list[dict] | None = None):
        self._events = events or []

    async def search(self, *, source_ip=None, username=None, event_type=None,
                     hostname=None, limit=50) -> list[dict]:
        def ok(e: dict) -> bool:
            return (
                (source_ip is None or str(e.get("source_ip")) == source_ip)
                and (username is None or e.get("username") == username)
                and (event_type is None or e.get("event_type") == event_type)
                and (hostname is None or e.get("hostname") == hostname)
            )
        return [e for e in self._events if ok(e)][:limit]


class DBEventStore:
    """Queries the SecurityEvent table via an async session factory."""

    def __init__(self, session_factory: Callable[[], "Awaitable"]):
        self._session_factory = session_factory

    async def search(self, *, source_ip=None, username=None, event_type=None,
                     hostname=None, limit=50) -> list[dict]:
        from sqlalchemy import select
        from app.models.event import SecurityEvent

        async with self._session_factory() as session:
            q = select(SecurityEvent)
            if source_ip:
                q = q.where(SecurityEvent.source_ip == source_ip)
            if username:
                q = q.where(SecurityEvent.username == username)
            if event_type:
                q = q.where(SecurityEvent.event_type == event_type)
            if hostname:
                q = q.where(SecurityEvent.hostname == hostname)
            q = q.order_by(SecurityEvent.ingested_at.desc()).limit(limit)
            rows = (await session.execute(q)).scalars().all()
            return [
                {
                    "id": str(e.id), "event_type": e.event_type,
                    "source_ip": str(e.source_ip) if e.source_ip else None,
                    "dest_ip": str(e.dest_ip) if e.dest_ip else None,
                    "username": e.username, "hostname": e.hostname,
                    "severity": e.severity.value if e.severity else None,
                    "ingested_at": e.ingested_at.isoformat() if e.ingested_at else None,
                }
                for e in rows
            ]
