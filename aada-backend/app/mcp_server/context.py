"""
ToolResult and ToolContext — the value tools return and the dependency bundle
they run against.

ToolContext is dependency injection for tools: every external system a tool needs
(reputation feed, CVE DB, geo resolver, threat feed, firewall, event store, RAG)
is supplied here. Production wires real/DB-backed providers; tests pass stubs.
The tool handlers never construct their own dependencies, which keeps them pure
and trivially testable.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.mcp_server.providers import (
    CVEDatabase,
    EventStore,
    FirewallBackend,
    InMemoryEventStore,
    ReputationFeed,
    SimulatedFirewall,
    ThreatIntelFeed,
)
from app.services.detection.geo import GeoResolver, StaticGeoResolver


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return {"ok": self.ok, "summary": self.summary, "data": self.data, "error": self.error}

    @classmethod
    def fail(cls, message: str) -> "ToolResult":
        return cls(ok=False, summary=message, error=message)


@dataclass
class ToolContext:
    reputation: ReputationFeed
    cve_db: CVEDatabase
    geo: GeoResolver
    threat_feed: ThreatIntelFeed
    firewall: FirewallBackend
    event_store: EventStore
    rag: Any = None                      # optional RAGPipeline for enrichment


def build_default_context(*, events: list[dict] | None = None) -> ToolContext:
    """Offline context: seeded feeds, simulated firewall, in-memory events."""
    return ToolContext(
        reputation=ReputationFeed.load(),
        cve_db=CVEDatabase.load(),
        geo=StaticGeoResolver(),
        threat_feed=ThreatIntelFeed.load(),
        firewall=SimulatedFirewall(),
        event_store=InMemoryEventStore(events or []),
    )


def build_app_context(session_factory: Callable | None = None) -> ToolContext:
    """Production context: DB-backed log search, seeded feeds, simulated firewall."""
    from app.mcp_server.providers import DBEventStore

    ctx = build_default_context()
    if session_factory is not None:
        ctx.event_store = DBEventStore(session_factory)
    try:
        from app.services.rag.pipeline import get_default_pipeline
        ctx.rag = get_default_pipeline()
    except Exception:
        ctx.rag = None
    return ctx
