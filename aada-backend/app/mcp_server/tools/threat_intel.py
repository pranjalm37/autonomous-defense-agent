"""
Tool: Threat intelligence (aggregate indicator dossier).

A composite tool: given one indicator it fans out across reputation, geo, the
actor/campaign feed, and (if available) the RAG knowledge base, returning a single
enriched dossier. This is the kind of "one call, full picture" tool an agent
reaches for first when triaging an unfamiliar indicator.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from app.mcp_server.context import ToolContext, ToolResult
from app.mcp_server.registry import ToolSpec

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH = re.compile(r"^[a-fA-F0-9]{32,64}$")


def _classify(indicator: str) -> str:
    if _IP.match(indicator):
        return "ip"
    if _HASH.match(indicator):
        return "hash"
    if "." in indicator:
        return "domain"
    return "unknown"


class ThreatIntelInput(BaseModel):
    indicator: str = Field(description="IP, domain, or file hash to enrich")
    indicator_type: Literal["ip", "domain", "hash", "auto"] = "auto"


async def handle(params: ThreatIntelInput, ctx: ToolContext) -> ToolResult:
    itype = params.indicator_type
    if itype == "auto":
        itype = _classify(params.indicator)

    dossier: dict = {"indicator": params.indicator, "indicator_type": itype}

    # Reputation + geo only make sense for IPs.
    if itype == "ip":
        rep = ctx.reputation.lookup(params.indicator)
        dossier["reputation"] = {
            "score": rep.get("score"), "categories": rep.get("categories", []),
            "sources": rep.get("sources", []),
        }
        geo = ctx.geo.resolve(params.indicator)
        dossier["geo"] = (
            {"country": geo.country, "city": geo.city} if geo else None
        )

    # Actor / campaign attribution for any indicator type.
    actors = ctx.threat_feed.match_indicator(params.indicator)
    dossier["attributed_actors"] = [
        {
            "name": a["name"], "aliases": a.get("aliases", []),
            "motivation": a.get("motivation"),
            "mitre_techniques": a.get("mitre_techniques", []),
            "description": a.get("description"),
        }
        for a in actors
    ]

    # Optional knowledge-base context (MITRE/Sigma/IR) if RAG is wired.
    if ctx.rag is not None and actors:
        techniques = sorted({t for a in actors for t in a.get("mitre_techniques", [])})
        try:
            dossier["knowledge_context"] = ctx.rag.build_context(
                " ".join(techniques) or params.indicator, top_k=3, max_chars=1500)
        except Exception:
            dossier["knowledge_context"] = None

    actor_names = [a["name"] for a in actors]
    summary = (
        f"{params.indicator} ({itype}): "
        + (f"attributed to {', '.join(actor_names)}. " if actor_names else "no actor attribution. ")
        + (f"Reputation score {dossier.get('reputation', {}).get('score')}."
           if itype == "ip" else "")
    )
    return ToolResult(ok=True, summary=summary.strip(), data=dossier)


SPEC = ToolSpec(
    name="threat_intelligence",
    description=(
        "Enrich a single indicator (IP, domain, or file hash) into a full threat "
        "dossier: reputation, geolocation, attributed threat actors/campaigns with "
        "their MITRE techniques, and relevant knowledge-base context. Use this as "
        "the first step when triaging an unfamiliar indicator."
    ),
    input_model=ThreatIntelInput,
    handler=handle,
)
