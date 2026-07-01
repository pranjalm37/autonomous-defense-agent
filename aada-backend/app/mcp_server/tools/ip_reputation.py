"""Tool: IP reputation lookup."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.mcp_server.context import ToolContext, ToolResult
from app.mcp_server.registry import ToolSpec


class IPReputationInput(BaseModel):
    ip: str = Field(description="IPv4/IPv6 address to look up, e.g. 203.0.113.66")


def _verdict(score: int | None) -> str:
    if score is None:
        return "unknown"
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "clean"


async def handle(params: IPReputationInput, ctx: ToolContext) -> ToolResult:
    rec = ctx.reputation.lookup(params.ip)
    score = rec.get("score")
    verdict = _verdict(score)
    geo = ctx.geo.resolve(params.ip)

    data = {
        "ip": params.ip,
        "reputation_score": score,        # 0 (clean) – 100 (malicious)
        "verdict": verdict,
        "categories": rec.get("categories", []),
        "sources": rec.get("sources", []),
        "notes": rec.get("notes"),
        "country": geo.country if geo else None,
    }
    summary = (
        f"{params.ip} is {verdict}"
        + (f" (score {score}/100; {', '.join(rec.get('categories', [])) or 'no categories'})"
           if score is not None else " — no reputation data on file")
    )
    return ToolResult(ok=True, summary=summary, data=data)


SPEC = ToolSpec(
    name="ip_reputation_lookup",
    description=(
        "Look up the threat reputation of an IP address. Returns a 0-100 malice "
        "score, a verdict (clean/suspicious/malicious), abuse categories, and the "
        "intel sources. Use this to triage a source or destination IP seen in an "
        "alert before deciding whether to block it."
    ),
    input_model=IPReputationInput,
    handler=handle,
)
