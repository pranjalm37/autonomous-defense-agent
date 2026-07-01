"""Tool: CVE search."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.mcp_server.context import ToolContext, ToolResult
from app.mcp_server.registry import ToolSpec


class CVESearchInput(BaseModel):
    query: str | None = Field(None, description="Free-text terms, e.g. 'log4j rce'")
    product: str | None = Field(None, description="Affected product, e.g. 'openssl'")
    cve_id: str | None = Field(None, description="Exact CVE id, e.g. CVE-2021-44228")
    max_results: int = Field(10, ge=1, le=50)


async def handle(params: CVESearchInput, ctx: ToolContext) -> ToolResult:
    if not any([params.query, params.product, params.cve_id]):
        return ToolResult.fail("provide at least one of: query, product, cve_id")

    results = ctx.cve_db.search(
        query=params.query, product=params.product,
        cve_id=params.cve_id, max_results=params.max_results,
    )
    summary = (
        f"Found {len(results)} CVE(s)"
        + (f": {', '.join(c['id'] for c in results[:5])}" if results else " matching the criteria")
    )
    return ToolResult(ok=True, summary=summary, data={"count": len(results), "results": results})


SPEC = ToolSpec(
    name="cve_search",
    description=(
        "Search the vulnerability database for CVEs by free-text query, affected "
        "product, or exact CVE id. Returns CVSS score, severity, description, and "
        "whether it is exploited in the wild. Use this to assess whether an alert "
        "or asset is tied to a known vulnerability."
    ),
    input_model=CVESearchInput,
    handler=handle,
)
