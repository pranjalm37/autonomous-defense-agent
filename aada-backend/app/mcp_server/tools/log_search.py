"""Tool: Log / event search."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.mcp_server.context import ToolContext, ToolResult
from app.mcp_server.registry import ToolSpec


class LogSearchInput(BaseModel):
    source_ip: str | None = Field(None, description="Filter by source IP")
    username: str | None = Field(None, description="Filter by username")
    event_type: str | None = Field(None, description="Filter by event type, e.g. ssh_login_failed")
    hostname: str | None = Field(None, description="Filter by hostname")
    limit: int = Field(50, ge=1, le=500)


async def handle(params: LogSearchInput, ctx: ToolContext) -> ToolResult:
    if not any([params.source_ip, params.username, params.event_type, params.hostname]):
        return ToolResult.fail("provide at least one filter (source_ip, username, event_type, hostname)")

    events = await ctx.event_store.search(
        source_ip=params.source_ip, username=params.username,
        event_type=params.event_type, hostname=params.hostname, limit=params.limit,
    )
    return ToolResult(
        ok=True,
        summary=f"Found {len(events)} matching log event(s)",
        data={"count": len(events), "events": events},
    )


SPEC = ToolSpec(
    name="log_search",
    description=(
        "Search ingested security events (logs) by source IP, username, event "
        "type, and/or hostname. Returns matching normalized events newest-first. "
        "Use this to pivot from an indicator to all related activity — e.g. find "
        "every event from a suspicious IP, or every failed login for a user."
    ),
    input_model=LogSearchInput,
    handler=handle,
)
