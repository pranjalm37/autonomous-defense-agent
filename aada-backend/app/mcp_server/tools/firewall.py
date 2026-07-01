"""
Tool: Firewall actions (block / unblock / list).

This is the one *state-changing* tool, so it is marked destructive and
requires_approval. By default it runs against the SimulatedFirewall (in-memory,
no real device). In production the same interface is backed by a real firewall
and the call is gated by the human-in-the-loop approval workflow: the agent
proposes the block, a human approves it, and only then does execution proceed.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.mcp_server.context import ToolContext, ToolResult
from app.mcp_server.registry import ToolSpec


class FirewallInput(BaseModel):
    action: Literal["block_ip", "unblock_ip", "list_blocked"]
    ip: str | None = Field(None, description="Target IP (required for block/unblock)")
    reason: str | None = Field(None, description="Justification, recorded with the rule")
    ttl_minutes: int | None = Field(None, ge=1, description="Auto-expire after N minutes")

    @model_validator(mode="after")
    def _need_ip(self):
        if self.action in ("block_ip", "unblock_ip") and not self.ip:
            raise ValueError(f"'ip' is required for action '{self.action}'")
        return self


async def handle(params: FirewallInput, ctx: ToolContext) -> ToolResult:
    fw = ctx.firewall
    if params.action == "block_ip":
        entry = fw.block(params.ip, params.reason or "blocked by AADA agent", params.ttl_minutes)
        return ToolResult(
            ok=True,
            summary=f"Blocked {params.ip}"
                    + (f" for {params.ttl_minutes} min" if params.ttl_minutes else "")
                    + " (simulated)",
            data={"action": "block_ip", "entry": entry},
        )
    if params.action == "unblock_ip":
        result = fw.unblock(params.ip)
        return ToolResult(
            ok=True,
            summary=f"{'Unblocked' if result['removed'] else 'No active block for'} {params.ip}",
            data={"action": "unblock_ip", **result},
        )
    # list_blocked
    blocked = fw.list_blocked()
    return ToolResult(
        ok=True,
        summary=f"{len(blocked)} IP(s) currently blocked",
        data={"action": "list_blocked", "blocked": blocked},
    )


SPEC = ToolSpec(
    name="firewall_action",
    description=(
        "Take a firewall action: block_ip, unblock_ip, or list_blocked. Blocking "
        "is destructive and requires human approval before it executes against a "
        "real device. Use block_ip to contain a confirmed-malicious source; always "
        "include a clear reason and prefer a ttl so blocks expire."
    ),
    input_model=FirewallInput,
    handler=handle,
    destructive=True,
    requires_approval=True,
)
