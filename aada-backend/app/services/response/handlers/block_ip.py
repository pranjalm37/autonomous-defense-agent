"""Action: Block IP at the firewall. Reversible (unblock). Guarded against self-DoS."""
from __future__ import annotations

import ipaddress

from app.models.action import ActionType
from app.services.response.framework import (
    ActionContext, ActionHandler, ExecutionResult, GuardrailError,
)


class BlockIPHandler(ActionHandler):
    action_type = ActionType.BLOCK_IP
    reversible = True
    safe_default = False   # blocking traffic needs approval by default

    async def execute(self, action, ctx: ActionContext) -> ExecutionResult:
        ip = action.target_value
        self._guard(ip, ctx)
        if ctx.dry_run:
            return ExecutionResult(ok=True, summary=f"[dry-run] would block {ip}",
                                   rollback_token={"ip": ip})
        params = action.parameters or {}
        entry = ctx.firewall.block(ip, action.ai_justification or "AADA response engine",
                                   params.get("ttl_minutes"))
        return ExecutionResult(ok=True, summary=f"Blocked {ip}", output={"entry": entry},
                               rollback_token={"ip": ip})

    async def rollback(self, action, ctx: ActionContext) -> ExecutionResult:
        ip = self._rollback_token(action).get("ip") or action.target_value
        result = ctx.firewall.unblock(ip)
        return ExecutionResult(ok=True, summary=f"Unblocked {ip}", output=result)

    @staticmethod
    def _guard(ip: str, ctx: ActionContext) -> None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise GuardrailError(f"'{ip}' is not a valid IP address")
        # Never firewall-block our own infrastructure or allowlisted ranges —
        # a misfire here is a self-inflicted outage.
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise GuardrailError(f"refusing to block internal/private address {ip}")
        if ip in ctx.ip_allowlist:
            raise GuardrailError(f"{ip} is allowlisted — refusing to block")
