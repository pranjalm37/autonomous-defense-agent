"""Action: Increase logging verbosity on a target. Reversible (restore level)."""
from __future__ import annotations

from app.models.action import ActionType
from app.services.response.framework import ActionContext, ActionHandler, ExecutionResult


class IncreaseLoggingHandler(ActionHandler):
    action_type = ActionType.INCREASE_LOGGING
    reversible = True
    safe_default = True   # more telemetry is low-risk → no approval needed

    async def execute(self, action, ctx: ActionContext) -> ExecutionResult:
        target = action.target_value or "global"
        params = action.parameters or {}
        level = params.get("level", "debug")
        previous = await ctx.logging_ctrl.set_level(target, level)
        return ExecutionResult(
            ok=True,
            summary=f"Raised logging on {target}: {previous} → {level}",
            output={"target": target, "level": level, "previous": previous},
            rollback_token={"target": target, "previous": previous},
        )

    async def rollback(self, action, ctx: ActionContext) -> ExecutionResult:
        token = self._rollback_token(action)
        target = token.get("target") or action.target_value or "global"
        previous = token.get("previous", "info")
        await ctx.logging_ctrl.set_level(target, previous)
        return ExecutionResult(ok=True, summary=f"Restored logging on {target} → {previous}")
