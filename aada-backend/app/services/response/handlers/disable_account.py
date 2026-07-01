"""Action: Disable a user account. Reversible (re-enable). Guards protected accounts."""
from __future__ import annotations

from app.models.action import ActionType
from app.services.response.framework import (
    ActionContext, ActionHandler, ExecutionResult, GuardrailError,
)


class DisableAccountHandler(ActionHandler):
    action_type = ActionType.DISABLE_USER
    reversible = True
    safe_default = False   # locking a user out needs approval

    async def execute(self, action, ctx: ActionContext) -> ExecutionResult:
        user = action.target_value
        # Guardrail: never disable break-glass / privileged accounts automatically.
        if user in ctx.protected_accounts:
            raise GuardrailError(f"refusing to disable protected account '{user}'")
        if ctx.dry_run:
            return ExecutionResult(ok=True, summary=f"[dry-run] would disable {user}",
                                   rollback_token={"user": user})
        result = await ctx.directory.disable(user)
        return ExecutionResult(ok=True, summary=f"Disabled account '{user}'",
                               output=result, rollback_token={"user": user})

    async def rollback(self, action, ctx: ActionContext) -> ExecutionResult:
        user = self._rollback_token(action).get("user") or action.target_value
        result = await ctx.directory.enable(user)
        return ExecutionResult(ok=True, summary=f"Re-enabled account '{user}'", output=result)
