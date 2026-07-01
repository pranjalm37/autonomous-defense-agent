"""Action: Send alert (notify a channel). Not reversible — you can't unsend."""
from __future__ import annotations

from app.models.action import ActionType
from app.services.response.framework import ActionContext, ActionHandler, ExecutionResult


class SendAlertHandler(ActionHandler):
    action_type = ActionType.SEND_ALERT
    reversible = False
    safe_default = True   # notifying humans is inherently safe → no approval needed

    async def execute(self, action, ctx: ActionContext) -> ExecutionResult:
        params = action.parameters or {}
        channel = action.target_value or params.get("channel", "soc-alerts")
        subject = params.get("subject", "Security alert from AADA")
        body = action.ai_justification or params.get("body", "")
        if ctx.dry_run:
            return ExecutionResult(ok=True, summary=f"[dry-run] would alert {channel}")
        rec = await ctx.notifier.send(channel, subject, body)
        return ExecutionResult(ok=True, summary=f"Alert sent to {channel}", output=rec)

    async def rollback(self, action, ctx: ActionContext) -> ExecutionResult:
        # Best-effort retraction notice; the original message cannot be recalled.
        return ExecutionResult(ok=True, summary="notifications cannot be recalled; no rollback performed")
