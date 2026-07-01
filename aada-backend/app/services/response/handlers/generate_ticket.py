"""Action: Generate a tracking ticket. Reversible (close ticket). Safe by default."""
from __future__ import annotations

from app.models.action import ActionType
from app.services.response.framework import ActionContext, ActionHandler, ExecutionResult


class GenerateTicketHandler(ActionHandler):
    action_type = ActionType.GENERATE_TICKET
    reversible = True
    safe_default = True   # filing a ticket harms nothing → no approval needed

    async def execute(self, action, ctx: ActionContext) -> ExecutionResult:
        params = action.parameters or {}
        title = params.get("title") or action.target_value or "Security incident"
        body = action.ai_justification or params.get("body", "")
        severity = params.get("severity", "medium")
        if ctx.dry_run:
            return ExecutionResult(ok=True, summary=f"[dry-run] would file ticket '{title}'")
        ticket = await ctx.ticketing.create(title, body, severity)
        return ExecutionResult(ok=True, summary=f"Filed ticket {ticket['id']}",
                               output=ticket, rollback_token={"ticket_id": ticket["id"]})

    async def rollback(self, action, ctx: ActionContext) -> ExecutionResult:
        ticket_id = self._rollback_token(action).get("ticket_id")
        if not ticket_id:
            return ExecutionResult(ok=False, summary="no ticket id recorded", error="missing rollback token")
        result = await ctx.ticketing.close(ticket_id)
        return ExecutionResult(ok=True, summary=f"Closed ticket {ticket_id}", output=result)
