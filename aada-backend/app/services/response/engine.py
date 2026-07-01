"""
ResponseEngine — executes approved actions and rolls them back.

It owns the Action status machine and produces a ToolLog for every attempt:

    PENDING ──approve──► APPROVED ──execute──► EXECUTING ──► COMPLETED ──rollback──► ROLLED_BACK
                                                         └─► FAILED

Safety controls enforced here:
  1. Approval gate     execute() refuses any action that is not APPROVED.
  2. Guardrails        a handler's GuardrailError aborts execution cleanly
                       (status FAILED, reason recorded) — nothing is performed.
  3. Idempotency       re-executing a COMPLETED action is a no-op.
  4. Rollback safety   rollback() only runs on a COMPLETED, reversible action and
                       uses the stored rollback token.
  5. Audit             every attempt yields a ToolLog (success/failure/skipped).

`execute`/`rollback` act on an Action instance and mutate it in place; the caller
(endpoint) persists. This keeps the engine DB-free and unit-testable.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from app.logging_config import get_logger
from app.models.action import Action, ActionStatus
from app.models.tool_log import ToolLog, ToolStatus
from app.services.response.framework import ActionContext, ExecutionResult, GuardrailError
from app.services.response.handlers import default_handlers

logger = get_logger(__name__)


class ResponseEngine:
    def __init__(self, handlers=None):
        self.handlers = handlers or default_handlers()

    async def execute(
        self, action: Action, ctx: ActionContext, *, executed_by: uuid.UUID | None = None
    ) -> tuple[ExecutionResult, ToolLog]:
        # 1. Approval gate.
        if action.status != ActionStatus.APPROVED:
            res = ExecutionResult(ok=False, summary="action is not approved",
                                  error=f"status is '{action.status.value}', expected 'approved'")
            return res, self._log(action, "execute", res, ToolStatus.SKIPPED, 0)

        handler = self.handlers.get(action.action_type)
        if handler is None:
            res = ExecutionResult(ok=False, summary="no handler", error=f"no handler for {action.action_type}")
            action.status = ActionStatus.FAILED
            action.error_message = res.error
            return res, self._log(action, "execute", res, ToolStatus.FAILURE, 0)

        action.status = ActionStatus.EXECUTING
        action.executed_at = _now()
        if executed_by is not None:
            action.executed_by_id = executed_by

        start = time.monotonic()
        try:
            res = await handler.execute(action, ctx)
        except GuardrailError as e:
            elapsed = _ms(start)
            action.status = ActionStatus.FAILED
            action.error_message = f"guardrail: {e}"
            res = ExecutionResult(ok=False, summary=f"blocked by safety guardrail: {e}", error=str(e))
            logger.warning("response_guardrail_block", action_type=action.action_type.value, reason=str(e))
            return res, self._log(action, "execute", res, ToolStatus.FAILURE, elapsed)
        except Exception as e:  # handler crash → FAILED, never half-applied silently
            elapsed = _ms(start)
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            res = ExecutionResult(ok=False, summary="handler error", error=str(e))
            logger.exception("response_handler_error", action_type=action.action_type.value)
            return res, self._log(action, "execute", res, ToolStatus.FAILURE, elapsed)

        elapsed = _ms(start)
        if res.ok:
            action.status = ActionStatus.COMPLETED
            action.completed_at = _now()
            if res.rollback_token is not None:
                action.parameters = {**(action.parameters or {}), "_rollback": res.rollback_token}
        else:
            action.status = ActionStatus.FAILED
            action.error_message = res.error

        logger.info("response_executed", action_type=action.action_type.value,
                    ok=res.ok, status=action.status.value, ms=elapsed)
        return res, self._log(action, "execute", res, ToolStatus.SUCCESS if res.ok else ToolStatus.FAILURE, elapsed)

    async def rollback(
        self, action: Action, ctx: ActionContext, *, executed_by: uuid.UUID | None = None
    ) -> tuple[ExecutionResult, ToolLog]:
        if action.status != ActionStatus.COMPLETED:
            res = ExecutionResult(ok=False, summary="only completed actions can be rolled back",
                                  error=f"status is '{action.status.value}'")
            return res, self._log(action, "rollback", res, ToolStatus.SKIPPED, 0)
        if not action.reversible:
            res = ExecutionResult(ok=False, summary="action is not reversible", error="not reversible")
            return res, self._log(action, "rollback", res, ToolStatus.SKIPPED, 0)

        handler = self.handlers.get(action.action_type)
        start = time.monotonic()
        try:
            res = await handler.rollback(action, ctx)
        except Exception as e:
            elapsed = _ms(start)
            res = ExecutionResult(ok=False, summary="rollback error", error=str(e))
            return res, self._log(action, "rollback", res, ToolStatus.FAILURE, elapsed)

        elapsed = _ms(start)
        if res.ok:
            action.status = ActionStatus.ROLLED_BACK
        logger.info("response_rolled_back", action_type=action.action_type.value, ok=res.ok, ms=elapsed)
        return res, self._log(action, "rollback", res, ToolStatus.SUCCESS if res.ok else ToolStatus.FAILURE, elapsed)

    # ── audit log ──
    @staticmethod
    def _log(action: Action, op: str, res: ExecutionResult, status: ToolStatus, ms: int) -> ToolLog:
        return ToolLog(
            tool_name=f"response.{op}.{action.action_type.value}",
            input_params={"target": action.target_value, "parameters": action.parameters},
            output=res.output or {"summary": res.summary, "error": res.error},
            status=status,
            error_message=res.error,
            duration_ms=ms,
            executed_at=_now(),
            created_at=_now(),
            action_id=getattr(action, "id", None),
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
