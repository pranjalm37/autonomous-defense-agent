"""
Approval workflow — the human-in-the-loop gate.

Every action starts PENDING. It cannot execute until it is APPROVED, by one of:
  - a human reviewer (approve/deny → records an Approval row), or
  - the auto-approval policy, for low-risk, reversible, inherently-safe actions
    (send_alert, generate_ticket, increase_logging).

Destructive actions (block_ip, disable_user, …) are NEVER auto-approved — they
always wait for a human. This is the core safety control: the agent proposes,
a human disposes.

These methods mutate the Action and return Approval rows for the caller to
persist; they perform no I/O, so the state machine is fully unit-testable.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.models.action import Action, ActionStatus, ActionType
from app.models.approval import Approval, ApprovalDecision

# Inherently safe actions eligible for auto-approval (still must be reversible
# and below the risk ceiling).
AUTO_APPROVABLE = {
    ActionType.SEND_ALERT, ActionType.GENERATE_TICKET, ActionType.INCREASE_LOGGING,
    ActionType.DECREASE_LOGGING,
}
AUTO_APPROVE_RISK_CEILING = 0.6   # risk_score is 0..1


class ApprovalError(Exception):
    pass


class ApprovalService:
    def can_auto_approve(self, action: Action) -> bool:
        return (
            action.action_type in AUTO_APPROVABLE
            and action.reversible
            and (action.risk_score or 0.0) < AUTO_APPROVE_RISK_CEILING
        )

    def auto_approve(self, action: Action) -> bool:
        """Approve in place if policy allows. Returns whether it was approved."""
        if action.status != ActionStatus.PENDING or not self.can_auto_approve(action):
            return False
        action.status = ActionStatus.APPROVED
        params = dict(action.parameters or {})
        params["_approval"] = {"by": "policy", "at": _now_iso()}
        action.parameters = params
        return True

    def approve(self, action: Action, reviewer_id: uuid.UUID, *, notes: str | None = None) -> Approval:
        if action.status not in (ActionStatus.PENDING,):
            raise ApprovalError(f"cannot approve an action in status '{action.status.value}'")
        action.status = ActionStatus.APPROVED
        return Approval(
            decision=ApprovalDecision.APPROVED, notes=notes,
            reviewed_at=_now(), action_id=action.id, reviewer_id=reviewer_id,
        )

    def deny(self, action: Action, reviewer_id: uuid.UUID, *, notes: str | None = None) -> Approval:
        if action.status not in (ActionStatus.PENDING,):
            raise ApprovalError(f"cannot deny an action in status '{action.status.value}'")
        action.status = ActionStatus.DENIED
        return Approval(
            decision=ApprovalDecision.DENIED, notes=notes,
            reviewed_at=_now(), action_id=action.id, reviewer_id=reviewer_id,
        )

    def escalate(self, action: Action, reviewer_id: uuid.UUID,
                 escalate_to_id: uuid.UUID, *, notes: str | None = None) -> Approval:
        # Stays PENDING; just records that it was escalated to a senior reviewer.
        return Approval(
            decision=ApprovalDecision.ESCALATED, notes=notes, reviewed_at=_now(),
            action_id=action.id, reviewer_id=reviewer_id, escalated_to_id=escalate_to_id,
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()
