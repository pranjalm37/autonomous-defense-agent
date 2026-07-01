"""
Response-engine tests — action framework, approval state machine, execution,
rollback, and safety guardrails. Offline: in-memory Action objects + simulated
backends, no DB.
"""
from __future__ import annotations

import uuid

import pytest

from app.models.action import Action, ActionStatus, ActionType
from app.models.approval import ApprovalDecision
from app.models.tool_log import ToolStatus
from app.services.response import ApprovalService, ResponseEngine, build_response_context
from app.services.response.approval import ApprovalError

ENGINE = ResponseEngine()
APPROVALS = ApprovalService()


def _action(action_type, target, *, status=ActionStatus.APPROVED, reversible=True,
            risk=0.5, parameters=None):
    a = Action(
        action_type=action_type, status=status, target_type="x", target_value=target,
        reversible=reversible, risk_score=risk, parameters=parameters or {},
    )
    a.id = uuid.uuid4()
    return a


def _ctx():
    return build_response_context()


# ── Approval state machine ────────────────────────────────────────────────────
def test_human_approval_transitions_to_approved():
    a = _action(ActionType.BLOCK_IP, "45.77.12.9", status=ActionStatus.PENDING)
    reviewer = uuid.uuid4()
    approval = APPROVALS.approve(a, reviewer, notes="confirmed C2")
    assert a.status == ActionStatus.APPROVED
    assert approval.decision == ApprovalDecision.APPROVED
    assert approval.reviewer_id == reviewer


def test_deny_transitions_to_denied():
    a = _action(ActionType.DISABLE_USER, "jdoe", status=ActionStatus.PENDING)
    approval = APPROVALS.deny(a, uuid.uuid4(), notes="false positive")
    assert a.status == ActionStatus.DENIED
    assert approval.decision == ApprovalDecision.DENIED


def test_cannot_approve_non_pending():
    a = _action(ActionType.BLOCK_IP, "45.77.12.9", status=ActionStatus.COMPLETED)
    with pytest.raises(ApprovalError):
        APPROVALS.approve(a, uuid.uuid4())


def test_auto_approve_only_safe_reversible_low_risk():
    safe = _action(ActionType.GENERATE_TICKET, "incident", status=ActionStatus.PENDING, risk=0.2)
    assert APPROVALS.auto_approve(safe) is True
    assert safe.status == ActionStatus.APPROVED

    # Destructive action is never auto-approved.
    destructive = _action(ActionType.BLOCK_IP, "45.77.12.9", status=ActionStatus.PENDING, risk=0.2)
    assert APPROVALS.auto_approve(destructive) is False
    assert destructive.status == ActionStatus.PENDING

    # Safe but high-risk → not auto-approved.
    risky = _action(ActionType.INCREASE_LOGGING, "web01", status=ActionStatus.PENDING, risk=0.9)
    assert APPROVALS.auto_approve(risky) is False


# ── Execution gate ────────────────────────────────────────────────────────────
async def test_execute_refuses_unapproved_action():
    a = _action(ActionType.BLOCK_IP, "45.77.12.9", status=ActionStatus.PENDING)
    res, log = await ENGINE.execute(a, _ctx())
    assert res.ok is False
    assert a.status == ActionStatus.PENDING            # untouched
    assert log.status == ToolStatus.SKIPPED


# ── Send alert ────────────────────────────────────────────────────────────────
async def test_send_alert_executes():
    ctx = _ctx()
    a = _action(ActionType.SEND_ALERT, "soc-alerts", parameters={"subject": "Breach"})
    res, log = await ENGINE.execute(a, ctx, executed_by=uuid.uuid4())
    assert res.ok and a.status == ActionStatus.COMPLETED
    assert ctx.notifier.sent and ctx.notifier.sent[0]["channel"] == "soc-alerts"
    assert log.status == ToolStatus.SUCCESS


# ── Block IP + rollback ───────────────────────────────────────────────────────
async def test_block_ip_executes_and_rolls_back():
    ctx = _ctx()
    a = _action(ActionType.BLOCK_IP, "45.77.12.9")
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok and a.status == ActionStatus.COMPLETED
    assert ctx.firewall.is_blocked("45.77.12.9")
    assert a.parameters["_rollback"]["ip"] == "45.77.12.9"   # rollback token stored

    res2, log2 = await ENGINE.rollback(a, ctx)
    assert res2.ok and a.status == ActionStatus.ROLLED_BACK
    assert not ctx.firewall.is_blocked("45.77.12.9")
    assert log2.status == ToolStatus.SUCCESS


async def test_block_ip_guardrail_refuses_internal_ip():
    ctx = _ctx()
    a = _action(ActionType.BLOCK_IP, "10.0.0.5")           # private
    res, log = await ENGINE.execute(a, ctx)
    assert res.ok is False
    assert a.status == ActionStatus.FAILED
    assert "internal" in (a.error_message or "").lower() or "guardrail" in (a.error_message or "").lower()
    assert not ctx.firewall.is_blocked("10.0.0.5")          # nothing happened


async def test_block_ip_guardrail_refuses_allowlisted():
    ctx = _ctx()
    ctx.ip_allowlist.add("203.0.113.66")
    a = _action(ActionType.BLOCK_IP, "203.0.113.66")
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok is False and a.status == ActionStatus.FAILED


# ── Disable account + guardrail ───────────────────────────────────────────────
async def test_disable_account_executes_and_rolls_back():
    ctx = _ctx()
    a = _action(ActionType.DISABLE_USER, "mallory")
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok and ctx.directory.is_disabled("mallory")
    await ENGINE.rollback(a, ctx)
    assert not ctx.directory.is_disabled("mallory")
    assert a.status == ActionStatus.ROLLED_BACK


async def test_disable_account_guardrail_protects_admin():
    ctx = _ctx()
    a = _action(ActionType.DISABLE_USER, "admin")
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok is False and a.status == ActionStatus.FAILED
    assert not ctx.directory.is_disabled("admin")


# ── Generate ticket + rollback ────────────────────────────────────────────────
async def test_generate_ticket_and_close_on_rollback():
    ctx = _ctx()
    a = _action(ActionType.GENERATE_TICKET, "ransomware on web01",
                parameters={"severity": "high"})
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok
    tid = res.output["id"]
    assert ctx.ticketing.tickets[tid]["status"] == "open"
    await ENGINE.rollback(a, ctx)
    assert ctx.ticketing.tickets[tid]["status"] == "closed"


# ── Increase logging + restore ────────────────────────────────────────────────
async def test_increase_logging_and_restore():
    ctx = _ctx()
    assert await ctx.logging_ctrl.get_level("web01") == "info"
    a = _action(ActionType.INCREASE_LOGGING, "web01", parameters={"level": "debug"})
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok and await ctx.logging_ctrl.get_level("web01") == "debug"
    await ENGINE.rollback(a, ctx)
    assert await ctx.logging_ctrl.get_level("web01") == "info"   # restored


# ── Rollback safety ───────────────────────────────────────────────────────────
async def test_cannot_rollback_uncompleted_action():
    a = _action(ActionType.BLOCK_IP, "45.77.12.9", status=ActionStatus.APPROVED)
    res, log = await ENGINE.rollback(a, _ctx())
    assert res.ok is False and log.status == ToolStatus.SKIPPED


async def test_irreversible_action_not_rolled_back():
    ctx = _ctx()
    a = _action(ActionType.SEND_ALERT, "soc", reversible=False)
    await ENGINE.execute(a, ctx)
    assert a.status == ActionStatus.COMPLETED
    res, _ = await ENGINE.rollback(a, ctx)
    assert res.ok is False              # reversible=False → engine refuses


# ── End-to-end: approve → execute → rollback ──────────────────────────────────
async def test_full_lifecycle():
    ctx = _ctx()
    a = _action(ActionType.BLOCK_IP, "45.77.12.9", status=ActionStatus.PENDING)
    APPROVALS.approve(a, uuid.uuid4(), notes="confirmed malicious")
    assert a.status == ActionStatus.APPROVED
    res, _ = await ENGINE.execute(a, ctx)
    assert res.ok and a.status == ActionStatus.COMPLETED
    res2, _ = await ENGINE.rollback(a, ctx)
    assert res2.ok and a.status == ActionStatus.ROLLED_BACK


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
