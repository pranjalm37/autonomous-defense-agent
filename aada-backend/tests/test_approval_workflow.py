"""
Human approval workflow tests — audit logging, comments, and the approve→audit
flow. Offline: in-memory ORM objects, no DB.
"""
from __future__ import annotations

import uuid

from app.models.action import Action, ActionStatus, ActionType
from app.models.action_comment import ActionComment
from app.models.user import User
from app.services import audit
from app.services.audit import AuditAction, AuditContext
from app.services.response import ApprovalService


def _user():
    u = User(email="analyst@soc.io", username="analyst", full_name="A. Nalyst",
             hashed_password="x")
    u.id = uuid.uuid4()
    return u


def _action(status=ActionStatus.PENDING):
    a = Action(action_type=ActionType.BLOCK_IP, status=status, target_type="ip",
               target_value="45.77.12.9", reversible=True, risk_score=0.9, parameters={})
    a.id = uuid.uuid4()
    return a


# ── Audit factory ─────────────────────────────────────────────────────────────
def test_make_audit_log_captures_actor_and_change():
    user = _user()
    rid = uuid.uuid4()
    entry = audit.make_audit_log(
        action=AuditAction.ACTION_APPROVED, resource_type="action", resource_id=rid,
        ctx=AuditContext(user=user, ip_address="10.0.0.9", user_agent="curl"),
        old_value={"status": "pending"}, new_value={"status": "approved"},
    )
    assert entry.action == "action.approved"
    assert entry.resource_id == rid
    assert entry.user_id == user.id
    assert entry.user_email == "analyst@soc.io"   # denormalized
    assert entry.old_value == {"status": "pending"}
    assert entry.new_value == {"status": "approved"}
    assert entry.ip_address == "10.0.0.9"
    assert entry.created_at is not None


def test_make_audit_log_without_user_is_system():
    entry = audit.make_audit_log(action="action.executed", resource_type="action")
    assert entry.user_id is None and entry.user_email is None


def test_audit_action_verbs_are_namespaced():
    for v in (AuditAction.ACTION_APPROVED, AuditAction.ACTION_REJECTED,
              AuditAction.ACTION_COMMENTED, AuditAction.ACTION_EXECUTED,
              AuditAction.ACTION_ROLLED_BACK):
        assert v.startswith("action.")


# ── Audit context extraction from a request ───────────────────────────────────
class _FakeReq:
    def __init__(self, headers, host):
        self.headers = headers
        self.client = type("c", (), {"host": host})()
        self.state = type("s", (), {})()


def test_audit_context_from_request_extracts_metadata():
    rid = uuid.uuid4()
    req = _FakeReq({"user-agent": "Mozilla", "x-request-id": str(rid)}, "203.0.113.5")
    ctx = audit.audit_context_from_request(req, _user())
    assert ctx.ip_address == "203.0.113.5"
    assert ctx.user_agent == "Mozilla"
    assert ctx.request_id == rid


def test_audit_context_tolerates_bad_request_id():
    req = _FakeReq({"x-request-id": "not-a-uuid"}, "1.2.3.4")
    ctx = audit.audit_context_from_request(req, None)
    assert ctx.request_id is None and ctx.user is None


# ── Comment model ─────────────────────────────────────────────────────────────
def test_action_comment_construction():
    a = _action()
    c = ActionComment(body="Looks like real C2 — approving.", action_id=a.id,
                      user_id=uuid.uuid4(), author_email="lead@soc.io")
    assert c.body.startswith("Looks like")
    assert c.author_email == "lead@soc.io"


# ── Approve → audit flow (the units the endpoint composes) ────────────────────
def test_approve_then_audit_records_transition():
    approvals = ApprovalService()
    user = _user()
    action = _action(ActionStatus.PENDING)
    before = action.status.value

    approval = approvals.approve(action, user.id, notes="confirmed malicious")
    assert action.status == ActionStatus.APPROVED
    assert approval.notes == "confirmed malicious"

    entry = audit.make_audit_log(
        action=AuditAction.ACTION_APPROVED, resource_type="action", resource_id=action.id,
        ctx=AuditContext(user=user), old_value={"status": before},
        new_value={"status": action.status.value},
    )
    assert entry.old_value["status"] == "pending"
    assert entry.new_value["status"] == "approved"


def test_reject_then_audit():
    approvals = ApprovalService()
    action = _action(ActionStatus.PENDING)
    approvals.deny(action, uuid.uuid4(), notes="false positive")
    assert action.status == ActionStatus.DENIED
    entry = audit.make_audit_log(action=AuditAction.ACTION_REJECTED, resource_type="action",
                                 resource_id=action.id, new_value={"status": "denied"})
    assert entry.action == "action.rejected"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
