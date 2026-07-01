"""
Audit-logging system tests — the four event categories, category derivation, and
the audit-log factory. Offline; no DB.
"""
from __future__ import annotations

import uuid

from app.services import audit
from app.services.audit import AuditAction, AuditContext, category_of


# ── Category derivation (the four classes the brief asks us to log) ────────────
def test_user_actions_categorized():
    for v in (AuditAction.AUTH_LOGIN, AuditAction.AUTH_REGISTER,
              AuditAction.ACTION_APPROVED, AuditAction.ACTION_REJECTED,
              AuditAction.ACTION_COMMENTED):
        assert category_of(v) == "user"


def test_ai_decisions_categorized():
    for v in (AuditAction.AI_ANALYSIS, AuditAction.AI_DECISION, AuditAction.DETECTION_RUN):
        assert category_of(v) == "ai"


def test_remediation_categorized():
    assert category_of(AuditAction.ACTION_EXECUTED) == "remediation"
    assert category_of(AuditAction.ACTION_ROLLED_BACK) == "remediation"


def test_tool_calls_categorized():
    assert category_of(AuditAction.TOOL_CALL) == "tool"


def test_unknown_action_prefix_fallback():
    assert category_of("ai.something_new") == "ai"          # prefix fallback
    assert category_of("auth.logout") == "user"
    assert category_of("weird.event") == "system"


# ── Factory ───────────────────────────────────────────────────────────────────
class _User:
    def __init__(self):
        self.id = uuid.uuid4()
        self.email = "analyst@soc.io"


def test_make_audit_log_sets_category_and_actor():
    user = _User()
    rid = uuid.uuid4()
    entry = audit.make_audit_log(
        action=AuditAction.AI_DECISION, resource_type="alert", resource_id=rid,
        ctx=AuditContext(user=user, ip_address="10.0.0.5"),
        new_value={"verdict": "malicious", "risk_score": 92},
    )
    assert entry.action == "ai.decision"
    assert entry.category == "ai"                  # derived from the verb
    assert entry.user_email == "analyst@soc.io"
    assert entry.resource_id == rid
    assert entry.ip_address == "10.0.0.5"
    assert entry.new_value["verdict"] == "malicious"
    assert entry.created_at is not None


def test_failed_login_records_email_without_user():
    entry = audit.make_audit_log(
        action=AuditAction.AUTH_LOGIN_FAILED, resource_type="user",
        ctx=AuditContext(user=None, ip_address="203.0.113.5"),
        user_email="attacker@evil.test", new_value={"reason": "invalid_credentials"},
    )
    assert entry.user_id is None
    assert entry.user_email == "attacker@evil.test"   # captured even with no user binding
    assert entry.category == "user"


def test_all_categories_known():
    for v in vars(AuditAction).values():
        if isinstance(v, str) and "." in v:
            assert category_of(v) in audit.CATEGORIES


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
