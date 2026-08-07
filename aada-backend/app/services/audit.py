"""
Audit logging — the immutable record of who (or what) did what.

The audit trail is the accountability backbone of an autonomous system: it must
answer, after the fact, *who or which agent took an action, when, from where, and
what changed*. Four classes of event are captured (the `category` facet):

    user        human actions      — login, register, approve, reject, comment
    ai          agent decisions    — AI analysis, decision-engine verdicts, detection runs
    remediation action execution   — execute / rollback of a remediation
    tool        MCP/tool calls     — detailed records live in `tool_logs`

`audit_logs` is append-only — never UPDATE/DELETE — so it is admissible for
compliance (SOC 2, ISO 27001) and forensic reconstruction.

`make_audit_log` is a pure factory (returns an unsaved row, sets the category from
the action verb) so it is unit-testable; callers add it to the session.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from app.models.audit_log import AuditLog
from app.models.user import User


class AuditAction:
    # user actions
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_REGISTER = "auth.register"
    ACTION_APPROVED = "action.approved"
    ACTION_REJECTED = "action.rejected"
    ACTION_COMMENTED = "action.commented"
    ACTION_ESCALATED = "action.escalated"
    # Staging a synthetic attack is a deliberate human act, so it is attributable.
    SIMULATION_RUN = "simulation.run"
    # ai decisions
    AI_ANALYSIS = "ai.analysis"
    AI_DECISION = "ai.decision"
    DETECTION_RUN = "detection.run"
    # remediation
    ACTION_EXECUTED = "action.executed"
    ACTION_ROLLED_BACK = "action.rolled_back"
    # tool calls
    TOOL_CALL = "tool.call"


# Exact verb → category, with a prefix fallback for anything new.
_CATEGORY: dict[str, str] = {
    AuditAction.AUTH_LOGIN: "user", AuditAction.AUTH_LOGIN_FAILED: "user",
    AuditAction.AUTH_REGISTER: "user",
    AuditAction.ACTION_APPROVED: "user", AuditAction.ACTION_REJECTED: "user",
    AuditAction.ACTION_COMMENTED: "user", AuditAction.ACTION_ESCALATED: "user",
    AuditAction.SIMULATION_RUN: "user",
    AuditAction.AI_ANALYSIS: "ai", AuditAction.AI_DECISION: "ai",
    AuditAction.DETECTION_RUN: "ai",
    AuditAction.ACTION_EXECUTED: "remediation", AuditAction.ACTION_ROLLED_BACK: "remediation",
    AuditAction.TOOL_CALL: "tool",
}
_PREFIX_CATEGORY = {"auth": "user", "ai": "ai", "detection": "ai", "tool": "tool",
                    "action": "remediation", "simulation": "user"}

CATEGORIES = ["user", "ai", "remediation", "tool", "system"]


def category_of(action: str) -> str:
    if action in _CATEGORY:
        return _CATEGORY[action]
    return _PREFIX_CATEGORY.get(action.split(".")[0], "system")


@dataclass
class AuditContext:
    user: User | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: uuid.UUID | None = None


def make_audit_log(
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | None = None,
    ctx: AuditContext | None = None,
    old_value: dict | None = None,
    new_value: dict | None = None,
    user_email: str | None = None,
) -> AuditLog:
    ctx = ctx or AuditContext()
    return AuditLog(
        user_id=ctx.user.id if ctx.user else None,
        user_email=(ctx.user.email if ctx.user else None) or user_email,  # denormalized for durability
        action=action,
        category=category_of(action),
        resource_type=resource_type,
        resource_id=resource_id,
        old_value=old_value,
        new_value=new_value,
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        request_id=ctx.request_id,
        created_at=datetime.now(timezone.utc),
    )


def record(db, **kwargs) -> AuditLog:
    """Build and stage an audit log on the session (committed by get_db)."""
    entry = make_audit_log(**kwargs)
    db.add(entry)
    return entry


def audit_context_from_request(request, user: User | None) -> AuditContext:
    """Extract actor + request metadata from a FastAPI Request."""
    req_id = None
    raw = request.headers.get("x-request-id") or getattr(getattr(request, "state", None), "request_id", None)
    if raw:
        try:
            req_id = uuid.UUID(str(raw))
        except (ValueError, TypeError):
            req_id = None
    return AuditContext(
        user=user,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        request_id=req_id,
    )
