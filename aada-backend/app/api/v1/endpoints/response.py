"""
Response / remediation endpoints — the human approval workflow.

    GET  /response/actions                   list actions (filter by status) — the queue
    GET  /response/actions/{id}              full detail: decision history + comments
    POST /response/actions/{id}/approve      human approves → APPROVED   (audited)
    POST /response/actions/{id}/deny         human rejects → DENIED       (audited)
    POST /response/actions/{id}/comments     add a review comment         (audited)
    GET  /response/actions/{id}/comments     list the comment thread
    POST /response/actions/{id}/execute      run an APPROVED action       (audited)
    POST /response/actions/{id}/rollback     undo a COMPLETED action      (audited)

Approve/deny is the human-in-the-loop gate; execute refuses anything not APPROVED.
Every decision, comment, execution, and rollback writes an immutable AuditLog.
"""
from __future__ import annotations

import uuid
from functools import lru_cache

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import NotFoundError, ValidationError
from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.models.action import Action, ActionStatus
from app.models.action_comment import ActionComment
from app.models.user import User
from app.schemas.response import (
    ActionDetailResponse,
    ActionResponse,
    CommentRequest,
    CommentResponse,
    ExecutionResponse,
    ReviewRequest,
)
from app.services import audit
from app.services.audit import AuditAction
from app.services.response import ApprovalService, ResponseEngine, build_response_context
from app.services.response.approval import ApprovalError

router = APIRouter(prefix="/response", tags=["response"])


@lru_cache
def _engine() -> ResponseEngine:
    return ResponseEngine()


@lru_cache
def _context():
    return build_response_context()


_approvals = ApprovalService()


async def _load(db: AsyncSession, action_id: uuid.UUID, *, with_thread: bool = False) -> Action:
    q = select(Action).where(Action.id == action_id)
    if with_thread:
        q = q.options(selectinload(Action.approvals), selectinload(Action.comments))
    action = (await db.execute(q)).scalar_one_or_none()
    if action is None:
        raise NotFoundError("Action", str(action_id))
    return action


# ── Queue + detail ────────────────────────────────────────────────────────────
@router.get("/actions", response_model=list[ActionResponse])
async def list_actions(
    status: ActionStatus | None = Query(None),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[Action]:
    q = select(Action)
    if status:
        q = q.where(Action.status == status)
    q = q.order_by(Action.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.get("/actions/{action_id}", response_model=ActionDetailResponse)
async def get_action(
    action_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Action:
    return await _load(db, action_id, with_thread=True)


# ── Approve / reject ──────────────────────────────────────────────────────────
@router.post("/actions/{action_id}/approve", response_model=ActionResponse, status_code=201)
async def approve_action(
    action_id: uuid.UUID,
    body: ReviewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> Action:
    action = await _load(db, action_id)
    before = action.status.value
    try:
        approval = _approvals.approve(action, user.id, notes=body.notes)
    except ApprovalError as e:
        raise ValidationError(str(e))
    db.add(approval)
    audit.record(
        db, action=AuditAction.ACTION_APPROVED, resource_type="action", resource_id=action.id,
        ctx=audit.audit_context_from_request(request, user),
        old_value={"status": before}, new_value={"status": action.status.value, "notes": body.notes},
    )
    return action


@router.post("/actions/{action_id}/deny", response_model=ActionResponse, status_code=201)
async def deny_action(
    action_id: uuid.UUID,
    body: ReviewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> Action:
    action = await _load(db, action_id)
    before = action.status.value
    try:
        approval = _approvals.deny(action, user.id, notes=body.notes)
    except ApprovalError as e:
        raise ValidationError(str(e))
    db.add(approval)
    audit.record(
        db, action=AuditAction.ACTION_REJECTED, resource_type="action", resource_id=action.id,
        ctx=audit.audit_context_from_request(request, user),
        old_value={"status": before}, new_value={"status": action.status.value, "notes": body.notes},
    )
    return action


# ── Comments ──────────────────────────────────────────────────────────────────
@router.get("/actions/{action_id}/comments", response_model=list[CommentResponse])
async def list_comments(
    action_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[ActionComment]:
    await _load(db, action_id)   # 404 if missing
    rows = await db.execute(
        select(ActionComment).where(ActionComment.action_id == action_id)
        .order_by(ActionComment.created_at.asc())
    )
    return list(rows.scalars().all())


@router.post("/actions/{action_id}/comments", response_model=CommentResponse, status_code=201)
async def add_comment(
    action_id: uuid.UUID,
    body: CommentRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ActionComment:
    await _load(db, action_id)
    comment = ActionComment(
        body=body.body, action_id=action_id, user_id=user.id, author_email=user.email,
    )
    db.add(comment)
    audit.record(
        db, action=AuditAction.ACTION_COMMENTED, resource_type="action", resource_id=action_id,
        ctx=audit.audit_context_from_request(request, user),
        new_value={"comment": body.body[:500]},
    )
    await db.flush()
    return comment


# ── Execute / rollback ────────────────────────────────────────────────────────
@router.post("/actions/{action_id}/execute", response_model=ExecutionResponse, status_code=201)
async def execute_action(
    action_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> ExecutionResponse:
    action = await _load(db, action_id)
    before = action.status.value
    result, tool_log = await _engine().execute(action, _context(), executed_by=user.id)
    db.add(tool_log)
    audit.record(
        db, action=AuditAction.ACTION_EXECUTED, resource_type="action", resource_id=action.id,
        ctx=audit.audit_context_from_request(request, user),
        old_value={"status": before},
        new_value={"status": action.status.value, "ok": result.ok, "summary": result.summary},
    )
    return ExecutionResponse(ok=result.ok, summary=result.summary,
                             status=action.status, output=result.output, error=result.error)


@router.post("/actions/{action_id}/rollback", response_model=ExecutionResponse, status_code=201)
async def rollback_action(
    action_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> ExecutionResponse:
    action = await _load(db, action_id)
    before = action.status.value
    result, tool_log = await _engine().rollback(action, _context(), executed_by=user.id)
    db.add(tool_log)
    audit.record(
        db, action=AuditAction.ACTION_ROLLED_BACK, resource_type="action", resource_id=action.id,
        ctx=audit.audit_context_from_request(request, user),
        old_value={"status": before},
        new_value={"status": action.status.value, "ok": result.ok, "summary": result.summary},
    )
    return ExecutionResponse(ok=result.ok, summary=result.summary,
                             status=action.status, output=result.output, error=result.error)
