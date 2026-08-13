"""
Audit endpoints — read-only search over the immutable accountability trail.

The log is append-only; there is intentionally no create/update/delete API. Rows
are written by the workflow itself (app/services/audit.py). This module is the
*forensic console*:

    GET /audit/logs                         search audit_logs (text, category, dates)
    GET /audit/logs/{id}                    one entry
    GET /audit/tools                        search tool_logs (the tool-call trail)
    GET /audit/timeline/{rtype}/{rid}       merged chronological trail for a resource
    GET /audit/stats                        facet counts over a window

Search supports free-text `q` (actor / action / resource), category + action +
resource + user filters, a created_at date range, and pagination. Restricted to
analyst/admin — the audit trail is sensitive.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.dependencies import require_roles
from app.models.audit_log import AuditLog
from app.models.tool_log import ToolLog
from app.models.user import User
from app.schemas.audit import (
    AuditLogList,
    AuditLogResponse,
    AuditStats,
    TimelineEntry,
    ToolLogResponse,
)

router = APIRouter(prefix="/audit", tags=["audit"])
_GUARD = Depends(require_roles("analyst", "admin"))


@router.get("/logs", response_model=AuditLogList)
async def search_audit_logs(
    q: str | None = Query(None, description="Free-text over actor, action, resource"),
    category: str | None = Query(None, description="user | ai | remediation | tool | system"),
    action: str | None = Query(None),
    resource_type: str | None = Query(None),
    resource_id: uuid.UUID | None = Query(None),
    user_id: uuid.UUID | None = Query(None),
    date_from: datetime | None = Query(None),
    date_to: datetime | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = _GUARD,
) -> AuditLogList:
    filters = []
    if q:
        like = f"%{q}%"
        filters.append(or_(
            AuditLog.action.ilike(like),
            AuditLog.user_email.ilike(like),
            AuditLog.resource_type.ilike(like),
            cast(AuditLog.resource_id, String).ilike(like),
        ))
    if category:
        filters.append(AuditLog.category == category)
    if action:
        filters.append(AuditLog.action == action)
    if resource_type:
        filters.append(AuditLog.resource_type == resource_type)
    if resource_id:
        filters.append(AuditLog.resource_id == resource_id)
    if user_id:
        filters.append(AuditLog.user_id == user_id)
    if date_from:
        filters.append(AuditLog.created_at >= date_from)
    if date_to:
        filters.append(AuditLog.created_at <= date_to)

    base = select(AuditLog).where(*filters)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (await db.execute(
        base.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    )).scalars().all()
    return AuditLogList(total=total, items=list(rows))


@router.get("/logs/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: uuid.UUID, db: AsyncSession = Depends(get_db), _: User = _GUARD,
) -> AuditLog:
    row = (await db.execute(select(AuditLog).where(AuditLog.id == log_id))).scalar_one_or_none()
    if row is None:
        raise NotFoundError("AuditLog", str(log_id))
    return row


@router.get("/tools", response_model=list[ToolLogResponse])
async def search_tool_logs(
    tool_name: str | None = Query(None),
    status: str | None = Query(None),
    action_id: uuid.UUID | None = Query(None),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = _GUARD,
) -> list[ToolLog]:
    q = select(ToolLog)
    if tool_name:
        q = q.where(ToolLog.tool_name.ilike(f"%{tool_name}%"))
    if status:
        q = q.where(ToolLog.status == status)
    if action_id:
        q = q.where(ToolLog.action_id == action_id)
    rows = (await db.execute(q.order_by(ToolLog.executed_at.desc()).limit(limit))).scalars().all()
    return list(rows)


@router.get("/timeline/{resource_type}/{resource_id}", response_model=list[TimelineEntry])
async def resource_timeline(
    resource_type: str,
    resource_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = _GUARD,
) -> list[TimelineEntry]:
    """Full chronological trail for one resource — audit events plus, for actions,
    the underlying tool calls — merged into a single timeline."""
    entries: list[TimelineEntry] = []

    audits = (await db.execute(
        select(AuditLog)
        .where(AuditLog.resource_type == resource_type, AuditLog.resource_id == resource_id)
    )).scalars().all()
    for a in audits:
        entries.append(TimelineEntry(
            source="audit", timestamp=a.created_at, actor=a.user_email or "system",
            label=a.action, detail=a.new_value,
        ))

    if resource_type == "action":
        tools = (await db.execute(
            select(ToolLog).where(ToolLog.action_id == resource_id)
        )).scalars().all()
        for t in tools:
            entries.append(TimelineEntry(
                source="tool", timestamp=t.executed_at, actor=t.tool_name,
                label=f"tool.{t.status.value if hasattr(t.status, 'value') else t.status}",
                detail={"duration_ms": t.duration_ms, "error": t.error_message},
            ))

    entries.sort(key=lambda e: e.timestamp)
    return entries


@router.get("/stats", response_model=AuditStats)
async def audit_stats(
    window_hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    _: User = _GUARD,
) -> AuditStats:
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    base = select(AuditLog).where(AuditLog.created_at >= since)

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    by_cat = (await db.execute(
        select(AuditLog.category, func.count()).where(AuditLog.created_at >= since)
        .group_by(AuditLog.category)
    )).all()
    by_act = (await db.execute(
        select(AuditLog.action, func.count()).where(AuditLog.created_at >= since)
        .group_by(AuditLog.action)
    )).all()
    return AuditStats(
        total=total,
        by_category={c: n for c, n in by_cat},
        by_action={a: n for a, n in by_act},
        window_hours=window_hours,
    )
