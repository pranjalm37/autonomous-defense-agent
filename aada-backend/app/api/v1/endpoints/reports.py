"""
Incident-report endpoints.

    POST /reports/incidents/{id}/generate   build + persist a report for an incident
    POST /reports/alerts/{id}/generate      build + persist a report for one alert
    GET  /reports                           list generated reports
    GET  /reports/{id}                      fetch the structured report (JSON body)
    GET  /reports/{id}/export.json          download as JSON
    GET  /reports/{id}/export.pdf           download as PDF

Generation assembles the six sections from the incident's evidence and stores the
report JSON as the source of truth; the two export routes render that same JSON to
the requested format.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.models.report import Report
from app.models.user import User
from app.schemas.report import ReportListItem
from app.services.reporting import ReportingService, IncidentReport, to_json, to_pdf

router = APIRouter(prefix="/reports", tags=["reports"])
_service = ReportingService()


@router.post("/incidents/{incident_id}/generate", response_model=IncidentReport, status_code=201)
async def generate_for_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> IncidentReport:
    report, _ = await _service.generate_for_incident(db, incident_id, generated_by=user.id)
    return report


@router.post("/alerts/{alert_id}/generate", response_model=IncidentReport, status_code=201)
async def generate_for_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> IncidentReport:
    report, _ = await _service.generate_for_alert(db, alert_id, generated_by=user.id)
    return report


@router.get("", response_model=list[ReportListItem])
async def list_reports(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[Report]:
    rows = await db.execute(select(Report).order_by(Report.created_at.desc()).limit(limit))
    return list(rows.scalars().all())


async def _load_report(db: AsyncSession, report_id: uuid.UUID) -> IncidentReport:
    row = (await db.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
    if row is None:
        raise NotFoundError("Report", str(report_id))
    return IncidentReport.model_validate_json(row.content)


@router.get("/{report_id}", response_model=IncidentReport)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IncidentReport:
    return await _load_report(db, report_id)


@router.get("/{report_id}/export.json")
async def export_json(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    report = await _load_report(db, report_id)
    return Response(
        content=to_json(report), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{report.report_id}.json"'},
    )


@router.get("/{report_id}/export.pdf")
async def export_pdf(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    report = await _load_report(db, report_id)
    return Response(
        content=to_pdf(report), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report.report_id}.pdf"'},
    )
