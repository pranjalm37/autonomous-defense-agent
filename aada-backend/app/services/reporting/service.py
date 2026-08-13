"""
ReportingService — generate and persist incident reports from the database.

Loads an incident (or a single alert) with its alerts, source events, and actions,
maps them to the builder's input views, builds the IncidentReport, and stores it
as a `reports` row (content = the report JSON, summary = executive summary).
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.logging_config import get_logger
from app.models.action import Action
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.report import Report, ReportType
from app.services.reporting.builder import (
    ActionView,
    AlertView,
    EventView,
    IncidentBundle,
    ReportBuilder,
)
from app.services.reporting.schemas import IncidentReport

logger = get_logger(__name__)


class ReportingService:
    def __init__(self):
        self.builder = ReportBuilder()

    async def generate_for_incident(
        self, db: AsyncSession, incident_id: uuid.UUID, *, generated_by: uuid.UUID | None = None
    ) -> tuple[IncidentReport, Report]:
        incident = (await db.execute(
            select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
        if incident is None:
            raise NotFoundError("Incident", str(incident_id))

        alerts = list((await db.execute(
            select(Alert).where(Alert.incident_id == incident_id))).scalars().all())
        alert_ids = [a.id for a in alerts]
        events = list((await db.execute(
            select(SecurityEvent).where(SecurityEvent.alert_id.in_(alert_ids))
        )).scalars().all()) if alert_ids else []
        actions = list((await db.execute(
            select(Action).where(Action.incident_id == incident_id))).scalars().all())

        bundle = IncidentBundle(
            title=incident.title, severity=incident.severity.value, status=incident.status.value,
            created_at=incident.created_at,
            alerts=[self._alert_view(a) for a in alerts],
            events=[self._event_view(e) for e in events],
            actions=[self._action_view(a) for a in actions],
        )
        report = self.builder.build(bundle)
        row = self._persist(db, report, incident_id=incident_id, generated_by=generated_by)
        logger.info("report_generated", incident_id=str(incident_id), report_id=report.report_id)
        return report, row

    async def generate_for_alert(
        self, db: AsyncSession, alert_id: uuid.UUID, *, generated_by: uuid.UUID | None = None
    ) -> tuple[IncidentReport, Report]:
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
        if alert is None:
            raise NotFoundError("Alert", str(alert_id))
        events = list((await db.execute(
            select(SecurityEvent).where(SecurityEvent.alert_id == alert_id))).scalars().all())
        actions = list((await db.execute(
            select(Action).where(Action.alert_id == alert_id))).scalars().all())

        bundle = IncidentBundle(
            title=alert.title, severity=alert.severity.value, status=alert.status.value,
            created_at=alert.created_at,
            alerts=[self._alert_view(alert)],
            events=[self._event_view(e) for e in events],
            actions=[self._action_view(a) for a in actions],
        )
        report = self.builder.build(bundle)
        row = self._persist(db, report, alert_id=alert_id, generated_by=generated_by)
        return report, row

    # ── ORM → view mappers ──
    @staticmethod
    def _alert_view(a: Alert) -> AlertView:
        return AlertView(
            title=a.title, severity=a.severity.value, threat_type=a.threat_type,
            source_ip=str(a.source_ip) if a.source_ip else None,
            dest_ip=str(a.dest_ip) if a.dest_ip else None,
            hostname=a.hostname, affected_user=a.affected_user,
            mitre_techniques=list(a.mitre_techniques or []),
            iocs=a.iocs or {}, ai_analysis=a.ai_analysis, created_at=a.created_at,
        )

    @staticmethod
    def _event_view(e: SecurityEvent) -> EventView:
        np = e.normalized_payload or {}
        return EventView(
            event_type=e.event_type, summary=str(np.get("message") or e.event_type),
            source_ip=str(e.source_ip) if e.source_ip else None,
            hostname=e.hostname, username=e.username, timestamp=e.ingested_at,
        )

    @staticmethod
    def _action_view(a: Action) -> ActionView:
        return ActionView(
            action_type=a.action_type.value, target=a.target_value, status=a.status.value,
            ai_justification=a.ai_justification, executed_at=a.executed_at, created_at=a.created_at,
        )

    @staticmethod
    def _persist(db, report: IncidentReport, *, incident_id=None, alert_id=None, generated_by=None) -> Report:
        row = Report(
            report_type=ReportType.INCIDENT_REPORT,
            title=report.title,
            content=report.model_dump_json(),     # source-of-truth JSON
            summary=report.executive_summary,
            metadata_={"report_id": report.report_id, "metrics": report.metrics},
            incident_id=incident_id, alert_id=alert_id, generated_by_id=generated_by,
        )
        db.add(row)
        return row
