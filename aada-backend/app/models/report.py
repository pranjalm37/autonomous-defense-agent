"""
reports — AI-authored narrative documents tied to alerts or incidents.
Types include technical incident reports, executive summaries, and
compliance exports. Stored as structured markdown with metadata sidebar.
"""
from __future__ import annotations
import uuid
import enum
from typing import TYPE_CHECKING
from sqlalchemy import String, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.alert import Alert
    from app.models.user import User


class ReportType(str, enum.Enum):
    INCIDENT_REPORT = "incident_report"
    EXECUTIVE_SUMMARY = "executive_summary"
    THREAT_ANALYSIS = "threat_analysis"
    COMPLIANCE = "compliance"
    FORENSIC = "forensic"


class Report(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "reports"

    report_type: Mapped[ReportType] = mapped_column(SAEnum(ReportType), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)   # AI-generated markdown
    summary: Mapped[str | None] = mapped_column(Text)            # TL;DR paragraph
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB)  # tags, version, etc.

    # FKs — a report belongs to either an incident or an alert (or both)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), index=True
    )
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    # Relationships
    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="reports")
    alert: Mapped["Alert | None"] = relationship("Alert")
    generated_by: Mapped["User | None"] = relationship("User")

    def __repr__(self) -> str:
        return f"<Report id={self.id} type={self.report_type} title={self.title[:40]}>"
