"""
alerts — AI-analyzed threats derived from one or more raw events.
Sits between raw event ingestion and human-reviewed incidents.
Each alert carries the full AI reasoning chain and MITRE mapping.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.action import Action
    from app.models.event import SecurityEvent
    from app.models.incident import Incident
    from app.models.user import User


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ANALYZING = "analyzing"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False, index=True)
    status: Mapped[AlertStatus] = mapped_column(
        SAEnum(AlertStatus), nullable=False, default=AlertStatus.NEW, index=True
    )

    # Network context (denormalized from events for fast querying)
    source_ip: Mapped[str | None] = mapped_column(INET)
    dest_ip: Mapped[str | None] = mapped_column(INET)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    affected_user: Mapped[str | None] = mapped_column(String(255))
    threat_type: Mapped[str | None] = mapped_column(String(100), index=True)

    # MITRE ATT&CK
    mitre_tactics: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    mitre_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String))

    # AI analysis output
    ai_confidence: Mapped[float | None] = mapped_column(Float)         # 0.0 – 1.0
    ai_reasoning: Mapped[str | None] = mapped_column(Text)             # prose explanation
    ai_analysis: Mapped[dict | None] = mapped_column(JSONB)            # full structured output
    iocs: Mapped[dict | None] = mapped_column(JSONB)                   # IPs, hashes, domains
    affected_assets: Mapped[dict | None] = mapped_column(JSONB)

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # FKs
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    # Relationships
    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="alerts")
    assigned_to: Mapped["User | None"] = relationship(
        "User", foreign_keys=[assigned_to_id], back_populates="assigned_alerts"
    )
    source_events: Mapped[list["SecurityEvent"]] = relationship(
        "SecurityEvent", back_populates="alert"
    )
    actions: Mapped[list["Action"]] = relationship("Action", back_populates="alert")

    def __repr__(self) -> str:
        return f"<Alert id={self.id} severity={self.severity} status={self.status}>"
