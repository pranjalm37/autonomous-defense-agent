"""
incidents — a correlated group of alerts that together represent one attack campaign.
While an alert is a single detection, an incident is the full story: lateral movement,
persistence, exfiltration. The AI agent creates and updates incidents automatically.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.action import Action
    from app.models.alert import Alert
    from app.models.report import Report
    from app.models.user import User


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class Incident(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    severity: Mapped[IncidentSeverity] = mapped_column(
        SAEnum(IncidentSeverity), nullable=False, index=True
    )
    status: Mapped[IncidentStatus] = mapped_column(
        SAEnum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN, index=True
    )

    # MITRE ATT&CK coverage
    mitre_tactics: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    mitre_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String))

    # AI-produced fields
    ai_summary: Mapped[str | None] = mapped_column(Text)
    attack_chain: Mapped[dict | None] = mapped_column(JSONB)   # ordered timeline of TTPs
    affected_assets: Mapped[dict | None] = mapped_column(JSONB)
    root_cause: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[str | None] = mapped_column(Text)

    # Timestamps for incident lifecycle
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    eradicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Ownership
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    # Relationships
    assigned_to: Mapped["User | None"] = relationship(
        "User", foreign_keys=[assigned_to_id], back_populates="assigned_incidents"
    )
    created_by: Mapped["User | None"] = relationship("User", foreign_keys=[created_by_id])
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="incident")
    actions: Mapped[list["Action"]] = relationship("Action", back_populates="incident")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="incident")

    def __repr__(self) -> str:
        return f"<Incident id={self.id} severity={self.severity} status={self.status}>"
