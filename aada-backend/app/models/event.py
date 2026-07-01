"""
events — raw security telemetry ingested from SIEM / EDR / Firewall / IDS / Cloud.
Every alert must trace back to one or more source events (evidence chain).
"""
from __future__ import annotations
import uuid
import enum
from datetime import datetime
from typing import TYPE_CHECKING
from sqlalchemy import String, Text, Boolean, ForeignKey, DateTime, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.alert import Alert


class EventSource(str, enum.Enum):
    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    IDS = "ids"
    CLOUD = "cloud"
    ENDPOINT = "endpoint"
    MANUAL = "manual"


class EventSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "events"

    # Origin
    source: Mapped[EventSource] = mapped_column(SAEnum(EventSource), nullable=False, index=True)
    source_event_id: Mapped[str | None] = mapped_column(String(255), index=True)  # ID in originating system
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[EventSeverity] = mapped_column(
        SAEnum(EventSeverity), nullable=False, default=EventSeverity.INFO, index=True
    )

    # Payload
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    normalized_payload: Mapped[dict | None] = mapped_column(JSONB)  # vendor-agnostic after normalization

    # Network context
    source_ip: Mapped[str | None] = mapped_column(INET)
    dest_ip: Mapped[str | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column()
    dest_port: Mapped[int | None] = mapped_column()
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    user_agent: Mapped[str | None] = mapped_column(Text)

    # Processing state
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Link to alert (set after AI analysis)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), index=True
    )
    alert: Mapped["Alert | None"] = relationship("Alert", back_populates="source_events")

    def __repr__(self) -> str:
        return f"<SecurityEvent id={self.id} source={self.source} type={self.event_type}>"
