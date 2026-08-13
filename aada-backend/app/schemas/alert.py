import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.alert import AlertStatus, Severity
from app.schemas._types import IPStr


class AlertCreate(BaseModel):
    title: str
    description: str | None = None
    severity: Severity
    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = None
    affected_user: str | None = None
    threat_type: str | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    ai_confidence: float | None = Field(None, ge=0.0, le=1.0)
    ai_reasoning: str | None = None


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    severity: Severity
    status: AlertStatus
    source_ip: IPStr
    dest_ip: IPStr
    hostname: str | None
    affected_user: str | None
    threat_type: str | None
    ai_confidence: float | None
    incident_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assigned_to_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    ai_reasoning: str | None = None


class AlertListResponse(BaseModel):
    total: int
    items: list[AlertResponse]
