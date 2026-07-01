import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas._types import IPStr


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    action: str
    category: str
    resource_type: str
    resource_id: uuid.UUID | None
    user_id: uuid.UUID | None
    user_email: str | None
    old_value: dict | None
    new_value: dict | None
    ip_address: IPStr
    created_at: datetime


class AuditLogList(BaseModel):
    total: int
    items: list[AuditLogResponse]


class ToolLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tool_name: str
    status: str
    duration_ms: int | None
    error_message: str | None
    action_id: uuid.UUID | None
    executed_at: datetime


class TimelineEntry(BaseModel):
    source: str            # "audit" | "tool"
    timestamp: datetime
    actor: str | None
    label: str
    detail: dict | None = None


class AuditStats(BaseModel):
    total: int
    by_category: dict[str, int]
    by_action: dict[str, int]
    window_hours: int = Field(description="Look-back window the stats cover")
