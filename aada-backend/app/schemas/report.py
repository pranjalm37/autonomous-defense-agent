import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.report import ReportType


class ReportListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_type: ReportType
    title: str
    summary: str | None
    incident_id: uuid.UUID | None
    alert_id: uuid.UUID | None
    created_at: datetime
