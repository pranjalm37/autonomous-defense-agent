import uuid

from pydantic import BaseModel, Field


class DetectionRunRequest(BaseModel):
    lookback_minutes: int = Field(60, ge=1, le=1440)
    limit: int = Field(5000, ge=1, le=50000)
    only_unprocessed: bool = True


class DetectionRunResult(BaseModel):
    events_analyzed: int
    detections: int
    alerts_created: int
    by_rule: dict[str, int]
    by_severity: dict[str, int]
    alert_ids: list[uuid.UUID]


class RuleInfo(BaseModel):
    rule_id: str
    name: str
    threat_type: str
    thresholds: dict[str, float | int]
