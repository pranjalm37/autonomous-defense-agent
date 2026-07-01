from pydantic import BaseModel, Field


class EventInputModel(BaseModel):
    event_type: str
    summary: str
    source_ip: str | None = None
    dest_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    severity: str | None = None
    timestamp: str | None = None
    raw: dict = Field(default_factory=dict)


class AlertInputModel(BaseModel):
    title: str
    description: str | None = None
    severity: str = "medium"
    threat_type: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = None
    affected_user: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    detection_rule: str | None = None
    rule_metadata: dict = Field(default_factory=dict)


class AdHocAnalyzeRequest(BaseModel):
    """Analyze an alert that isn't (yet) in the database."""
    alert: AlertInputModel
    events: list[EventInputModel] = Field(default_factory=list)
    use_rag: bool = True
