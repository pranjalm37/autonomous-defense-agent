from pydantic import BaseModel, Field

from app.services.decision.schemas import DecisionMode


class DetectionSignalModel(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    threat_type: str | None = None
    severity: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)


class LLMSignalModel(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    is_true_positive: bool = True
    recommended_severity: str | None = None


class ThreatIntelSignalModel(BaseModel):
    malicious_score: int | None = None
    allowlisted: bool = False
    attributed_actors: list[str] = Field(default_factory=list)


class KnowledgeSignalModel(BaseModel):
    relevance: float = 0.0
    citations: list[str] = Field(default_factory=list)


class ActionProposalModel(BaseModel):
    title: str
    action_type: str
    target: str
    reversible: bool = True
    priority: str = "medium"
    rationale: str = ""


class AdHocDecisionRequest(BaseModel):
    mode: DecisionMode | None = None
    detection: DetectionSignalModel | None = None
    llm: LLMSignalModel | None = None
    threat_intel: ThreatIntelSignalModel | None = None
    knowledge: KnowledgeSignalModel | None = None
    actions: list[ActionProposalModel] = Field(default_factory=list)
