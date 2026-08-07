"""Request/response models for the attack simulator."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ScenarioInfo(BaseModel):
    """A staged attack the simulator can run."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str
    mitre: str
    format: str
    target: str
    expected_rule: str


class SimulationStage(BaseModel):
    """One pipeline stage that actually executed, with its timing."""
    stage: str
    detail: str
    ok: bool
    elapsed_ms: float


class SimulationResult(BaseModel):
    run_id: str
    scenario_id: str
    scenario_name: str
    events_ingested: int
    alerts_created: int
    alert_ids: list[str] = Field(default_factory=list)
    expected_rule: str
    expected_rule_fired: bool
    duration_ms: float
    stages: list[SimulationStage] = Field(default_factory=list)
