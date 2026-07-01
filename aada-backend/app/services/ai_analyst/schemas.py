"""
AI SOC analyst — input context and the structured output contract.

The output schema is the most important design decision here. An LLM left to
free-text would produce prose a human must re-read and re-key into the system.
By forcing the model to fill a strict schema (via OpenAI structured outputs), we
get machine-actionable fields — a risk score we can rank, MITRE IDs we can pivot
on, recommended actions we can drop straight into the approval queue — while the
narrative fields (executive_summary, technical_analysis) stay human-readable.

Every field has a single, well-scoped purpose so the model knows exactly what to
put where, which sharply reduces rambling and hallucination.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field

from app.models.alert import Severity


# ──────────────────────────────────────────────────────────────────────────────
# Input context (assembled by the analyst, fed into the prompt)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class EventInput:
    event_type: str
    summary: str
    source_ip: str | None = None
    dest_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    severity: str | None = None
    timestamp: str | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class AlertInput:
    title: str
    description: str | None
    severity: str
    threat_type: str | None
    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = None
    affected_user: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    detection_rule: str | None = None
    rule_metadata: dict = field(default_factory=dict)


@dataclass
class AnalysisContext:
    alert: AlertInput
    events: list[EventInput] = field(default_factory=list)
    rag_context: str = ""           # retrieved knowledge-base text (cited)


# ──────────────────────────────────────────────────────────────────────────────
# Structured output (the model must return exactly this)
# ──────────────────────────────────────────────────────────────────────────────
class MitreTechnique(BaseModel):
    technique_id: str = Field(description="ATT&CK technique ID, e.g. T1110.001")
    name: str = Field(description="Technique name")
    tactic: str = Field(description="ATT&CK tactic, e.g. Credential Access")


class RecommendedAction(BaseModel):
    title: str = Field(description="Short imperative action, e.g. 'Block source IP'")
    action_type: Literal[
        "block_ip", "isolate_host", "disable_user", "kill_process",
        "quarantine_file", "revoke_session", "reset_password",
        "investigate", "monitor", "custom",
    ] = Field(description="Maps to the remediation action catalog")
    target: str = Field(description="What to act on (IP, host, user, file)")
    priority: Literal["immediate", "high", "medium", "low"]
    rationale: str = Field(description="Why this action, grounded in the evidence")
    reversible: bool = True
    requires_approval: bool = True


class AIAnalysis(BaseModel):
    # Triage verdict first — everything else is conditioned on it.
    is_true_positive: bool = Field(description="False if this is benign / a false positive")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the verdict")

    # Audience-tiered narrative
    executive_summary: str = Field(
        description="2-3 plain-language sentences for a non-technical manager")
    technical_analysis: str = Field(
        description="Detailed analyst-level reasoning citing specific evidence")
    attack_narrative: str = Field(
        description="Step-by-step account of what the attacker did/attempted")

    # Machine-actionable structure
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    risk_score: int = Field(ge=0, le=100, description="Overall risk 0-100")
    recommended_severity: Severity
    iocs: list[str] = Field(
        default_factory=list,
        description="Indicators (IPs, hashes, domains, users) found ONLY in the evidence")
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    references: list[str] = Field(
        default_factory=list, description="Knowledge-base citations actually used")

    # Bookkeeping (filled by the analyst, not the model)
    model: str | None = None
