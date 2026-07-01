"""
Decision-engine types.

The decision engine is the brain that sits ABOVE the other services. It does not
re-detect or re-analyze; it *fuses* their outputs into one risk + confidence score
and then applies an operating-mode policy to decide what — if anything — to do.

Inputs (one signal per upstream service; all optional so the engine degrades):
    DetectionSignal   from the rule-based detection engine
    LLMSignal         from the AI SOC analyst (AIAnalysis)
    ThreatIntelSignal from VirusTotal/AbuseIPDB enrichment
    KnowledgeSignal   from the RAG knowledge base

Output:
    Decision          fused risk_score + confidence_score + per-action dispositions
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field

from pydantic import BaseModel, Field


# ── Operating modes ───────────────────────────────────────────────────────────
class DecisionMode(str, enum.Enum):
    MONITOR = "monitor"        # observe only — never act, surface recommendations
    ASSISTED = "assisted"      # propose actions, require human approval (HITL)
    AUTONOMOUS = "autonomous"  # auto-execute safe/reversible actions within policy


# ── What the engine decides to do with each action ────────────────────────────
class Disposition(str, enum.Enum):
    AUTO_EXECUTE = "auto_execute"          # run now (autonomous, within policy)
    REQUIRE_APPROVAL = "require_approval"  # queue for a human
    ESCALATE = "escalate"                  # high-impact/irreversible → senior human
    MONITOR_ONLY = "monitor_only"          # record as advisory, take no action
    SUPPRESS = "suppress"                  # likely false positive — do nothing


class Verdict(str, enum.Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    FALSE_POSITIVE = "false_positive"


# ── Input signals (internal dataclasses) ──────────────────────────────────────
@dataclass
class DetectionSignal:
    risk_score: int            # 0-100
    confidence: float          # 0-1
    threat_type: str | None = None
    severity: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class LLMSignal:
    risk_score: int
    confidence: float
    is_true_positive: bool
    recommended_severity: str | None = None


@dataclass
class ThreatIntelSignal:
    malicious_score: int | None = None   # 0-100 (None = no intel)
    allowlisted: bool = False
    attributed_actors: list[str] = field(default_factory=list)


@dataclass
class KnowledgeSignal:
    relevance: float = 0.0               # top retrieval similarity, 0-1
    citations: list[str] = field(default_factory=list)


@dataclass
class ActionProposal:
    title: str
    action_type: str                     # block_ip, isolate_host, …
    target: str
    reversible: bool = True
    priority: str = "medium"
    rationale: str = ""


@dataclass
class DecisionInput:
    mode: DecisionMode
    actions: list[ActionProposal] = field(default_factory=list)
    detection: DetectionSignal | None = None
    llm: LLMSignal | None = None
    threat_intel: ThreatIntelSignal | None = None
    knowledge: KnowledgeSignal | None = None


# ── Thresholds (the knobs of the decision tree) ───────────────────────────────
@dataclass
class DecisionThresholds:
    min_confidence: float = 0.50   # autonomous won't act below this confidence
    act_risk_min: int = 45         # autonomous won't act below this risk
    auto_confidence: float = 0.80  # autonomous auto-exec needs ≥ this confidence
    auto_risk_min: int = 60        # …and ≥ this risk
    fp_risk_ceiling: int = 65      # never suppress as FP above this risk


# Action types safe to auto-execute in autonomous mode: cheap, reversible, low
# blast radius. Everything else (isolate a host, disable a user, delete a file)
# always routes to a human even in autonomous mode.
AUTONOMOUS_SAFE_ACTIONS = {
    "block_ip", "revoke_session", "quarantine_file", "monitor", "investigate",
}


# ── Output ────────────────────────────────────────────────────────────────────
class ActionDecision(BaseModel):
    title: str
    action_type: str
    target: str
    disposition: Disposition
    reason: str


class Decision(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    confidence_score: float = Field(ge=0.0, le=1.0)
    verdict: Verdict
    mode: DecisionMode
    is_false_positive: bool
    requires_human: bool
    top_disposition: Disposition
    action_decisions: list[ActionDecision] = Field(default_factory=list)
    rationale: str = ""
    signal_breakdown: dict = Field(default_factory=dict)
