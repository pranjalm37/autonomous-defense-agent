"""
AI SOC analyst tests — offline (HeuristicLLMProvider), no API key needed.

Covers: prompt assembly (delimiters + evidence present), schema validity of the
output, IOC extraction grounded in evidence, MITRE mapping, calibrated risk →
severity, recommended-action shape, and the full RAG-grounded analyze() flow.
"""
from __future__ import annotations

import pytest

from app.models.alert import Severity
from app.services.ai_analyst import AISOCAnalyst
from app.services.ai_analyst.llm import HeuristicLLMProvider
from app.services.ai_analyst.prompts import SYSTEM_PROMPT, build_user_prompt
from app.services.ai_analyst.schemas import (
    AIAnalysis,
    AlertInput,
    AnalysisContext,
    EventInput,
)
from app.services.rag import build_pipeline
from app.services.rag.knowledge import load_all


def _ctx(**over) -> AnalysisContext:
    alert = AlertInput(
        title="SSH brute force succeeded after 6 failed logins from 203.0.113.66",
        description="Failure burst followed by success",
        severity="critical",
        threat_type="brute_force",
        source_ip="203.0.113.66",
        hostname="web01",
        affected_user="root",
        mitre_techniques=["T1110", "T1110.001", "T1078"],
        detection_rule="ssh_brute_force",
        rule_metadata={"risk_score": 92, "confidence": 0.97, "failed_count": 6},
    )
    events = [
        EventInput(event_type="ssh_login_failed", summary="Failed password for root",
                   source_ip="203.0.113.66", username="root", hostname="web01"),
        EventInput(event_type="ssh_login_success", summary="Accepted password for root",
                   source_ip="203.0.113.66", username="root", hostname="web01"),
    ]
    return AnalysisContext(alert=alert, events=events, rag_context=over.get("rag", ""))


# ── Prompts ───────────────────────────────────────────────────────────────────
def test_user_prompt_contains_sections_and_evidence():
    prompt = build_user_prompt(_ctx())
    assert "===== ALERT" in prompt
    assert "===== LOG EVENTS" in prompt
    assert "===== KNOWLEDGE-BASE CONTEXT" in prompt
    assert "203.0.113.66" in prompt           # evidence is embedded
    assert "ssh_login_success" in prompt


def test_system_prompt_encodes_grounding_and_safety():
    p = SYSTEM_PROMPT.lower()
    assert "only" in p and "evidence" in p     # grounding
    assert "requires_approval" in p or "approval" in p  # human-in-the-loop


# ── Output schema ─────────────────────────────────────────────────────────────
def test_analysis_is_schema_valid_and_complete():
    analysis = AISOCAnalyst().analyze(_ctx())
    assert isinstance(analysis, AIAnalysis)
    assert analysis.executive_summary and analysis.technical_analysis
    assert analysis.attack_narrative
    assert 0 <= analysis.risk_score <= 100
    assert 0.0 <= analysis.confidence <= 1.0
    assert isinstance(analysis.recommended_severity, Severity)


def test_high_risk_maps_to_high_severity():
    analysis = AISOCAnalyst().analyze(_ctx())
    assert analysis.risk_score >= 85
    assert analysis.recommended_severity == Severity.CRITICAL
    assert analysis.is_true_positive is True


def test_iocs_are_extracted_from_evidence():
    analysis = AISOCAnalyst().analyze(_ctx())
    assert "203.0.113.66" in analysis.iocs


def test_mitre_techniques_mapped_with_tactics():
    analysis = AISOCAnalyst().analyze(_ctx())
    ids = {t.technique_id for t in analysis.mitre_techniques}
    assert "T1110" in ids
    assert all(t.tactic for t in analysis.mitre_techniques)
    assert analysis.mitre_tactics


def test_recommended_actions_are_approval_gated():
    analysis = AISOCAnalyst().analyze(_ctx())
    assert analysis.recommended_actions
    blocking = [a for a in analysis.recommended_actions if a.action_type == "block_ip"]
    assert blocking, "brute force should recommend blocking the source IP"
    assert blocking[0].requires_approval is True
    assert blocking[0].rationale


def test_provider_name_recorded():
    analysis = AISOCAnalyst(llm=HeuristicLLMProvider()).analyze(_ctx())
    assert analysis.model == "heuristic:offline"


# ── End-to-end with real RAG context ──────────────────────────────────────────
def test_analyze_with_rag_context_records_citations():
    rag = build_pipeline(force_offline=True)
    rag.ingest(load_all())
    analyst = AISOCAnalyst(rag_pipeline=rag)

    # mimic what analyze_alert builds for the RAG query
    ctx = _ctx()
    ctx.rag_context = rag.build_context("brute force T1110 ssh failed login", top_k=3)
    assert ctx.rag_context                       # knowledge was retrieved
    analysis = analyst.analyze(ctx)
    assert analysis.references                    # citations carried into output


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
