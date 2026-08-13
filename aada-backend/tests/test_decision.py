"""
Decision-engine tests — fusion math, false-positive suppression, and the
mode-driven policy tree. Pure (no DB); the engine's decide() is fully testable.
"""
from __future__ import annotations

import pytest

from app.services.decision import (
    ActionProposal,
    DecisionEngine,
    DecisionInput,
    DecisionMode,
    DetectionSignal,
    Disposition,
    KnowledgeSignal,
    LLMSignal,
    ThreatIntelSignal,
    Verdict,
    fusion,
)

ENGINE = DecisionEngine()


def _block_action(reversible=True):
    return ActionProposal(title="Block source IP", action_type="block_ip",
                          target="45.77.12.9", reversible=reversible, priority="high")


def _isolate_action():
    return ActionProposal(title="Isolate host", action_type="isolate_host",
                          target="web01", reversible=True, priority="high")


def _strong_input(mode, actions=None):
    """All sources agree this is a real, high-risk threat."""
    return DecisionInput(
        mode=mode,
        detection=DetectionSignal(risk_score=90, confidence=0.95, threat_type="malware"),
        llm=LLMSignal(risk_score=88, confidence=0.92, is_true_positive=True),
        threat_intel=ThreatIntelSignal(malicious_score=97, attributed_actors=["APT-DEMO-BEAR"]),
        knowledge=KnowledgeSignal(relevance=0.6, citations=["[mitre:T1071]"]),
        actions=actions if actions is not None else [_block_action()],
    )


# ── Fusion: risk scoring ──────────────────────────────────────────────────────
def test_fuse_risk_weighted_mean_with_corroboration_bump():
    inp = _strong_input(DecisionMode.MONITOR)
    risk = fusion.fuse_risk(inp)
    assert 88 <= risk <= 100        # all-high signals → high fused risk


def test_fuse_risk_degrades_with_missing_sources():
    inp = DecisionInput(mode=DecisionMode.MONITOR,
                        detection=DetectionSignal(risk_score=60, confidence=0.7))
    assert fusion.fuse_risk(inp) == 60   # single source → just that score


# ── Fusion: confidence & corroboration ────────────────────────────────────────
def test_confidence_rises_with_corroboration():
    lone = DecisionInput(mode=DecisionMode.MONITOR,
                         detection=DetectionSignal(risk_score=80, confidence=0.7))
    many = _strong_input(DecisionMode.MONITOR)
    assert fusion.fuse_confidence(many) > fusion.fuse_confidence(lone)
    assert fusion.corroborating_sources(many) >= 3


def test_disagreement_lowers_confidence():
    # Detector screams, LLM says benign, intel clean → low confidence.
    inp = DecisionInput(
        mode=DecisionMode.MONITOR,
        detection=DetectionSignal(risk_score=85, confidence=0.8),
        llm=LLMSignal(risk_score=20, confidence=0.6, is_true_positive=False),
        threat_intel=ThreatIntelSignal(malicious_score=5),
    )
    assert fusion.fuse_confidence(inp) < 0.6


# ── False positives ───────────────────────────────────────────────────────────
def test_false_positive_when_llm_says_benign_and_low_risk():
    inp = DecisionInput(
        mode=DecisionMode.AUTONOMOUS,
        detection=DetectionSignal(risk_score=30, confidence=0.5),
        llm=LLMSignal(risk_score=15, confidence=0.8, is_true_positive=False),
        threat_intel=ThreatIntelSignal(malicious_score=2),
        actions=[_block_action()],
    )
    d = ENGINE.decide(inp)
    assert d.is_false_positive
    assert d.verdict == Verdict.FALSE_POSITIVE
    assert d.top_disposition == Disposition.SUPPRESS


def test_high_risk_is_never_suppressed_as_false_positive():
    # Even with an LLM 'false positive' verdict, very high fused risk is not suppressed.
    inp = DecisionInput(
        mode=DecisionMode.AUTONOMOUS,
        detection=DetectionSignal(risk_score=95, confidence=0.95),
        llm=LLMSignal(risk_score=90, confidence=0.5, is_true_positive=False),
        threat_intel=ThreatIntelSignal(malicious_score=96),
        actions=[_block_action()],
    )
    d = ENGINE.decide(inp)
    assert not d.is_false_positive


# ── Modes ─────────────────────────────────────────────────────────────────────
def test_monitor_mode_never_acts():
    d = ENGINE.decide(_strong_input(DecisionMode.MONITOR))
    assert d.top_disposition == Disposition.MONITOR_ONLY
    assert all(a.disposition == Disposition.MONITOR_ONLY for a in d.action_decisions)


def test_assisted_mode_requires_approval():
    d = ENGINE.decide(_strong_input(DecisionMode.ASSISTED))
    assert d.top_disposition == Disposition.REQUIRE_APPROVAL
    assert d.requires_human
    assert all(a.disposition == Disposition.REQUIRE_APPROVAL for a in d.action_decisions)


def test_autonomous_auto_executes_safe_reversible_action():
    d = ENGINE.decide(_strong_input(DecisionMode.AUTONOMOUS, actions=[_block_action()]))
    assert d.verdict == Verdict.MALICIOUS
    assert d.action_decisions[0].disposition == Disposition.AUTO_EXECUTE


def test_autonomous_escalates_high_impact_action():
    d = ENGINE.decide(_strong_input(DecisionMode.AUTONOMOUS, actions=[_isolate_action()]))
    # isolate_host is not in the autonomous-safe set → human required even here.
    assert d.action_decisions[0].disposition == Disposition.ESCALATE
    assert d.requires_human


def test_autonomous_irreversible_action_not_auto_executed():
    d = ENGINE.decide(_strong_input(DecisionMode.AUTONOMOUS, actions=[_block_action(reversible=False)]))
    assert d.action_decisions[0].disposition == Disposition.ESCALATE


def test_autonomous_low_confidence_monitors_instead_of_acting():
    inp = DecisionInput(
        mode=DecisionMode.AUTONOMOUS,
        detection=DetectionSignal(risk_score=70, confidence=0.5),  # lone, uncertain
        actions=[_block_action()],
    )
    d = ENGINE.decide(inp)
    # Single uncertain source → confidence below auto bar → monitor, don't act.
    assert d.action_decisions[0].disposition in (Disposition.MONITOR_ONLY, Disposition.REQUIRE_APPROVAL)
    assert d.action_decisions[0].disposition != Disposition.AUTO_EXECUTE


# ── Verdict & breakdown ───────────────────────────────────────────────────────
def test_verdict_bands_and_breakdown_present():
    d = ENGINE.decide(_strong_input(DecisionMode.MONITOR))
    assert d.verdict == Verdict.MALICIOUS
    assert d.signal_breakdown["corroborating_sources"] >= 3
    assert d.signal_breakdown["llm_risk"] == 88


def test_benign_when_all_low():
    inp = DecisionInput(
        mode=DecisionMode.ASSISTED,
        detection=DetectionSignal(risk_score=15, confidence=0.6),
        llm=LLMSignal(risk_score=10, confidence=0.7, is_true_positive=True),
    )
    d = ENGINE.decide(inp)
    assert d.verdict in (Verdict.BENIGN, Verdict.FALSE_POSITIVE)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
