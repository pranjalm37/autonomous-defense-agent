"""
Attack simulations — end-to-end, purple-team style.

Each test stages a known attack as raw logs / events, pushes it through the REAL
pipeline (ingestion parsers → normalizer → detection engine, then for one case the
AI analyst → decision engine), and asserts the system catches it with the right
verdict. A benign-traffic case guards against false positives.

These are the highest-value tests in the suite: they verify the components work
*together* on realistic adversary behavior, not just in isolation.
"""
from __future__ import annotations

import pytest

from app.schemas.event import LogFormat
from app.services.ingestion.parsers import get_parser
from app.services.ingestion import normalizer
from app.services.detection.engine import DetectionEngine
from tests import attack_data as atk


# ── ingestion helpers (use the real parsers + normalizer) ─────────────────────
def _ingest_raw(text: str, fmt: LogFormat):
    parser = get_parser(fmt)
    return [normalizer.normalize(r, default_source=parser.default_source)
            for r in parser.parse(text)]


def _ingest_json(events: list[dict]):
    import json
    parser = get_parser(LogFormat.JSON)
    return [normalizer.normalize(r, default_source=parser.default_source)
            for r in parser.parse(json.dumps(events))]


def _detect(events):
    return DetectionEngine().analyze(events)


def _rule_ids(detections):
    return {d.rule_id for d in detections}


# ── SSH brute force (raw auth.log → ingest → detect) ──────────────────────────
def test_ssh_brute_force_detected_end_to_end():
    events = _ingest_raw(atk.ssh_brute_force(fails=6, succeed=True), LogFormat.SSH)
    dets = _detect(events)
    assert "ssh_brute_force" in _rule_ids(dets)
    bf = next(d for d in dets if d.rule_id == "ssh_brute_force")
    assert bf.metadata["succeeded"] is True          # failure burst → success
    assert bf.severity.value == "critical"
    assert bf.source_ip == atk.ATTACKER_IP


def test_ssh_failures_below_threshold_quiet():
    events = _ingest_raw(atk.ssh_brute_force(fails=3, succeed=False), LogFormat.SSH)
    assert "ssh_brute_force" not in _rule_ids(_detect(events))


# ── Port scan ─────────────────────────────────────────────────────────────────
def test_port_scan_detected():
    events = _ingest_json(atk.port_scan(ports=20))
    dets = _detect(events)
    assert "port_scan" in _rule_ids(dets)


# ── Credential stuffing ───────────────────────────────────────────────────────
def test_credential_stuffing_detected():
    events = _ingest_json(atk.credential_stuffing(users=14))
    dets = _detect(events)
    assert "credential_stuffing" in _rule_ids(dets)
    cs = next(d for d in dets if d.rule_id == "credential_stuffing")
    assert cs.metadata["distinct_users"] >= 10


# ── Malware / C2 ──────────────────────────────────────────────────────────────
def test_malware_and_c2_detected():
    events = _ingest_json(atk.malware_c2())
    dets = _detect(events)
    assert "malware_indicators" in _rule_ids(dets)
    techniques = {t for d in dets for t in d.mitre_techniques}
    assert {"T1071", "T1204.002"} & techniques        # C2 and/or malicious file
    # the known-bad hash + C2 IP should surface critical findings
    assert any(d.severity.value == "critical" for d in dets if d.rule_id == "malware_indicators")


# ── Privilege escalation ──────────────────────────────────────────────────────
def test_privilege_escalation_detected():
    events = _ingest_raw(atk.privilege_escalation(), LogFormat.AUTH)
    dets = _detect(events)
    assert "privilege_escalation" in _rule_ids(dets)
    pe = next(d for d in dets if d.rule_id == "privilege_escalation")
    assert "T1003" in pe.mitre_techniques             # shadow read = credential dumping


# ── False-positive guard ──────────────────────────────────────────────────────
def test_benign_traffic_produces_no_detections():
    events = _ingest_json(atk.benign_traffic())
    assert _detect(events) == []


# ── Full chain: ingest → detect → analyze → decide ────────────────────────────
def test_full_pipeline_brute_force_to_decision():
    from app.services.ai_analyst import AISOCAnalyst
    from app.services.ai_analyst.schemas import AlertInput, AnalysisContext, EventInput
    from app.services.decision import (
        DecisionEngine as DecEngine, DecisionInput, DecisionMode,
        DetectionSignal, LLMSignal, ThreatIntelSignal, ActionProposal,
    )

    # 1. ingest + detect
    events = _ingest_raw(atk.ssh_brute_force(fails=6, succeed=True), LogFormat.SSH)
    det = next(d for d in _detect(events) if d.rule_id == "ssh_brute_force")

    # 2. AI analysis (offline heuristic provider)
    analyst = AISOCAnalyst()
    analysis = analyst.analyze(AnalysisContext(
        alert=AlertInput(title=det.title, description=det.description, severity=det.severity.value,
                         threat_type=det.threat_type, source_ip=det.source_ip,
                         mitre_techniques=det.mitre_techniques,
                         rule_metadata={"risk_score": det.risk_score, "confidence": det.confidence}),
        events=[EventInput(event_type="ssh_login_failed", summary="Failed password",
                           source_ip=det.source_ip)],
    ))
    assert analysis.is_true_positive

    # 3. fused decision (autonomous)
    decision = DecEngine().decide(DecisionInput(
        mode=DecisionMode.AUTONOMOUS,
        detection=DetectionSignal(risk_score=det.risk_score, confidence=det.confidence,
                                  threat_type=det.threat_type),
        llm=LLMSignal(risk_score=analysis.risk_score, confidence=analysis.confidence,
                      is_true_positive=analysis.is_true_positive),
        threat_intel=ThreatIntelSignal(malicious_score=97),
        actions=[ActionProposal(title="Block IP", action_type="block_ip",
                                target=det.source_ip, reversible=True)],
    ))
    assert decision.verdict.value in ("malicious", "suspicious")
    assert decision.action_decisions[0].disposition.value in ("auto_execute", "require_approval", "escalate")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
