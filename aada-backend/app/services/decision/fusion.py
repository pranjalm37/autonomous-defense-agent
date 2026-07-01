"""
Signal fusion — turning four independent opinions into one risk + confidence.

Risk scoring
------------
Each source contributes a 0-100 risk. We take a WEIGHTED MEAN over whatever
signals are present (the engine degrades when a source is missing):

    detection 0.35   the deterministic rule said how bad the pattern is
    llm       0.40   the analyst reasoned over the full context (weighted highest)
    intel     0.25   external corroboration about the indicator

Agreement then nudges the score: when ≥2 sources independently land in the
high band, real risk is a touch higher than the mean (corroborated threats are
worse than the average suggests). Disagreement is NOT used to lower risk — it is
expressed as lower *confidence* instead.

Confidence scoring
------------------
Confidence answers "how sure are we?", and it is the main weapon against false
positives. It starts from the detector/LLM confidences and rises with
CORROBORATION — each *independent* source that agrees there's a real threat adds
confidence. A lone detector firing with nothing else to back it up stays
low-confidence, so autonomous mode won't act on it. Disagreement (one source
screams, another says benign) subtracts confidence.

False positives
---------------
A separate check looks for affirmative evidence the alert is benign: the LLM
analyst's false-positive verdict, an allowlisted/clean-reputation source, or
simply low-risk + low-confidence. We never suppress a high-risk alert as a false
positive (`fp_risk_ceiling`) — being wrong about "ignore this" is far costlier
than being wrong about "look at this."
"""
from __future__ import annotations

from app.services.decision.schemas import (
    DecisionInput, DecisionThresholds, KnowledgeSignal,
)

_W_DETECTION = 0.35
_W_LLM = 0.40
_W_INTEL = 0.25
_HIGH_BAND = 65


def fuse_risk(inp: DecisionInput) -> int:
    weighted: list[tuple[float, float]] = []
    if inp.detection is not None:
        weighted.append((inp.detection.risk_score, _W_DETECTION))
    if inp.llm is not None:
        weighted.append((inp.llm.risk_score, _W_LLM))
    if inp.threat_intel is not None and inp.threat_intel.malicious_score is not None:
        weighted.append((inp.threat_intel.malicious_score, _W_INTEL))

    if not weighted:
        return 0

    total_w = sum(w for _, w in weighted)
    mean = sum(r * w for r, w in weighted) / total_w

    # Corroboration bump: ≥2 sources independently in the high band.
    highs = [r for r, _ in weighted if r >= _HIGH_BAND]
    if len(highs) >= 2:
        mean = min(100.0, mean + 5.0 * (len(highs) - 1))

    return int(round(_clamp(mean, 0, 100)))


def corroborating_sources(inp: DecisionInput) -> int:
    """Count independent sources that affirmatively indicate a real threat."""
    n = 0
    if inp.detection is not None and inp.detection.risk_score >= 50:
        n += 1
    if inp.llm is not None and inp.llm.is_true_positive:
        n += 1
    if inp.threat_intel is not None and (inp.threat_intel.malicious_score or 0) >= 50:
        n += 1
    if inp.knowledge is not None and inp.knowledge.relevance >= 0.3:
        n += 1
    return n


def fuse_confidence(inp: DecisionInput) -> float:
    bases = [c for c in (
        inp.detection.confidence if inp.detection else None,
        inp.llm.confidence if inp.llm else None,
    ) if c is not None]
    base = sum(bases) / len(bases) if bases else 0.5

    # +confidence for each independent corroborating source beyond the first.
    boost = 0.06 * max(0, corroborating_sources(inp) - 1)
    if (inp.knowledge or KnowledgeSignal()).relevance >= 0.3:
        boost += 0.06

    # −confidence when sources disagree (wide spread of risk opinions, or the
    # LLM contradicts a loud detector).
    penalty = _disagreement_penalty(inp)

    return round(_clamp(base + boost - penalty, 0.05, 0.99), 2)


def _disagreement_penalty(inp: DecisionInput) -> float:
    risks = []
    if inp.detection is not None:
        risks.append(inp.detection.risk_score)
    if inp.llm is not None:
        risks.append(inp.llm.risk_score)
    if inp.threat_intel is not None and inp.threat_intel.malicious_score is not None:
        risks.append(inp.threat_intel.malicious_score)

    penalty = 0.0
    if len(risks) >= 2 and (max(risks) - min(risks)) >= 50:
        penalty += 0.15
    # LLM says benign while a detector screams → strong disagreement.
    if inp.llm is not None and not inp.llm.is_true_positive \
            and inp.detection is not None and inp.detection.risk_score >= _HIGH_BAND:
        penalty += 0.15
    return penalty


def assess_false_positive(
    inp: DecisionInput, fused_risk: int, fused_conf: float, th: DecisionThresholds
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if inp.llm is not None and not inp.llm.is_true_positive:
        reasons.append("AI analyst verdict: false positive")
    if inp.threat_intel is not None:
        if inp.threat_intel.allowlisted:
            reasons.append("source is allowlisted")
        elif inp.threat_intel.malicious_score is not None \
                and inp.threat_intel.malicious_score < 10 and fused_risk < 40:
            reasons.append("threat intel shows clean reputation")
    if fused_conf < 0.35 and fused_risk < 40:
        reasons.append("low confidence and low risk")

    # Never suppress a clearly high-risk alert, no matter the FP signals.
    is_fp = bool(reasons) and fused_risk < th.fp_risk_ceiling
    return is_fp, reasons


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))
