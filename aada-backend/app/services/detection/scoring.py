"""
Risk scoring & severity.

SOC alerting separates two ideas that beginners often conflate:

  - **Confidence** — how sure are we this is a true positive? (0.0–1.0)
  - **Severity**   — if real, how bad is it? (info → critical)

A high-confidence port scan is still only *medium* severity; a low-confidence
"possible domain-admin compromise" can still be *critical*. We combine both into
a single 0–100 **risk score** so the queue can be ranked, then derive a severity
band from that score.

Risk model (all bounded, then clamped to 0–100):

    risk = base(severity_signal)            # where the rule *starts*
         × confidence                       # discount uncertain detections
         × (1 + volume_factor)              # more evidence → higher risk
         × asset_factor                     # crown-jewel / external exposure
         + escalation_bonus                 # e.g. brute force that SUCCEEDED
"""
from __future__ import annotations

from app.models.alert import Severity

# Where a rule's signal strength starts on the 0–100 scale.
_BASE: dict[Severity, float] = {
    Severity.INFO: 10.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 45.0,
    Severity.HIGH: 65.0,
    Severity.CRITICAL: 80.0,
}

# Score band → severity label (used when a rule lets the score decide severity).
_BANDS: list[tuple[int, Severity]] = [
    (85, Severity.CRITICAL),
    (65, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
    (0,  Severity.INFO),
]


def compute_risk_score(
    base_severity: Severity,
    confidence: float,
    *,
    volume_factor: float = 0.0,   # 0..1 — how far over threshold (capped by caller)
    asset_factor: float = 1.0,    # 1.0 normal, >1 crown-jewel / external, <1 internal-noise
    escalation_bonus: float = 0.0,  # flat add for "the attack worked" signals
) -> int:
    confidence = _clamp(confidence, 0.0, 1.0)
    volume_factor = _clamp(volume_factor, 0.0, 1.0)
    asset_factor = _clamp(asset_factor, 0.5, 1.6)

    base = _BASE[base_severity]
    score = base * confidence * (1.0 + volume_factor) * asset_factor + escalation_bonus
    return int(round(_clamp(score, 0.0, 100.0)))


def severity_from_score(score: int) -> Severity:
    for threshold, sev in _BANDS:
        if score >= threshold:
            return sev
    return Severity.INFO


def over_threshold_factor(observed: int, threshold: int, *, saturation: int | None = None) -> float:
    """
    Map 'how far over the threshold' to a 0..1 volume factor.

    At exactly the threshold → 0.0. At `saturation` (default 4× threshold) or
    beyond → 1.0. Keeps a 1000-failure flood from scoring the same as a 6-failure
    one, without letting volume dominate the score.
    """
    if observed <= threshold:
        return 0.0
    saturation = saturation or threshold * 4
    span = max(saturation - threshold, 1)
    return _clamp((observed - threshold) / span, 0.0, 1.0)


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))
