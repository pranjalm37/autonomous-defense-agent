"""
SSH Brute Force  —  MITRE T1110 / T1110.001

Concept
-------
Brute force = many authentication attempts against a *small* set of accounts
from one source, hoping to guess a password. The signature is **volume of
failures from a single source IP inside a short window**.

Threshold logic:  >= FAIL_THRESHOLD failed/invalid SSH auths from the same
source IP within WINDOW_SECONDS.

Escalation:  if that same IP later *succeeds*, the attack worked — promote to
critical and flag the compromised account. This "failure burst → success" shape
is the single highest-value SSH signal a SOC watches for.
"""
from __future__ import annotations

from collections.abc import Sequence

from app.models.alert import Severity
from app.services.detection import mitre, scoring
from app.services.detection.base import (
    BaseRule,
    Detection,
    distinct,
    field,
    group_by,
    is_external,
    max_in_window,
)

_FAIL_EVENTS = {"ssh_login_failed", "ssh_invalid_user"}
_SUCCESS_EVENTS = {"ssh_login_success"}


class SSHBruteForceRule(BaseRule):
    rule_id = "ssh_brute_force"
    name = "SSH Brute Force"
    threat_type = "brute_force"

    # ── Tunable thresholds ──
    FAIL_THRESHOLD = 5
    WINDOW_SECONDS = 60

    def evaluate(self, events: Sequence) -> list[Detection]:
        ssh = [e for e in events if field(e, "event_type") in _FAIL_EVENTS | _SUCCESS_EVENTS]
        detections: list[Detection] = []

        for src_ip, ip_events in group_by(ssh, lambda e: field(e, "source_ip")).items():
            failures = [e for e in ip_events if field(e, "event_type") in _FAIL_EVENTS]
            peak, window_events = max_in_window(failures, self.WINDOW_SECONDS)
            if peak < self.FAIL_THRESHOLD:
                continue

            successes = [e for e in ip_events if field(e, "event_type") in _SUCCESS_EVENTS]
            targeted_users = distinct(failures, lambda e: field(e, "username"))
            external = is_external(src_ip)

            # Confidence scales with how cleanly this matches the pattern.
            confidence = min(0.95, 0.6 + 0.05 * (peak - self.FAIL_THRESHOLD))
            base_sev = Severity.HIGH if external else Severity.MEDIUM
            escalation = 0.0
            compromised_user = None

            if successes:
                # Failure burst followed by success from the same IP = breach.
                base_sev = Severity.CRITICAL
                confidence = 0.97
                escalation = 15.0
                compromised_user = field(successes[-1], "username")

            score = scoring.compute_risk_score(
                base_sev, confidence,
                volume_factor=scoring.over_threshold_factor(peak, self.FAIL_THRESHOLD),
                asset_factor=1.25 if external else 1.0,
                escalation_bonus=escalation,
            )

            verb = "succeeded after" if successes else "detected:"
            detections.append(Detection(
                rule_id=self.rule_id,
                title=f"SSH brute force {verb} {peak} failed logins from {src_ip}",
                description=(
                    f"{peak} failed SSH authentications from {src_ip} within "
                    f"{self.WINDOW_SECONDS}s against {len(targeted_users)} account(s)."
                    + (f" Followed by a SUCCESSFUL login as '{compromised_user}' — "
                       "host is likely compromised." if successes else "")
                ),
                threat_type=self.threat_type,
                severity=Severity.CRITICAL if successes else scoring.severity_from_score(score),
                risk_score=score,
                confidence=round(confidence, 2),
                mitre_techniques=["T1110", "T1110.001"] + (["T1078"] if successes else []),
                mitre_tactics=mitre.tactics_for("T1110", "T1110.001", *(["T1078"] if successes else [])),
                source_ip=src_ip,
                hostname=field(window_events[0], "hostname") if window_events else None,
                affected_user=compromised_user or (sorted(targeted_users)[0] if targeted_users else None),
                evidence_event_ids=[getattr(e, "id", None) for e in (window_events + successes)],
                iocs={"source_ip": src_ip, "targeted_users": sorted(targeted_users)},
                metadata={
                    "failed_count": peak,
                    "window_seconds": self.WINDOW_SECONDS,
                    "distinct_users": len(targeted_users),
                    "succeeded": bool(successes),
                },
            ))
        return detections
