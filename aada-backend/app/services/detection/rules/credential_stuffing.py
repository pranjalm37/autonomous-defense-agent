"""
Credential Stuffing  —  MITRE T1110.004 (and T1110.003 Password Spraying)

Concept
-------
The mirror image of brute force. Where brute force hammers a FEW accounts with
MANY guesses, credential stuffing replays MANY stolen username/password pairs —
so the tell is **high username cardinality with few attempts per account**.

    brute force         →  1 user,   500 passwords     (high attempts/user)
    credential stuffing →  500 users, 1–2 passwords     (low  attempts/user)
    password spraying   →  many users, 1 shared password

We trip when a single source fails auth against >= DISTINCT_USER_THRESHOLD
distinct usernames within the window, AND the average attempts/user stays low
(otherwise it's brute force and that rule owns it). Works across SSH, PAM, and
HTTP 401/403 — any normalized auth-failure event.
"""
from __future__ import annotations

from collections.abc import Sequence

from app.models.alert import Severity
from app.services.detection import mitre, scoring
from app.services.detection.base import (
    BaseRule, Detection, field, group_by, max_in_window, distinct, is_external,
)

_FAILURE_EVENTS = {
    "ssh_login_failed", "ssh_invalid_user", "pam_auth_failure", "login_failed",
}
_SUCCESS_EVENTS = {"ssh_login_success", "login_success", "console_login"}


def _is_auth_failure(e) -> bool:
    et = field(e, "event_type")
    if et in _FAILURE_EVENTS:
        return True
    # HTTP auth failures: 401 Unauthorized / 403 Forbidden on a login path.
    if et == "http_request":
        try:
            return int(field(e, "status_code", default=0)) in (401, 403)
        except (TypeError, ValueError):
            return False
    return False


def _is_auth_success(e) -> bool:
    et = field(e, "event_type")
    if et in _SUCCESS_EVENTS:
        return True
    if et == "http_request":
        try:
            return int(field(e, "status_code", default=0)) in (200, 302) and field(e, "username")
        except (TypeError, ValueError):
            return False
    return False


class CredentialStuffingRule(BaseRule):
    rule_id = "credential_stuffing"
    name = "Credential Stuffing / Password Spraying"
    threat_type = "credential_stuffing"

    # ── Tunable thresholds ──
    DISTINCT_USER_THRESHOLD = 10
    MAX_ATTEMPTS_PER_USER = 3      # above this it's brute force, not stuffing
    WINDOW_SECONDS = 300

    def evaluate(self, events: Sequence) -> list[Detection]:
        failures = [e for e in events if _is_auth_failure(e) and field(e, "source_ip")]
        successes = [e for e in events if _is_auth_success(e)]
        detections: list[Detection] = []

        for src_ip, ip_fail in group_by(failures, lambda e: field(e, "source_ip")).items():
            peak, window_events = max_in_window(ip_fail, self.WINDOW_SECONDS)
            users = distinct(window_events, lambda e: field(e, "username"))
            if len(users) < self.DISTINCT_USER_THRESHOLD:
                continue

            attempts_per_user = peak / max(len(users), 1)
            if attempts_per_user > self.MAX_ATTEMPTS_PER_USER:
                continue  # high attempts/user → brute force rule's territory

            # Did any of the targeted users then log in successfully from this IP?
            breached = [
                s for s in successes
                if field(s, "source_ip") == src_ip and field(s, "username") in users
            ]
            external = is_external(src_ip)
            confidence = min(0.93, 0.6 + 0.015 * (len(users) - self.DISTINCT_USER_THRESHOLD))
            base_sev = Severity.HIGH if external else Severity.MEDIUM
            escalation = 18.0 if breached else 0.0

            score = scoring.compute_risk_score(
                base_sev, confidence,
                volume_factor=scoring.over_threshold_factor(len(users), self.DISTINCT_USER_THRESHOLD),
                asset_factor=1.3 if external else 1.0,
                escalation_bonus=escalation,
            )

            detections.append(Detection(
                rule_id=self.rule_id,
                title=f"Credential stuffing from {src_ip} — {len(users)} accounts targeted"
                      + (" (BREACH)" if breached else ""),
                description=(
                    f"{src_ip} failed authentication against {len(users)} distinct accounts "
                    f"({attempts_per_user:.1f} attempts/account) in {self.WINDOW_SECONDS}s — "
                    "consistent with replay of stolen credentials."
                    + (f" {len(breached)} account(s) subsequently logged in successfully."
                       if breached else "")
                ),
                threat_type=self.threat_type,
                severity=Severity.CRITICAL if breached else scoring.severity_from_score(score),
                risk_score=score,
                confidence=round(confidence, 2),
                mitre_techniques=["T1110.004", "T1110.003"] + (["T1078"] if breached else []),
                mitre_tactics=mitre.tactics_for("T1110.004", *(["T1078"] if breached else [])),
                source_ip=src_ip,
                affected_user=field(breached[0], "username") if breached else None,
                evidence_event_ids=[getattr(e, "id", None) for e in (window_events + breached)],
                iocs={"source_ip": src_ip, "targeted_users": sorted(users)[:100]},
                metadata={
                    "distinct_users": len(users),
                    "attempts_per_user": round(attempts_per_user, 2),
                    "window_seconds": self.WINDOW_SECONDS,
                    "breached": bool(breached),
                },
            ))
        return detections
