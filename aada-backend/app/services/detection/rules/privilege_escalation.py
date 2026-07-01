"""
Privilege Escalation  —  MITRE T1548 / T1548.003 (Sudo) / T1068 / T1003

Concept
-------
Privilege escalation is the attacker moving from a normal account to root/admin.
On Linux the highest-signal sources are sudo and su. We watch for two shapes:

  1. **Dangerous elevation** — a `sudo` to root that runs a sensitive command:
     reading /etc/shadow (credential dumping, T1003), editing sudoers, dropping a
     setuid bit, or spawning a root shell. Each is a single-event detection.

  2. **Root-access brute force** — repeated FAILED `su`/`sudo` attempts (guessing
     the root or a privileged password) above a threshold.

This rule is deliberately heuristic and command-aware: the *what* of the elevated
command matters as much as the *that* of the elevation.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from app.models.alert import Severity
from app.services.detection import mitre, scoring
from app.services.detection.base import (
    BaseRule, Detection, field, group_by, distinct,
)

# command → (label, extra technique). Order matters: first match wins.
_SENSITIVE = [
    (re.compile(r"/etc/shadow|/etc/gshadow", re.I),      ("read shadow file (credential dumping)", "T1003")),
    (re.compile(r"/etc/sudoers|visudo", re.I),           ("modify sudoers", "T1548.003")),
    (re.compile(r"chmod\s+(?:[ug]*\+s|4\d{3})", re.I),   ("set setuid bit", "T1548")),
    (re.compile(r"useradd|usermod|passwd\s+\w", re.I),   ("manipulate accounts", "T1078")),
    (re.compile(r"\b(?:nc|ncat|socat)\b", re.I),         ("launch network/reverse shell", "T1059")),
    (re.compile(r"(?:/bin/|/usr/bin/)?(?:bash|sh|zsh)\b", re.I), ("spawn a root shell", "T1059")),
]


class PrivilegeEscalationRule(BaseRule):
    rule_id = "privilege_escalation"
    name = "Privilege Escalation"
    threat_type = "privilege_escalation"

    # ── Tunable thresholds ──
    SU_FAIL_THRESHOLD = 3

    def evaluate(self, events: Sequence) -> list[Detection]:
        detections: list[Detection] = []
        detections += self._dangerous_sudo(events)
        detections += self._su_brute(events)
        return detections

    # ── 1. sensitive sudo-to-root commands ──
    def _dangerous_sudo(self, events: Sequence) -> list[Detection]:
        out: list[Detection] = []
        for e in events:
            if field(e, "event_type") != "sudo_command":
                continue
            target = (field(e, "target_user") or "").lower()
            command = field(e, "command") or ""
            if target != "root":
                continue

            label, extra_tech = None, None
            for pattern, (lbl, tech) in _SENSITIVE:
                if pattern.search(command):
                    label, extra_tech = lbl, tech
                    break
            if label is None:
                continue

            actor = field(e, "username")
            techs = ["T1548.003"] + ([extra_tech] if extra_tech and extra_tech != "T1548.003" else [])
            base_sev = Severity.CRITICAL if extra_tech == "T1003" else Severity.HIGH
            confidence = 0.85
            score = scoring.compute_risk_score(base_sev, confidence, asset_factor=1.2, escalation_bonus=8.0)

            out.append(Detection(
                rule_id=self.rule_id,
                title=f"Privileged sudo by '{actor}' — {label}",
                description=(
                    f"User '{actor}' ran a root sudo command that attempts to {label}: "
                    f"`{command[:200]}`. This is a high-risk elevation action."
                ),
                threat_type=self.threat_type,
                severity=base_sev,
                risk_score=score,
                confidence=confidence,
                mitre_techniques=techs,
                mitre_tactics=mitre.tactics_for(*techs),
                hostname=field(e, "hostname"),
                affected_user=actor,
                evidence_event_ids=[getattr(e, "id", None)],
                iocs={"command": command[:300]},
                metadata={"actor": actor, "target_user": "root", "category": label},
            ))
        return out

    # ── 2. repeated su/sudo failures (guessing the root password) ──
    def _su_brute(self, events: Sequence) -> list[Detection]:
        su_fail = [e for e in events if field(e, "event_type") in {"su_failed", "sudo_failed"}]
        out: list[Detection] = []
        for host, host_events in group_by(su_fail, lambda e: field(e, "hostname")).items():
            for actor, actor_events in group_by(host_events, lambda e: field(e, "username")).items():
                count = len(actor_events)
                if count < self.SU_FAIL_THRESHOLD:
                    continue
                confidence = min(0.9, 0.6 + 0.1 * (count - self.SU_FAIL_THRESHOLD))
                score = scoring.compute_risk_score(
                    Severity.HIGH, confidence,
                    volume_factor=scoring.over_threshold_factor(count, self.SU_FAIL_THRESHOLD),
                    asset_factor=1.15,
                )
                targets = distinct(actor_events, lambda e: field(e, "target_user"))
                out.append(Detection(
                    rule_id=self.rule_id,
                    title=f"Repeated privilege-escalation failures by '{actor}' on {host}",
                    description=(
                        f"'{actor}' failed su/sudo {count} times on {host} "
                        f"(targets: {', '.join(sorted(targets)) or 'root'}) — guessing a "
                        "privileged password."
                    ),
                    threat_type=self.threat_type,
                    severity=scoring.severity_from_score(score),
                    risk_score=score,
                    confidence=round(confidence, 2),
                    mitre_techniques=["T1548", "T1110"],
                    mitre_tactics=mitre.tactics_for("T1548", "T1110"),
                    hostname=host,
                    affected_user=actor,
                    evidence_event_ids=[getattr(e, "id", None) for e in actor_events],
                    iocs={"actor": actor, "target_users": sorted(targets)},
                    metadata={"fail_count": count, "host": host},
                ))
        return out
