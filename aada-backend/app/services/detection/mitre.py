"""
MITRE ATT&CK catalog (the subset this engine maps to).

ATT&CK is a knowledge base of adversary behavior organized as:
  - **Tactics**  — the attacker's goal / *why* (e.g. Credential Access, Discovery).
                   Identified TAxxxx. These are the columns of the ATT&CK matrix.
  - **Techniques** — *how* the goal is achieved (e.g. T1110 Brute Force).
                   Sub-techniques add a suffix (T1110.001 Password Guessing).

Tagging every alert with tactics + techniques lets a SOC:
  - see where on the kill chain an attack sits,
  - measure detection coverage ("which techniques can we see?"),
  - correlate alerts that belong to the same campaign.
"""
from __future__ import annotations

from dataclasses import dataclass


# ── Tactics ───────────────────────────────────────────────────────────────────
TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]   # tactic IDs this technique serves

    @property
    def url(self) -> str:
        base = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"


# ── Techniques referenced by the detection rules ──────────────────────────────
TECHNIQUES: dict[str, Technique] = {
    "T1595":     Technique("T1595", "Active Scanning", ("TA0043",)),
    "T1046":     Technique("T1046", "Network Service Discovery", ("TA0007",)),
    "T1110":     Technique("T1110", "Brute Force", ("TA0006",)),
    "T1110.001": Technique("T1110.001", "Brute Force: Password Guessing", ("TA0006",)),
    "T1110.003": Technique("T1110.003", "Brute Force: Password Spraying", ("TA0006",)),
    "T1110.004": Technique("T1110.004", "Brute Force: Credential Stuffing", ("TA0006",)),
    "T1078":     Technique("T1078", "Valid Accounts", ("TA0001", "TA0003", "TA0004", "TA0005")),
    "T1548":     Technique("T1548", "Abuse Elevation Control Mechanism", ("TA0004", "TA0005")),
    "T1548.003": Technique("T1548.003", "Sudo and Sudo Caching", ("TA0004", "TA0005")),
    "T1068":     Technique("T1068", "Exploitation for Privilege Escalation", ("TA0004",)),
    "T1204":     Technique("T1204", "User Execution", ("TA0002",)),
    "T1204.002": Technique("T1204.002", "User Execution: Malicious File", ("TA0002",)),
    "T1059":     Technique("T1059", "Command and Scripting Interpreter", ("TA0002",)),
    "T1059.001": Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", ("TA0002",)),
    "T1071":     Technique("T1071", "Application Layer Protocol", ("TA0011",)),
    "T1071.001": Technique("T1071.001", "Application Layer Protocol: Web Protocols", ("TA0011",)),
    "T1003":     Technique("T1003", "OS Credential Dumping", ("TA0006",)),
}


def tactics_for(*technique_ids: str) -> list[str]:
    """Return the de-duplicated set of tactic IDs covered by these techniques."""
    out: list[str] = []
    for tid in technique_ids:
        tech = TECHNIQUES.get(tid)
        if not tech:
            continue
        for ta in tech.tactics:
            if ta not in out:
                out.append(ta)
    return out


def describe(*technique_ids: str) -> list[dict]:
    """Human-readable expansion for reports / API responses."""
    result = []
    for tid in technique_ids:
        t = TECHNIQUES.get(tid)
        if t:
            result.append({
                "id": t.id,
                "name": t.name,
                "tactics": [{"id": ta, "name": TACTICS.get(ta, ta)} for ta in t.tactics],
                "url": t.url,
            })
    return result
