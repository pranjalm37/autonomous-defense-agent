"""Rule registry — the ordered set of rules the engine runs."""
from __future__ import annotations

from app.services.detection.base import BaseRule
from app.services.detection.rules.credential_stuffing import CredentialStuffingRule
from app.services.detection.rules.impossible_travel import ImpossibleTravelRule
from app.services.detection.rules.malware_indicators import MalwareIndicatorRule
from app.services.detection.rules.port_scan import PortScanRule
from app.services.detection.rules.privilege_escalation import PrivilegeEscalationRule
from app.services.detection.rules.ssh_brute_force import SSHBruteForceRule


def default_rules() -> list[BaseRule]:
    """Fresh instances of every built-in rule, in evaluation order."""
    return [
        SSHBruteForceRule(),
        PortScanRule(),
        CredentialStuffingRule(),
        ImpossibleTravelRule(),
        PrivilegeEscalationRule(),
        MalwareIndicatorRule(),
    ]


__all__ = [
    "default_rules",
    "SSHBruteForceRule",
    "PortScanRule",
    "CredentialStuffingRule",
    "ImpossibleTravelRule",
    "PrivilegeEscalationRule",
    "MalwareIndicatorRule",
]
