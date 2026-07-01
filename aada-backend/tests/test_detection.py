"""
Detection engine tests — a positive (should fire) and negative (should stay
quiet) case for every rule, plus risk-scoring and the full engine.

Events are built in-memory; no database is required. A tiny `Ev` stand-in mimics
the SecurityEvent attributes the rules read.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import Severity
from app.services.detection import DetectionEngine
from app.services.detection.base import Detection
from app.services.detection import scoring
from app.services.detection.geo import GeoPoint, StaticGeoResolver
from app.services.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.services.detection.rules.port_scan import PortScanRule
from app.services.detection.rules.credential_stuffing import CredentialStuffingRule
from app.services.detection.rules.impossible_travel import ImpossibleTravelRule
from app.services.detection.rules.privilege_escalation import PrivilegeEscalationRule
from app.services.detection.rules.malware_indicators import MalwareIndicatorRule

T0 = datetime(2026, 1, 10, 14, 0, 0, tzinfo=timezone.utc)


class Ev:
    """Minimal SecurityEvent stand-in."""
    _seq = 0

    def __init__(self, event_type, *, t=0, **fields):
        Ev._seq += 1
        self.id = Ev._seq
        self.event_type = event_type
        self.ingested_at = T0 + timedelta(seconds=t)
        self.created_at = self.ingested_at
        # Anything the rules look up lives in normalized_payload/raw_payload.
        self.normalized_payload = {"event_type": event_type, **fields}
        self.raw_payload = {"event_type": event_type, **fields}
        for k, v in fields.items():
            setattr(self, k, v)


# ── SSH brute force ───────────────────────────────────────────────────────────
def test_ssh_brute_force_fires():
    events = [Ev("ssh_login_failed", t=i * 2, source_ip="203.0.113.66",
                 username="root", hostname="web01") for i in range(6)]
    dets = SSHBruteForceRule().evaluate(events)
    assert len(dets) == 1
    assert dets[0].threat_type == "brute_force"
    assert "T1110" in dets[0].mitre_techniques


def test_ssh_brute_force_escalates_on_success():
    events = [Ev("ssh_login_failed", t=i, source_ip="203.0.113.66",
                 username="root", hostname="web01") for i in range(6)]
    events.append(Ev("ssh_login_success", t=30, source_ip="203.0.113.66",
                     username="root", hostname="web01"))
    det = SSHBruteForceRule().evaluate(events)[0]
    assert det.severity == Severity.CRITICAL
    assert "T1078" in det.mitre_techniques
    assert det.metadata["succeeded"] is True


def test_ssh_brute_force_below_threshold_quiet():
    events = [Ev("ssh_login_failed", t=i, source_ip="203.0.113.66", username="root")
              for i in range(3)]
    assert SSHBruteForceRule().evaluate(events) == []


# ── Port scan ─────────────────────────────────────────────────────────────────
def test_port_scan_vertical_fires():
    events = [Ev("connection_denied", t=i, source_ip="203.0.113.66",
                 dest_ip="10.0.0.5", dest_port=1000 + i) for i in range(20)]
    det = PortScanRule().evaluate(events)
    assert len(det) == 1
    assert det[0].metadata["scan_type"] in ("vertical", "block")
    assert "T1046" in det[0].mitre_techniques


def test_port_scan_few_ports_quiet():
    events = [Ev("connection_denied", t=i, source_ip="203.0.113.66",
                 dest_ip="10.0.0.5", dest_port=22) for i in range(20)]
    assert PortScanRule().evaluate(events) == []


# ── Credential stuffing ───────────────────────────────────────────────────────
def test_credential_stuffing_fires_on_many_users():
    events = [Ev("login_failed", t=i, source_ip="198.51.100.23",
                 username=f"user{i}") for i in range(12)]
    det = CredentialStuffingRule().evaluate(events)
    assert len(det) == 1
    assert det[0].metadata["distinct_users"] >= 10
    assert "T1110.004" in det[0].mitre_techniques


def test_credential_stuffing_ignores_single_user_bruteforce():
    # Many failures but ONE user → brute force, not stuffing.
    events = [Ev("login_failed", t=i, source_ip="198.51.100.23", username="admin")
              for i in range(15)]
    assert CredentialStuffingRule().evaluate(events) == []


# ── Impossible travel ─────────────────────────────────────────────────────────
def test_impossible_travel_fires():
    events = [
        Ev("ssh_login_success", t=0, source_ip="203.0.113.66", username="jdoe"),     # Moscow
        Ev("ssh_login_success", t=600, source_ip="8.8.8.8", username="jdoe"),         # California, 10 min later
    ]
    det = ImpossibleTravelRule().evaluate(events)
    assert len(det) == 1
    assert det[0].metadata["implied_speed_kmh"] > 900
    assert det[0].affected_user == "jdoe"


def test_impossible_travel_same_city_quiet():
    events = [
        Ev("ssh_login_success", t=0, source_ip="8.8.8.8", username="jdoe"),
        Ev("ssh_login_success", t=600, source_ip="104.16.0.1", username="jdoe"),  # both ~SF Bay
    ]
    assert ImpossibleTravelRule().evaluate(events) == []


def test_impossible_travel_internal_ips_quiet():
    events = [
        Ev("ssh_login_success", t=0, source_ip="10.0.0.5", username="jdoe"),
        Ev("ssh_login_success", t=60, source_ip="192.168.1.9", username="jdoe"),
    ]
    assert ImpossibleTravelRule().evaluate(events) == []


# ── Privilege escalation ──────────────────────────────────────────────────────
def test_priv_esc_shadow_read_is_critical():
    events = [Ev("sudo_command", t=0, username="jdoe", target_user="root",
                 hostname="web01", command="/bin/cat /etc/shadow")]
    det = PrivilegeEscalationRule().evaluate(events)
    assert len(det) == 1
    assert det[0].severity == Severity.CRITICAL
    assert "T1003" in det[0].mitre_techniques


def test_priv_esc_su_brute_fires():
    events = [Ev("su_failed", t=i, username="deploy", target_user="root", hostname="web01")
              for i in range(4)]
    det = PrivilegeEscalationRule().evaluate(events)
    assert any(d.metadata.get("fail_count", 0) >= 3 for d in det)


def test_priv_esc_benign_sudo_quiet():
    events = [Ev("sudo_command", t=0, username="deploy", target_user="root",
                 hostname="web01", command="/usr/bin/systemctl restart nginx")]
    assert PrivilegeEscalationRule().evaluate(events) == []


# ── Malware indicators ────────────────────────────────────────────────────────
def test_malware_known_hash_fires():
    bad = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    events = [Ev("file_quarantine", t=0, hostname="WIN-07", username="jdoe",
                 file_hash=bad, file_path="C:/Users/jdoe/invoice.scr")]
    det = MalwareIndicatorRule().evaluate(events)
    assert any(d.severity == Severity.CRITICAL for d in det)


def test_malware_office_spawns_shell_fires():
    events = [Ev("process_creation", t=0, hostname="WIN-07", username="jdoe",
                 parent_process="winword.exe", process="powershell.exe",
                 command_line="powershell -enc SQBFAFgA")]
    det = MalwareIndicatorRule().evaluate(events)
    techniques = {t for d in det for t in d.mitre_techniques}
    assert "T1059.001" in techniques or "T1204.002" in techniques


def test_malware_clean_process_quiet():
    events = [Ev("process_creation", t=0, hostname="WIN-07", username="jdoe",
                 parent_process="explorer.exe", process="chrome.exe",
                 command_line="chrome.exe --new-window")]
    assert MalwareIndicatorRule().evaluate(events) == []


# ── Scoring ───────────────────────────────────────────────────────────────────
def test_risk_score_monotonic_in_confidence():
    low = scoring.compute_risk_score(Severity.HIGH, 0.5)
    high = scoring.compute_risk_score(Severity.HIGH, 0.95)
    assert 0 <= low < high <= 100


def test_severity_from_score_bands():
    assert scoring.severity_from_score(90) == Severity.CRITICAL
    assert scoring.severity_from_score(70) == Severity.HIGH
    assert scoring.severity_from_score(45) == Severity.MEDIUM
    assert scoring.severity_from_score(10) == Severity.INFO


# ── Full engine ───────────────────────────────────────────────────────────────
def test_engine_runs_all_rules_and_sorts():
    events = [Ev("ssh_login_failed", t=i, source_ip="203.0.113.66", username="root")
              for i in range(6)]
    events += [Ev("connection_denied", t=i, source_ip="198.51.100.23",
                  dest_ip="10.0.0.5", dest_port=2000 + i) for i in range(20)]
    dets = DetectionEngine().analyze(events)
    assert len(dets) >= 2
    # sorted by risk_score descending
    assert dets == sorted(dets, key=lambda d: d.risk_score, reverse=True)


def test_engine_isolates_failing_rule():
    class Boom:
        rule_id = "boom"
        def evaluate(self, events):
            raise RuntimeError("kaboom")
    engine = DetectionEngine(rules=[Boom(), SSHBruteForceRule()])
    events = [Ev("ssh_login_failed", t=i, source_ip="203.0.113.66", username="root")
              for i in range(6)]
    # The exploding rule is swallowed; the good rule still produces a detection.
    assert len(engine.analyze(events)) == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
