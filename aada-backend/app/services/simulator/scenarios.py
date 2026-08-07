"""
Staged attack scenarios.

Each scenario emits data in a realistic on-the-wire format (raw syslog lines or
JSON event dicts) so a simulation exercises the *real* ingestion path — parsers,
then the normalizer — before detection ever sees it. Nothing here fabricates
internal objects or shortcuts the pipeline.

These mirror the fixtures in tests/attack_data.py, but anchor every timestamp to
the moment of the run: detection operates over a lookback window, so fixed
timestamps (which the tests rely on for deterministic windows) would fall outside
it and detect nothing.

Simulated records only. Generating a scenario performs no outbound network
activity and executes no remediation; it stages log data and lets the normal
pipeline react to it.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from app.schemas.event import LogFormat

C2_IP = "45.77.12.9"
BAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _ago(seconds: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def _syslog(ts: datetime) -> str:
    """sshd/sudo style prefix: 'Jan 10 13:55:36'."""
    return ts.strftime("%b %d %H:%M:%S")


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── generators ───────────────────────────────────────────────────────────────

def ssh_brute_force(ip: str = "185.220.101.34", host: str = "web01",
                    *, fails: int = 8) -> str:
    users = ["root", "admin", "oracle", "postgres", "test", "deploy", "ubuntu", "git"]
    lines = []
    for i in range(fails):
        ts = _ago(40 - i * 3)
        lines.append(
            f"{_syslog(ts)} {host} sshd[{12000 + i}]: Failed password for invalid user "
            f"{users[i % len(users)]} from {ip} port {54000 + i} ssh2"
        )
    lines.append(
        f"{_syslog(_ago(8))} {host} sshd[12099]: Accepted password for root "
        f"from {ip} port 54399 ssh2"
    )
    return "\n".join(lines)


def port_scan(ip: str = "203.0.113.66", host: str = "10.0.0.5", *, ports: int = 24) -> list[dict]:
    return [
        {"source": "firewall", "event_type": "connection_denied", "action": "deny",
         "timestamp": _iso(_ago(50 - i)), "src_ip": ip, "dst_ip": host,
         "dst_port": 1000 + i, "protocol": "tcp"}
        for i in range(ports)
    ]


def credential_stuffing(ip: str = "198.51.100.23", *, users: int = 18) -> list[dict]:
    return [
        {"source": "siem", "event_type": "login_failed", "severity": "medium",
         "timestamp": _iso(_ago(50 - i * 2)), "src_ip": ip,
         "user": f"user{i:03d}", "outcome": "failure"}
        for i in range(users)
    ]


def impossible_travel(user: str = "a.wren") -> list[dict]:
    """
    Same account authenticating from two continents minutes apart.

    Both addresses must be resolvable by the configured GeoResolver, or the rule
    has no coordinates to compare and stays silent. These two are in the offline
    table (Mountain View and Amsterdam, ~8,900 km) and are not used by any other
    scenario, so runs stay independent.
    """
    return [
        {"source": "cloud", "event_type": "login_success", "severity": "info",
         "timestamp": _iso(_ago(600)), "src_ip": "8.8.8.8",
         "user": user, "outcome": "success"},
        {"source": "cloud", "event_type": "login_success", "severity": "info",
         "timestamp": _iso(_ago(120)), "src_ip": "91.198.174.192",
         "user": user, "outcome": "success"},
    ]


def privilege_escalation(host: str = "web01", user: str = "jdoe") -> str:
    ts = _syslog(_ago(30))
    return (
        f"{ts} {host} sudo:   {user} : TTY=pts/1 ; PWD=/home/{user} ; "
        f"USER=root ; COMMAND=/bin/cat /etc/shadow"
    )


def malware_c2(host: str = "WIN-FINANCE-07") -> list[dict]:
    return [
        {"source": "edr", "event_type": "process_creation", "severity": "high",
         "timestamp": _iso(_ago(45)), "host": host, "user": "jdoe",
         "process": "powershell.exe", "parent_process": "winword.exe",
         "command_line": "powershell -enc SQBFAFgA"},
        {"source": "edr", "event_type": "file_quarantine", "timestamp": _iso(_ago(30)),
         "host": host, "user": "jdoe", "file_hash": BAD_HASH,
         "file_path": "C:\\Users\\jdoe\\Downloads\\invoice.scr"},
        {"source": "ids", "signature": "ET TROJAN Cobalt Strike Beacon",
         "severity": "critical", "timestamp": _iso(_ago(15)),
         "source.ip": host, "destination.ip": C2_IP, "destination.port": 443},
    ]


# ── registry ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    mitre: str
    fmt: LogFormat
    generate: Callable[[], str | list[dict]]
    expected_rule: str
    target: str = ""
    tags: list[str] = field(default_factory=list)


SCENARIOS: dict[str, Scenario] = {
    s.id: s for s in [
        Scenario(
            id="ssh_brute_force",
            name="SSH brute force",
            description="Eight failed logins from one source in under a minute, then a successful root login.",
            mitre="T1110.001",
            fmt=LogFormat.SSH,
            generate=ssh_brute_force,
            expected_rule="ssh_brute_force",
            target="185.220.101.34",
        ),
        Scenario(
            id="port_scan",
            name="Port scan",
            description="A single source probing two dozen ports on one host (vertical scan).",
            mitre="T1046",
            fmt=LogFormat.JSON,
            generate=port_scan,
            expected_rule="port_scan",
            target="203.0.113.66",
        ),
        Scenario(
            id="credential_stuffing",
            name="Credential stuffing",
            description="Failed logins spread across eighteen distinct usernames from one source.",
            mitre="T1110.004",
            fmt=LogFormat.JSON,
            generate=credential_stuffing,
            expected_rule="credential_stuffing",
            target="198.51.100.23",
        ),
        Scenario(
            id="impossible_travel",
            name="Impossible travel",
            description="One account authenticating from two distant regions minutes apart.",
            mitre="T1078",
            fmt=LogFormat.JSON,
            generate=impossible_travel,
            expected_rule="impossible_travel",
            target="a.wren",
            tags=["requires-geo"],
        ),
        Scenario(
            id="privilege_escalation",
            name="Privilege escalation",
            description="A sudo invocation reading /etc/shadow — credential dumping.",
            mitre="T1068",
            fmt=LogFormat.AUTH,
            generate=privilege_escalation,
            expected_rule="privilege_escalation",
            target="web01",
        ),
        Scenario(
            id="malware_c2",
            name="Malware / C2 beacon",
            description="Office spawning PowerShell, a known-bad hash, and a beacon to a flagged address.",
            mitre="T1071",
            fmt=LogFormat.JSON,
            generate=malware_c2,
            expected_rule="malware_indicators",
            target=C2_IP,
        ),
    ]
}


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]
