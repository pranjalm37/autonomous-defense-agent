"""
Synthetic attack data — mock datasets that drive the attack-simulation tests.

Each generator returns input in a realistic on-the-wire format (raw syslog lines
or JSON event dicts) so the simulations exercise the *real* ingestion path
(parsers → normalizer) before detection, not pre-baked internal objects. This is
purple-team style: stage a known attack, assert the pipeline catches it.
"""
from __future__ import annotations

ATTACKER_IP = "203.0.113.66"
C2_IP = "45.77.12.9"
STUFFER_IP = "198.51.100.23"
INTERNAL_IP = "10.20.4.55"
BAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def ssh_brute_force(ip: str = ATTACKER_IP, host: str = "web01", *,
                    fails: int = 6, succeed: bool = True) -> str:
    """Raw sshd auth.log: a burst of failures, optionally ending in success."""
    lines = []
    sec = 36
    for i in range(fails):
        user = ["admin", "root", "oracle", "test", "postgres", "ubuntu"][i % 6]
        lines.append(
            f"Jan 10 13:55:{sec:02d} {host} sshd[{12000+i}]: "
            f"Failed password for invalid user {user} from {ip} port {54000+i} ssh2")
        sec += 1
    if succeed:
        lines.append(
            f"Jan 10 13:56:05 {host} sshd[12099]: "
            f"Accepted password for root from {ip} port 54099 ssh2")
    return "\n".join(lines)


def port_scan(ip: str = ATTACKER_IP, host: str = "10.0.0.5", *, ports: int = 20) -> list[dict]:
    """Firewall connection-denied events across many destination ports (vertical scan)."""
    return [
        {"source": "firewall", "event_type": "connection_denied", "action": "deny",
         "timestamp": f"2026-01-10T14:01:{i%60:02d}Z",
         "src_ip": ip, "dst_ip": host, "dst_port": 1000 + i, "protocol": "tcp"}
        for i in range(ports)
    ]


def credential_stuffing(ip: str = STUFFER_IP, *, users: int = 14) -> list[dict]:
    """Failed logins across many distinct usernames from one source (stuffing)."""
    return [
        {"source": "siem", "event_type": "login_failed", "severity": "medium",
         "timestamp": f"2026-01-10T14:05:{i%60:02d}Z",
         "src_ip": ip, "user": f"user{i:03d}", "outcome": "failure"}
        for i in range(users)
    ]


def malware_c2(host: str = "WIN-FINANCE-07") -> list[dict]:
    """EDR + IDS events: known-bad hash, Office→PowerShell, C2 beacon to bad IP."""
    return [
        {"source": "edr", "event_type": "process_creation", "severity": "high",
         "timestamp": "2026-01-10T14:03:51Z", "host": host, "user": "jdoe",
         "process": "powershell.exe", "parent_process": "winword.exe",
         "command_line": "powershell -enc SQBFAFgA"},
        {"source": "edr", "event_type": "file_quarantine", "host": host, "user": "jdoe",
         "file_hash": BAD_HASH, "file_path": "C:\\Users\\jdoe\\Downloads\\invoice.scr"},
        {"source": "ids", "signature": "ET TROJAN Cobalt Strike Beacon", "severity": "critical",
         "timestamp": "2026-01-10T14:04:10Z", "source.ip": host, "destination.ip": C2_IP,
         "destination.port": 443},
    ]


def privilege_escalation(host: str = "web01", user: str = "jdoe") -> str:
    """Raw auth.log: a sudo that reads the shadow file (credential dumping)."""
    return (
        f"Jan 10 14:06:31 {host} sudo:   {user} : TTY=pts/1 ; PWD=/home/{user} ; "
        f"USER=root ; COMMAND=/bin/cat /etc/shadow"
    )


def benign_traffic(host: str = "app01") -> list[dict]:
    """Normal activity that must NOT trip any detection (false-positive guard)."""
    return [
        {"source": "siem", "event_type": "login_success", "severity": "info",
         "timestamp": "2026-01-10T09:00:00Z", "src_ip": INTERNAL_IP, "user": "deploy"},
        {"source": "edr", "event_type": "process_creation", "host": host, "user": "deploy",
         "process": "chrome.exe", "parent_process": "explorer.exe",
         "command_line": "chrome.exe --new-window"},
    ]
