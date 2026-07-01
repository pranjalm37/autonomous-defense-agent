"""
SSH parser — sshd lines from /var/log/auth.log or /var/log/secure.

Extracts the security-relevant fields from the free-text message: outcome
(accepted / failed / invalid-user), the attempted username, and the source
IP/port. Lines that are not sshd are skipped silently.

Example lines handled:
    Jan 10 13:55:36 web01 sshd[12345]: Failed password for invalid user admin from 203.0.113.9 port 54321 ssh2
    Jan 10 13:55:40 web01 sshd[12345]: Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2
    Jan 10 13:55:42 web01 sshd[12346]: Invalid user oracle from 198.51.100.22 port 40123
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timezone

from app.models.event import EventSource
from app.services.ingestion.parsers.base import BaseParser

# syslog prefix:  "Mon DD HH:MM:SS host process[pid]: message"
_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_ACCEPTED = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?")


class SSHParser(BaseParser):
    default_source = EventSource.ENDPOINT

    def parse(self, content: str) -> Iterator[dict]:
        for line in content.splitlines():
            line = line.strip()
            if not line or "sshd[" not in line:
                continue

            m = _SYSLOG.match(line)
            if not m:
                continue

            rec: dict = {
                "_raw": line,
                "timestamp": _syslog_ts(m.group("ts")),
                "hostname": m.group("host"),
                "pid": int(m.group("pid")),
                "program": "sshd",
            }
            msg = m.group("msg")

            if fm := _FAILED.search(msg):
                rec.update(
                    event_type="ssh_login_failed",
                    outcome="failure",
                    auth_method=fm.group("method"),
                    username=fm.group("user"),
                    source_ip=fm.group("ip"),
                    source_port=int(fm.group("port")),
                    severity="medium",
                )
            elif am := _ACCEPTED.search(msg):
                rec.update(
                    event_type="ssh_login_success",
                    outcome="success",
                    auth_method=am.group("method"),
                    username=am.group("user"),
                    source_ip=am.group("ip"),
                    source_port=int(am.group("port")),
                    severity="info",
                )
            elif im := _INVALID.search(msg):
                rec.update(
                    event_type="ssh_invalid_user",
                    outcome="failure",
                    username=im.group("user"),
                    source_ip=im.group("ip"),
                    source_port=int(im.group("port")) if im.group("port") else None,
                    severity="high",   # probing for nonexistent accounts = recon
                )
            else:
                rec.update(event_type="ssh_event", message=msg, severity="info")

            yield rec


def _syslog_ts(raw: str) -> str:
    """Syslog omits the year — assume the current year, return ISO 8601 UTC."""
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {raw}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        # If parsing lands in the future (Dec logs read in Jan), roll back a year.
        if dt > now:
            dt = dt.replace(year=now.year - 1)
        return dt.isoformat()
    except ValueError:
        return now.isoformat()
