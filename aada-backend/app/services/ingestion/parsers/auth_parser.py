"""
Auth parser — Linux PAM / sudo / login lines from /var/log/auth.log.

Covers the non-sshd authentication surface: sudo invocations, su, and generic
PAM auth failures. (Dedicated sshd handling lives in ssh_parser.py.)

Example lines handled:
    Jan 10 14:02:11 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
    Jan 10 14:03:55 web01 su[20111]: FAILED su for root by deploy
    Jan 10 14:05:09 web01 login[2001]: pam_unix(login:auth): authentication failure; logname= uid=0 ... user=admin
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timezone

from app.models.event import EventSource
from app.services.ingestion.parsers.base import BaseParser

_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_SUDO = re.compile(r"(?P<actor>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
_SU_FAIL = re.compile(r"FAILED su for (?P<target>\S+) by (?P<actor>\S+)")
_PAM_FAIL = re.compile(r"authentication failure;.*?(?:user=(?P<user>\S+))?", re.IGNORECASE)


class AuthLogParser(BaseParser):
    default_source = EventSource.ENDPOINT

    def parse(self, content: str) -> Iterator[dict]:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _SYSLOG.match(line)
            if not m:
                continue

            prog = m.group("prog").split("/")[-1]
            if prog == "sshd":
                continue  # handled by SSHParser

            rec: dict = {
                "_raw": line,
                "timestamp": _syslog_ts(m.group("ts")),
                "hostname": m.group("host"),
                "program": prog,
            }
            msg = m.group("msg")

            if prog == "sudo" and (sm := _SUDO.search(msg)):
                rec.update(
                    event_type="sudo_command",
                    outcome="success",
                    username=sm.group("actor"),
                    target_user=sm.group("target"),
                    command=sm.group("cmd"),
                    severity="medium" if sm.group("target") == "root" else "low",
                )
            elif sf := _SU_FAIL.search(msg):
                rec.update(
                    event_type="su_failed",
                    outcome="failure",
                    username=sf.group("actor"),
                    target_user=sf.group("target"),
                    severity="high",
                )
            elif pf := _PAM_FAIL.search(msg):
                rec.update(
                    event_type="pam_auth_failure",
                    outcome="failure",
                    username=pf.group("user"),
                    severity="medium",
                )
            else:
                rec.update(event_type=f"{prog}_event", message=msg, severity="info")

            yield rec


def _syslog_ts(raw: str) -> str:
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {raw}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        if dt > now:
            dt = dt.replace(year=now.year - 1)
        return dt.isoformat()
    except ValueError:
        return now.isoformat()
