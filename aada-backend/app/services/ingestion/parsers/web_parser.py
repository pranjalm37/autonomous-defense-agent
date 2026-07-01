"""
Web parser — Apache/Nginx access logs in Common or Combined Log Format (CLF).

    203.0.113.5 - frank [10/Jan/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 401 1234 "ref" "ua"

Combined adds the trailing "referer" and "user-agent" quoted fields; both
forms are accepted. HTTP status drives a coarse severity so brute-force (401)
and server errors (5xx) surface without an AI pass.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime

from app.models.event import EventSource
from app.services.ingestion.parsers.base import BaseParser, ParseError

_CLF = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


class WebLogParser(BaseParser):
    default_source = EventSource.FIREWALL  # WAF / reverse-proxy access logs

    def parse(self, content: str) -> Iterator[dict]:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _CLF.match(line)
            if not m:
                raise ParseError("line does not match Common/Combined Log Format", sample=line[:200])

            status = int(m.group("status"))
            user = m.group("user")
            rec = {
                "_raw": line,
                "event_type": "http_request",
                "timestamp": _clf_ts(m.group("ts")),
                "source_ip": m.group("ip"),
                "username": None if user == "-" else user,
                "http_method": m.group("method"),
                "url_path": m.group("path"),
                "http_version": m.group("proto"),
                "status_code": status,
                "bytes": None if m.group("size") == "-" else int(m.group("size")),
                "referer": m.group("referer"),
                "user_agent": m.group("ua"),
                "severity": _status_severity(status),
                "outcome": "success" if status < 400 else "failure",
            }
            yield rec


def _status_severity(status: int) -> str:
    if status >= 500:
        return "high"
    if status in (401, 403):
        return "medium"   # auth failure / forbidden — possible brute force or probing
    if status == 404:
        return "low"
    return "info"


def _clf_ts(raw: str) -> str:
    """'10/Jan/2026:13:55:36 +0000' → ISO 8601."""
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return raw
