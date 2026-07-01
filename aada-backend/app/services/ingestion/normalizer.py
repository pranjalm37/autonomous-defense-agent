"""
Log normalization
==================

Every source speaks its own dialect. A SIEM CSV calls the attacker address
`src_ip`; an sshd line calls it the token after `from`; an Nginx log puts it
first on the line. If we stored each source in its native shape, every query and
every AI prompt would need per-vendor special-casing.

Normalization collapses all of that into ONE canonical schema (a small subset of
the Elastic Common Schema) so the rest of the system — correlation, RAG, the
dashboard — only ever sees consistent field names.

Three things happen here:

1. **Field mapping** — known source aliases (`src_ip`, `clientip`, `source.ip`,
   `remote_addr`, …) are folded onto the canonical key (`source_ip`).
2. **Type & value coercion** — IPs validated, ports range-checked, timestamps
   pushed to timezone-aware UTC, severities mapped onto our 5-level enum.
3. **Lossless preservation** — the untouched original record is kept in
   `raw_payload`; the canonical view goes in `normalized_payload`. Nothing the
   parser saw is ever discarded, so a later schema change can re-normalize from
   history.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from app.models.event import EventSource, EventSeverity
from app.schemas.event import NormalizedEvent

# ── Canonical field ← source aliases ──────────────────────────────────────────
# The first alias found (in order) wins. Keys are the canonical names.
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "source_ip":   ("source_ip", "src_ip", "srcip", "src", "clientip", "client_ip",
                    "remote_addr", "ip", "source.ip", "src.ip"),
    "dest_ip":     ("dest_ip", "dst_ip", "dstip", "dst", "destination_ip",
                    "dest.ip", "destination.ip", "server_ip"),
    "source_port": ("source_port", "src_port", "srcport", "sport", "source.port"),
    "dest_port":   ("dest_port", "dst_port", "dstport", "dport", "destination.port"),
    "hostname":    ("hostname", "host", "host_name", "computer", "device", "agent_host"),
    "username":    ("username", "user", "user_name", "account", "user.name", "uid"),
    "user_agent":  ("user_agent", "ua", "http_user_agent", "user_agent.original"),
    "event_type":  ("event_type", "event", "type", "action", "event.action", "signature"),
    "source_event_id": ("source_event_id", "event_id", "id", "uuid", "_id"),
}

# ── Severity vocabulary → our 5-level enum ────────────────────────────────────
_SEVERITY_MAP: dict[str, EventSeverity] = {
    # words
    "info": EventSeverity.INFO, "informational": EventSeverity.INFO,
    "notice": EventSeverity.INFO, "debug": EventSeverity.INFO,
    "low": EventSeverity.LOW, "warning": EventSeverity.LOW, "warn": EventSeverity.LOW,
    "medium": EventSeverity.MEDIUM, "moderate": EventSeverity.MEDIUM, "error": EventSeverity.MEDIUM,
    "high": EventSeverity.HIGH, "important": EventSeverity.HIGH,
    "critical": EventSeverity.CRITICAL, "crit": EventSeverity.CRITICAL,
    "emergency": EventSeverity.CRITICAL, "alert": EventSeverity.CRITICAL,
    "fatal": EventSeverity.CRITICAL,
    # common numeric scales (syslog 0-7, and 1-5 risk scales)
    "0": EventSeverity.CRITICAL, "1": EventSeverity.CRITICAL, "2": EventSeverity.CRITICAL,
    "3": EventSeverity.HIGH, "4": EventSeverity.MEDIUM, "5": EventSeverity.LOW,
    "6": EventSeverity.INFO, "7": EventSeverity.INFO,
}


def _first(record: dict, aliases: tuple[str, ...]) -> str | None:
    """Return the first present, non-empty alias value (case-insensitive keys)."""
    lower = {k.lower(): v for k, v in record.items() if isinstance(k, str)}
    for alias in aliases:
        v = lower.get(alias.lower())
        if v not in (None, "", "-"):
            return v
    return None


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = str(value).split(":")[0] if str(value).count(":") == 1 else str(value)
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        try:
            return str(ipaddress.ip_address(str(value)))
        except ValueError:
            return None


def _as_port(value) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _as_severity(value) -> EventSeverity:
    if value is None:
        return EventSeverity.INFO
    if isinstance(value, EventSeverity):
        return value
    return _SEVERITY_MAP.get(str(value).strip().lower(), EventSeverity.INFO)


def _as_source(value, default: EventSource) -> EventSource:
    if isinstance(value, EventSource):
        return value
    if value is None:
        return default
    try:
        return EventSource(str(value).strip().lower())
    except ValueError:
        return default


def _as_utc(value) -> datetime:
    """Coerce many timestamp shapes to a tz-aware UTC datetime; fall back to now."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return datetime.now(timezone.utc)
    text = str(value).strip()
    # epoch seconds / millis
    if text.replace(".", "", 1).isdigit():
        num = float(text)
        if num > 1e12:      # milliseconds
            num /= 1000.0
        try:
            return datetime.fromtimestamp(num, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def normalize(record: dict, default_source: EventSource) -> NormalizedEvent:
    """
    Map one loose parsed record onto the canonical NormalizedEvent.

    `record` keeps the parser's native field names; `default_source` is the
    parser's declared source, used when the record itself doesn't specify one.
    """
    source = _as_source(_first(record, ("source", "source.type", "vendor")), default_source)
    event_type = _first(record, _FIELD_ALIASES["event_type"]) or "unknown"

    # Network / identity fields (everything except event_type, which is top-level).
    net_fields = {
        "source_ip":   _valid_ip(_first(record, _FIELD_ALIASES["source_ip"])),
        "dest_ip":     _valid_ip(_first(record, _FIELD_ALIASES["dest_ip"])),
        "source_port": _as_port(_first(record, _FIELD_ALIASES["source_port"])),
        "dest_port":   _as_port(_first(record, _FIELD_ALIASES["dest_port"])),
        "hostname":    _first(record, _FIELD_ALIASES["hostname"]),
        "username":    _first(record, _FIELD_ALIASES["username"]),
        "user_agent":  _first(record, _FIELD_ALIASES["user_agent"]),
    }

    normalized_payload = {k: v for k, v in net_fields.items() if v is not None}
    normalized_payload["event_type"] = event_type

    return NormalizedEvent(
        source=source,
        source_event_id=_first(record, _FIELD_ALIASES["source_event_id"]),
        event_type=event_type,
        severity=_as_severity(_first(record, ("severity", "level", "priority", "risk"))),
        raw_payload=record,
        normalized_payload=normalized_payload,
        ingested_at=_as_utc(_first(record, ("timestamp", "@timestamp", "time", "date", "_time"))),
        **net_fields,
    )
