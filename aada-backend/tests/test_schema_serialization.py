"""
Response-serialization regression tests — these guard the bugs the live container
surfaced that the offline API tests structurally couldn't (they never serialized
real Postgres INET / asyncpg values).
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.schemas.alert import AlertResponse
from app.schemas.audit import AuditLogResponse
from app.schemas.event import EventResponse


def test_audit_ip_address_coerces_ipaddress_object():
    # asyncpg returns INET columns as IPv4Address/IPv6Address, not str.
    row = SimpleNamespace(
        id=uuid.uuid4(), action="auth.login", category="user", resource_type="user",
        resource_id=None, user_id=None, user_email="a@b.io",
        old_value=None, new_value=None,
        ip_address=ipaddress.IPv4Address("192.168.65.1"),
        created_at=datetime.now(timezone.utc),
    )
    m = AuditLogResponse.model_validate(row)
    assert m.ip_address == "192.168.65.1" and isinstance(m.ip_address, str)


def test_audit_ip_address_allows_none():
    row = SimpleNamespace(
        id=uuid.uuid4(), action="ai.decision", category="ai", resource_type="alert",
        resource_id=None, user_id=None, user_email=None,
        old_value=None, new_value=None, ip_address=None,
        created_at=datetime.now(timezone.utc),
    )
    assert AuditLogResponse.model_validate(row).ip_address is None


def test_alert_and_event_ip_fields_coerce():
    from app.models.alert import AlertStatus, Severity
    from app.models.event import EventSeverity, EventSource

    alert = SimpleNamespace(
        id=uuid.uuid4(), title="x", severity=Severity.HIGH, status=AlertStatus.NEW,
        source_ip=ipaddress.IPv4Address("203.0.113.66"),
        dest_ip=ipaddress.IPv6Address("2001:db8::1"),
        hostname="h", affected_user="u", threat_type="brute_force",
        ai_confidence=0.9, incident_id=None,
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    am = AlertResponse.model_validate(alert)
    assert am.source_ip == "203.0.113.66"
    assert am.dest_ip == "2001:db8::1"

    event = SimpleNamespace(
        id=uuid.uuid4(), source=EventSource.SIEM, event_type="login_failed",
        severity=EventSeverity.MEDIUM,
        source_ip=ipaddress.IPv4Address("198.51.100.23"), dest_ip=None,
        hostname="h", username="u", processed=False,
        ingested_at=datetime.now(timezone.utc), alert_id=None,
        created_at=datetime.now(timezone.utc),
    )
    em = EventResponse.model_validate(event)
    assert em.source_ip == "198.51.100.23" and em.dest_ip is None


def test_config_list_env_accepts_plain_and_json(monkeypatch):
    """The startup crash: list env vars must accept non-JSON values."""
    from app.config import Settings
    monkeypatch.setenv("ALLOWED_HOSTS", "*")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:8080,http://localhost:3000")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setenv("SECRET_KEY", "x")
    s = Settings()
    assert s.allowed_hosts == ["*"]
    assert s.allowed_origins == ["http://localhost:8080", "http://localhost:3000"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
