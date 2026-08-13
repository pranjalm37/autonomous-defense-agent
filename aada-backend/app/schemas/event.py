"""
Pydantic models for the event ingestion pipeline.

The flow is:  raw input  ──parse──>  ParsedRecord  ──normalize──>  NormalizedEvent
              (JSON/CSV/log line)     (loose dict)                  (canonical schema)

`NormalizedEvent` is the canonical, vendor-agnostic shape every event is coerced
into before storage. It is a small subset of the Elastic Common Schema (ECS) —
enough to correlate threats across heterogeneous sources without locking us to
any one vendor's field names.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.event import EventSeverity, EventSource
from app.schemas._types import IPStr


# ──────────────────────────────────────────────────────────────────────────────
# Supported input formats
# ──────────────────────────────────────────────────────────────────────────────
class LogFormat(str, enum.Enum):
    JSON = "json"        # structured JSON events (single object or array)
    CSV = "csv"          # delimited rows with a header line
    SSH = "ssh"          # sshd lines from /var/log/secure or /var/log/auth.log
    AUTH = "auth"        # Linux PAM / sudo / login lines from auth.log
    WEB = "web"          # Apache/Nginx access logs (Common/Combined Log Format)


# ──────────────────────────────────────────────────────────────────────────────
# Inbound JSON event (the only format clients POST as a body)
# ──────────────────────────────────────────────────────────────────────────────
class RawJSONEvent(BaseModel):
    """
    A loosely-typed inbound JSON event. Only `event_type` is required; everything
    else is best-effort and gets normalized. Unknown keys are preserved into
    raw_payload so nothing is ever lost.
    """
    model_config = ConfigDict(extra="allow")

    source: EventSource = EventSource.MANUAL
    source_event_id: str | None = None
    event_type: str
    severity: EventSeverity = EventSeverity.INFO
    timestamp: datetime | None = None

    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = Field(None, ge=0, le=65535)
    dest_port: int | None = Field(None, ge=0, le=65535)
    hostname: str | None = None
    username: str | None = None
    user_agent: str | None = None

    message: str | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Canonical normalized event (output of the normalizer, input to storage)
# ──────────────────────────────────────────────────────────────────────────────
class NormalizedEvent(BaseModel):
    """The single shape all sources are mapped into before persistence."""
    source: EventSource
    source_event_id: str | None = None
    event_type: str
    severity: EventSeverity = EventSeverity.INFO

    raw_payload: dict                          # original record, untouched
    normalized_payload: dict | None = None     # the ECS-mapped fields

    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    hostname: str | None = None
    username: str | None = None
    user_agent: str | None = None

    ingested_at: datetime

    @field_validator("source_port", "dest_port")
    @classmethod
    def valid_port(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 65535):
            return None   # drop nonsense ports rather than reject the whole event
        return v


# ──────────────────────────────────────────────────────────────────────────────
# Responses
# ──────────────────────────────────────────────────────────────────────────────
class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: EventSource
    event_type: str
    severity: EventSeverity
    source_ip: IPStr
    dest_ip: IPStr
    hostname: str | None
    username: str | None
    processed: bool
    ingested_at: datetime
    alert_id: uuid.UUID | None
    created_at: datetime


class IngestError(BaseModel):
    line: int                 # 1-based index of the offending record
    error: str
    sample: str | None = None # truncated raw text for debugging


class IngestResult(BaseModel):
    """Summary returned from every ingestion call (batch or file)."""
    format: LogFormat
    received: int             # records parsed out of the input
    stored: int              # records successfully validated + persisted
    failed: int              # records that failed parse/validation
    errors: list[IngestError] = Field(default_factory=list)
    event_ids: list[uuid.UUID] = Field(default_factory=list)
