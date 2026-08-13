"""
Event ingestion endpoints.

    POST /events/json     ingest structured JSON (single object or array)
    POST /events/upload   ingest a CSV / SSH / auth / web log file (multipart)
    GET  /events          list stored events with filters
    GET  /events/{id}     fetch one event

All formats funnel through the same IngestionService → parse → normalize →
validate → store pipeline, so every event ends up in the canonical schema
regardless of how it arrived.
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.db.session import get_db
from app.dependencies import get_current_user
from app.models.event import EventSeverity, EventSource, SecurityEvent
from app.models.user import User
from app.schemas.event import EventResponse, IngestResult, LogFormat
from app.services.ingestion import IngestionService

router = APIRouter(prefix="/events", tags=["events"])

# Cap raw upload size at 25 MB to protect the worker.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


@router.post("/json", response_model=IngestResult, status_code=201)
async def ingest_json(
    body: list[dict] | dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IngestResult:
    """
    Ingest structured JSON events. Accepts a single object, an array of objects,
    or a wrapper like {"events": [...]}. Each object is normalized independently.
    """
    content = json.dumps(body)
    return await IngestionService(db).ingest(content, LogFormat.JSON)


@router.post("/upload", response_model=IngestResult, status_code=201)
async def ingest_file(
    format: LogFormat = Form(..., description="csv | ssh | auth | web | json"),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IngestResult:
    """Ingest a log file. The `format` field selects the parser."""
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValidationError(f"file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")
    content = raw.decode("utf-8", errors="replace")

    return await IngestionService(db).ingest(content, format)


@router.get("", response_model=list[EventResponse])
async def list_events(
    source: EventSource | None = Query(None),
    severity: EventSeverity | None = Query(None),
    processed: bool | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[SecurityEvent]:
    q = select(SecurityEvent)
    if source:
        q = q.where(SecurityEvent.source == source)
    if severity:
        q = q.where(SecurityEvent.severity == severity)
    if processed is not None:
        q = q.where(SecurityEvent.processed == processed)

    result = await db.execute(
        q.order_by(SecurityEvent.ingested_at.desc()).offset(offset).limit(limit)
    )
    return list(result.scalars().all())


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SecurityEvent:
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise NotFoundError("Event", str(event_id))
    return event
