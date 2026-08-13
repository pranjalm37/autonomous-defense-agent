"""
IngestionService — orchestrates the full pipeline for one ingest call:

    parse  →  normalize  →  validate  →  store

It is format-agnostic: hand it raw text and a LogFormat and it returns an
IngestResult summarizing how many records landed, how many failed, and why.
Bad records never abort the batch — they are collected into `errors` so a single
malformed line can't block thousands of good ones.
"""
from __future__ import annotations

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models.event import SecurityEvent
from app.schemas.event import IngestError, IngestResult, LogFormat, NormalizedEvent
from app.services.ingestion import normalizer
from app.services.ingestion.parsers import ParseError, get_parser

logger = get_logger(__name__)

# Guardrail: cap records per call so a giant upload can't exhaust memory/DB.
MAX_RECORDS = 50_000


class IngestionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def ingest(self, content: str, fmt: LogFormat) -> IngestResult:
        parser = get_parser(fmt)
        result = IngestResult(format=fmt, received=0, stored=0, failed=0)
        to_store: list[SecurityEvent] = []

        line_no = 0
        record_iter = self._safe_parse(parser, content, result)
        for line_no, record in record_iter:
            result.received += 1
            if result.received > MAX_RECORDS:
                result.errors.append(IngestError(
                    line=line_no, error=f"record cap {MAX_RECORDS} exceeded; remainder skipped"))
                break

            try:
                normalized = normalizer.normalize(record, default_source=parser.default_source)
                event = self._to_model(normalized)
            except (PydanticValidationError, ValueError) as e:
                result.failed += 1
                result.errors.append(IngestError(
                    line=line_no, error=f"validation: {e}", sample=str(record)[:200]))
                continue

            to_store.append(event)

        # Bulk add; session.py commits on success / rolls back on error.
        for event in to_store:
            self.db.add(event)
        await self.db.flush()   # populate PKs without committing

        result.stored = len(to_store)
        result.event_ids = [e.id for e in to_store]

        logger.info(
            "events_ingested",
            format=fmt.value,
            received=result.received,
            stored=result.stored,
            failed=result.failed,
        )
        return result

    @staticmethod
    def _safe_parse(parser, content: str, result: IngestResult):
        """
        Wrap the parser's generator so a ParseError on one record is recorded
        and skipped instead of killing the whole iteration.
        """
        gen = parser.parse(content)
        idx = 0
        while True:
            idx += 1
            try:
                record = next(gen)
            except StopIteration:
                return
            except ParseError as e:
                result.failed += 1
                result.errors.append(IngestError(line=idx, error=str(e), sample=e.sample))
                continue
            yield idx, record

    @staticmethod
    def _to_model(n: NormalizedEvent) -> SecurityEvent:
        return SecurityEvent(
            source=n.source,
            source_event_id=n.source_event_id,
            event_type=n.event_type,
            severity=n.severity,
            raw_payload=n.raw_payload,
            normalized_payload=n.normalized_payload,
            source_ip=n.source_ip,
            dest_ip=n.dest_ip,
            source_port=n.source_port,
            dest_port=n.dest_port,
            hostname=n.hostname,
            username=n.username,
            user_agent=n.user_agent,
            processed=False,
            ingested_at=n.ingested_at,
        )
