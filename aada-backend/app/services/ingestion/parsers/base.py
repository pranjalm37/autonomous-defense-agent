"""
Parser contract.

A parser's only job is to turn raw input (text or bytes) into a stream of loose
`dict` records — one per logical event. It does NOT normalize: field names stay
in the source's native vocabulary. Normalization is a separate, centralized step
(see app/services/ingestion/normalizer.py) so that adding a new source never
means touching the canonical schema.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from app.models.event import EventSource


class ParseError(Exception):
    """Raised for a single unparseable record. Carries the offending text."""

    def __init__(self, message: str, sample: str | None = None):
        super().__init__(message)
        self.sample = sample


class BaseParser(ABC):
    """Base class for all format parsers."""

    #: which EventSource newly-parsed records default to
    default_source: EventSource = EventSource.MANUAL

    @abstractmethod
    def parse(self, content: str) -> Iterator[dict]:
        """
        Yield one loose dict per record. Implementations should raise
        ParseError for an individual bad record (the service skips it and
        records the error) but let the whole call succeed if other records parse.
        """
        raise NotImplementedError
