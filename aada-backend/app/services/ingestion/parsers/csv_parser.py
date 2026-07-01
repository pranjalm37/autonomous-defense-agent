"""
CSV parser — header row defines field names; each subsequent row becomes a dict.

Delimiter is auto-sniffed (comma / tab / semicolon / pipe). Empty cells become
None rather than empty strings so downstream `or` fallbacks behave predictably.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterator

from app.models.event import EventSource
from app.services.ingestion.parsers.base import BaseParser, ParseError


class CSVParser(BaseParser):
    default_source = EventSource.SIEM   # CSV exports usually come from a SIEM

    def parse(self, content: str) -> Iterator[dict]:
        content = content.lstrip("﻿")  # strip UTF-8 BOM if present
        if not content.strip():
            return

        sample = content[:2048]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        except csv.Error:
            dialect = csv.excel  # default to comma

        reader = csv.DictReader(io.StringIO(content), dialect=dialect)
        if reader.fieldnames is None:
            raise ParseError("CSV has no header row")

        for row in reader:
            # Normalize blank strings → None, strip whitespace, drop the None key
            # that DictReader uses for extra columns.
            cleaned = {
                (k.strip() if k else k): (v.strip() if isinstance(v, str) and v.strip() else None)
                for k, v in row.items()
                if k is not None
            }
            yield cleaned
