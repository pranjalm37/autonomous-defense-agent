"""JSON parser — accepts a single object, a JSON array, or NDJSON (one object/line)."""
from __future__ import annotations

import json
from collections.abc import Iterator

from app.models.event import EventSource
from app.services.ingestion.parsers.base import BaseParser, ParseError


class JSONParser(BaseParser):
    default_source = EventSource.MANUAL

    def parse(self, content: str) -> Iterator[dict]:
        content = content.strip()
        if not content:
            return

        # Try whole-document parse first (single object or array).
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            # Fall back to NDJSON: one JSON object per line.
            yield from self._parse_ndjson(content)
            return

        if isinstance(doc, list):
            for i, item in enumerate(doc):
                if not isinstance(item, dict):
                    raise ParseError(f"array element {i} is not an object", sample=str(item)[:200])
                yield item
        elif isinstance(doc, dict):
            # A wrapper like {"events": [...]} is common — unwrap it.
            if len(doc) == 1 and isinstance(next(iter(doc.values())), list):
                for item in next(iter(doc.values())):
                    if isinstance(item, dict):
                        yield item
            else:
                yield doc
        else:
            raise ParseError("top-level JSON must be an object or array", sample=content[:200])

    @staticmethod
    def _parse_ndjson(content: str) -> Iterator[dict]:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ParseError(f"invalid JSON line: {e}", sample=line[:200])
            if not isinstance(obj, dict):
                raise ParseError("NDJSON line is not an object", sample=line[:200])
            yield obj
