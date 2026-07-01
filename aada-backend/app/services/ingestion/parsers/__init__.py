"""Parser registry — maps a LogFormat to the parser that handles it."""
from __future__ import annotations

from app.schemas.event import LogFormat
from app.services.ingestion.parsers.base import BaseParser, ParseError
from app.services.ingestion.parsers.json_parser import JSONParser
from app.services.ingestion.parsers.csv_parser import CSVParser
from app.services.ingestion.parsers.ssh_parser import SSHParser
from app.services.ingestion.parsers.auth_parser import AuthLogParser
from app.services.ingestion.parsers.web_parser import WebLogParser

_REGISTRY: dict[LogFormat, BaseParser] = {
    LogFormat.JSON: JSONParser(),
    LogFormat.CSV: CSVParser(),
    LogFormat.SSH: SSHParser(),
    LogFormat.AUTH: AuthLogParser(),
    LogFormat.WEB: WebLogParser(),
}


def get_parser(fmt: LogFormat) -> BaseParser:
    parser = _REGISTRY.get(fmt)
    if parser is None:
        raise ParseError(f"no parser registered for format '{fmt}'")
    return parser


__all__ = ["get_parser", "BaseParser", "ParseError"]
