"""Shared schema field types."""
from __future__ import annotations

from typing import Annotated

from pydantic import BeforeValidator


def _ip_to_str(v: object) -> str | None:
    # asyncpg returns INET columns as ipaddress.IPv4Address/IPv6Address objects;
    # coerce to str so `str`-typed response fields validate.
    return str(v) if v is not None else None


# Use for response fields backed by a Postgres INET column.
IPStr = Annotated[str | None, BeforeValidator(_ip_to_str)]
