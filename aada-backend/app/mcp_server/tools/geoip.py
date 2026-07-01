"""Tool: GeoIP lookup."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.mcp_server.context import ToolContext, ToolResult
from app.mcp_server.registry import ToolSpec


class GeoIPInput(BaseModel):
    ip: str = Field(description="IP address to geolocate")


async def handle(params: GeoIPInput, ctx: ToolContext) -> ToolResult:
    point = ctx.geo.resolve(params.ip)
    if point is None:
        return ToolResult(
            ok=True,
            summary=f"No geolocation for {params.ip} (internal/private or not in DB)",
            data={"ip": params.ip, "located": False},
        )
    data = {
        "ip": params.ip, "located": True,
        "country": point.country, "city": point.city,
        "latitude": point.lat, "longitude": point.lon,
    }
    return ToolResult(
        ok=True,
        summary=f"{params.ip} → {point.city or '?'}, {point.country or '?'}",
        data=data,
    )


SPEC = ToolSpec(
    name="geoip_lookup",
    description=(
        "Resolve an IP address to an approximate geographic location (country, "
        "city, latitude/longitude). Internal/RFC-1918 addresses return 'not "
        "located'. Use this to spot logins or traffic from unexpected countries "
        "and to support impossible-travel reasoning."
    ),
    input_model=GeoIPInput,
    handler=handle,
)
