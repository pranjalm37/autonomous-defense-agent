"""
Geo-IP resolution for the impossible-travel rule.

Production should plug in MaxMind GeoIP2 / GeoLite2 (a ~60 MB .mmdb file):

    import geoip2.database
    reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    rec = reader.city(ip)
    GeoPoint(rec.location.latitude, rec.location.longitude, rec.country.iso_code)

We keep that behind a tiny `GeoResolver` protocol so the detection logic never
imports a heavy DB and stays unit-testable. The default `StaticGeoResolver` ships
a small offline table (enough for demos/tests) and treats RFC-1918/loopback
addresses as "no location" so internal logins never generate false positives.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class GeoPoint:
    lat: float
    lon: float
    country: str | None = None
    city: str | None = None


class GeoResolver(Protocol):
    def resolve(self, ip: str) -> GeoPoint | None: ...


class StaticGeoResolver:
    """Offline resolver: built-in table + optional injected overrides."""

    # A handful of well-known coordinates for demos & tests.
    _TABLE: dict[str, GeoPoint] = {
        "203.0.113.66": GeoPoint(55.7558, 37.6173, "RU", "Moscow"),
        "198.51.100.23": GeoPoint(39.9042, 116.4074, "CN", "Beijing"),
        "45.77.12.9": GeoPoint(1.3521, 103.8198, "SG", "Singapore"),
        "8.8.8.8": GeoPoint(37.4056, -122.0775, "US", "Mountain View"),
        "104.16.0.1": GeoPoint(37.7749, -122.4194, "US", "San Francisco"),
        "91.198.174.192": GeoPoint(52.3676, 4.9041, "NL", "Amsterdam"),
    }

    def __init__(self, overrides: dict[str, GeoPoint] | None = None):
        self._table = {**self._TABLE, **(overrides or {})}

    def resolve(self, ip: str) -> GeoPoint | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return None
        # An explicit geo/threat-intel entry always wins — if we know where an
        # address is, use it (this also covers reserved/documentation ranges that
        # newer stdlib flags as "private").
        if str(ip) in self._table:
            return self._table[str(ip)]
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None   # un-located internal address → no geolocation
        return None       # no entry in this offline table; production uses GeoIP2


def haversine_km(a: GeoPoint, b: GeoPoint) -> float:
    """Great-circle distance between two points, in kilometers."""
    r = 6371.0
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dphi = math.radians(b.lat - a.lat)
    dlam = math.radians(b.lon - a.lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlam / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))
