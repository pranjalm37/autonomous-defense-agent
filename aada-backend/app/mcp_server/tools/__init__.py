"""Tool collection — assembles the registry of all security tools."""
from __future__ import annotations

from app.mcp_server.registry import ToolRegistry
from app.mcp_server.tools import (
    ip_reputation, cve_search, geoip, log_search, firewall, threat_intel,
)

_MODULES = [ip_reputation, cve_search, geoip, log_search, firewall, threat_intel]


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for mod in _MODULES:
        registry.register(mod.SPEC)
    return registry


__all__ = ["build_registry"]
