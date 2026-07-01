"""
MCP security-tool tests — exercise every tool through the registry with an
offline ToolContext (seeded feeds, simulated firewall, in-memory events). No MCP
protocol connection or network required.
"""
from __future__ import annotations

import pytest

from app.mcp_server.context import build_default_context
from app.mcp_server.providers import InMemoryEventStore
from app.mcp_server.tools import build_registry


@pytest.fixture
def registry():
    return build_registry()


@pytest.fixture
def ctx():
    events = [
        {"event_type": "ssh_login_failed", "source_ip": "203.0.113.66",
         "username": "root", "hostname": "web01"},
        {"event_type": "ssh_login_failed", "source_ip": "203.0.113.66",
         "username": "admin", "hostname": "web01"},
        {"event_type": "ssh_login_success", "source_ip": "10.0.0.5",
         "username": "deploy", "hostname": "web01"},
    ]
    c = build_default_context()
    c.event_store = InMemoryEventStore(events)
    return c


async def _run(registry, ctx, name, args):
    return await registry.execute(name, args, ctx)


# ── Registry ──────────────────────────────────────────────────────────────────
def test_registry_has_all_six_tools(registry):
    names = {s.name for s in registry.list_specs()}
    assert names == {
        "ip_reputation_lookup", "cve_search", "geoip_lookup",
        "log_search", "firewall_action", "threat_intelligence",
    }


def test_every_tool_exposes_a_json_schema_and_description(registry):
    for spec in registry.list_specs():
        schema = spec.json_schema()
        assert schema["type"] == "object"
        assert len(spec.description) > 40        # descriptions guide the model


def test_firewall_flagged_destructive_and_approval(registry):
    fw = registry.get("firewall_action")
    assert fw.destructive and fw.requires_approval


@pytest.mark.asyncio
async def test_unknown_tool_and_bad_args(registry, ctx):
    assert (await _run(registry, ctx, "does_not_exist", {})).ok is False
    bad = await _run(registry, ctx, "ip_reputation_lookup", {})   # missing required 'ip'
    assert bad.ok is False and "invalid arguments" in bad.error


# ── IP reputation ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_ip_reputation_flags_known_bad(registry, ctx):
    r = await _run(registry, ctx, "ip_reputation_lookup", {"ip": "45.77.12.9"})
    assert r.ok
    assert r.data["verdict"] == "malicious"
    assert r.data["reputation_score"] >= 90
    assert "c2" in r.data["categories"]


@pytest.mark.asyncio
async def test_ip_reputation_unknown_ip(registry, ctx):
    r = await _run(registry, ctx, "ip_reputation_lookup", {"ip": "192.0.2.123"})
    assert r.ok and r.data["verdict"] == "unknown"


# ── CVE search ────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_cve_search_by_query(registry, ctx):
    r = await _run(registry, ctx, "cve_search", {"query": "log4j"})
    assert r.ok and r.data["count"] >= 1
    assert any(c["id"] == "CVE-2021-44228" for c in r.data["results"])


@pytest.mark.asyncio
async def test_cve_search_by_product_sorted_by_cvss(registry, ctx):
    r = await _run(registry, ctx, "cve_search", {"product": "openssl"})
    cvss = [c["cvss"] for c in r.data["results"]]
    assert cvss == sorted(cvss, reverse=True)


@pytest.mark.asyncio
async def test_cve_search_requires_a_filter(registry, ctx):
    r = await _run(registry, ctx, "cve_search", {})
    assert r.ok is False


# ── GeoIP ─────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_geoip_resolves_known_ip(registry, ctx):
    r = await _run(registry, ctx, "geoip_lookup", {"ip": "203.0.113.66"})
    assert r.ok and r.data["located"] and r.data["country"] == "RU"


@pytest.mark.asyncio
async def test_geoip_internal_ip_not_located(registry, ctx):
    r = await _run(registry, ctx, "geoip_lookup", {"ip": "10.0.0.5"})
    assert r.ok and r.data["located"] is False


# ── Log search ────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_log_search_by_ip(registry, ctx):
    r = await _run(registry, ctx, "log_search", {"source_ip": "203.0.113.66"})
    assert r.ok and r.data["count"] == 2


@pytest.mark.asyncio
async def test_log_search_needs_a_filter(registry, ctx):
    r = await _run(registry, ctx, "log_search", {})
    assert r.ok is False


# ── Firewall ──────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_firewall_block_list_unblock_cycle(registry, ctx):
    blocked = await _run(registry, ctx, "firewall_action",
                         {"action": "block_ip", "ip": "45.77.12.9", "reason": "C2", "ttl_minutes": 60})
    assert blocked.ok and ctx.firewall.is_blocked("45.77.12.9")

    listing = await _run(registry, ctx, "firewall_action", {"action": "list_blocked"})
    assert any(e["ip"] == "45.77.12.9" for e in listing.data["blocked"])

    unblocked = await _run(registry, ctx, "firewall_action",
                           {"action": "unblock_ip", "ip": "45.77.12.9"})
    assert unblocked.ok and not ctx.firewall.is_blocked("45.77.12.9")


@pytest.mark.asyncio
async def test_firewall_block_requires_ip(registry, ctx):
    r = await _run(registry, ctx, "firewall_action", {"action": "block_ip"})
    assert r.ok is False


# ── Threat intelligence (composite) ───────────────────────────────────────────
@pytest.mark.asyncio
async def test_threat_intel_attributes_actor(registry, ctx):
    r = await _run(registry, ctx, "threat_intelligence", {"indicator": "45.77.12.9"})
    assert r.ok
    assert r.data["indicator_type"] == "ip"
    names = [a["name"] for a in r.data["attributed_actors"]]
    assert "APT-DEMO-BEAR" in names
    assert r.data["reputation"]["score"] >= 90


@pytest.mark.asyncio
async def test_threat_intel_auto_classifies_hash(registry, ctx):
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = await _run(registry, ctx, "threat_intelligence", {"indicator": h})
    assert r.ok and r.data["indicator_type"] == "hash"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
