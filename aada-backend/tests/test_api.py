"""
API-layer tests — the HTTP contract: routing, request/response schemas, auth
(401), RBAC (403), validation (422), and full end-to-end runs through endpoints
that don't touch the database (decision, knowledge, analyst, detection rules).

Uses FastAPI's TestClient with dependency overrides for the current user, so
authorization is exercised against the real `require_roles` guards.
"""
from __future__ import annotations

import pytest

# ── OpenAPI / routing ─────────────────────────────────────────────────────────
def test_openapi_lists_all_routers(client):
    paths = client.get("/openapi.json").json()["paths"]
    for prefix in ("/auth/login", "/alerts", "/events", "/detection/run",
                   "/analyst/analyze", "/decision/evaluate", "/response/actions",
                   "/audit/logs", "/reports", "/knowledge/query"):
        assert any(prefix in p for p in paths), f"missing route {prefix}"


# ── Authentication (401) ──────────────────────────────────────────────────────
@pytest.mark.parametrize("method,path", [
    ("get", "/api/v1/alerts"),
    ("get", "/api/v1/response/actions"),
    ("get", "/api/v1/audit/logs"),
    ("post", "/api/v1/detection/run"),
])
def test_protected_routes_require_auth(client, method, path):
    kwargs = {"json": {}} if method == "post" else {}   # httpx GET takes no body
    resp = getattr(client, method)(path, **kwargs)
    assert resp.status_code == 401


# ── Authorization (403 RBAC) ──────────────────────────────────────────────────
def test_viewer_cannot_run_detection(as_role):
    resp = as_role("viewer").post("/api/v1/detection/run", json={"lookback_minutes": 60})
    assert resp.status_code == 403


def test_viewer_cannot_read_audit(as_role):
    resp = as_role("viewer").get("/api/v1/audit/logs")
    assert resp.status_code == 403


def test_analyst_passes_role_guard_on_decision(as_role):
    # decision/evaluate is analyst-or-admin (via get_current_user only) and DB-free
    body = {"mode": "assisted", "detection": {"risk_score": 80, "confidence": 0.9}, "actions": []}
    resp = as_role("analyst").post("/api/v1/decision/evaluate", json=body)
    assert resp.status_code == 200


def test_admin_can_read_audit_route_guard(as_role):
    # admin passes the require_roles guard; the handler then needs a DB, which we
    # don't provide — so we assert it's NOT a 403 (authorization succeeded).
    resp = as_role("admin").get("/api/v1/audit/logs")
    assert resp.status_code != 403


# ── Validation (422) ──────────────────────────────────────────────────────────
def test_decision_evaluate_validates_body(as_role):
    # risk_score out of range → 422 from pydantic
    bad = {"detection": {"risk_score": 999, "confidence": 0.5}}
    resp = as_role("analyst").post("/api/v1/decision/evaluate", json=bad)
    assert resp.status_code == 422


# ── End-to-end through DB-free endpoints ──────────────────────────────────────
def test_decision_evaluate_returns_decision(as_role):
    body = {
        "mode": "autonomous",
        "detection": {"risk_score": 90, "confidence": 0.95, "threat_type": "malware"},
        "llm": {"risk_score": 88, "confidence": 0.9, "is_true_positive": True},
        "threat_intel": {"malicious_score": 97},
        "actions": [{"title": "Block IP", "action_type": "block_ip", "target": "45.77.12.9", "reversible": True}],
    }
    resp = as_role("analyst").post("/api/v1/decision/evaluate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "malicious"
    assert data["risk_score"] >= 85
    assert data["action_decisions"][0]["disposition"] == "auto_execute"


def test_analyst_adhoc_analysis(as_role):
    body = {
        "alert": {"title": "SSH brute force", "severity": "critical", "threat_type": "brute_force",
                  "source_ip": "203.0.113.66", "mitre_techniques": ["T1110"]},
        "events": [{"event_type": "ssh_login_failed", "summary": "Failed password", "source_ip": "203.0.113.66"}],
        "use_rag": True,
    }
    resp = as_role("analyst").post("/api/v1/analyst/analyze", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert "executive_summary" in data
    assert data["risk_score"] >= 0


def test_detection_rules_listed(as_role):
    resp = as_role("viewer").get("/api/v1/detection/rules")
    assert resp.status_code == 200
    rule_ids = {r["rule_id"] for r in resp.json()}
    assert "ssh_brute_force" in rule_ids
    assert len(rule_ids) == 6


def test_knowledge_query_returns_results(as_role):
    resp = as_role("viewer").post("/api/v1/knowledge/query",
                                  json={"query": "ssh brute force detection", "top_k": 3})
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"]
    assert len(data["results"]) >= 1
    assert "score" in data["results"][0]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
