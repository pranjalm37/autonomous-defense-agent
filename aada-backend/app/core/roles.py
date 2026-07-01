"""
Canonical roles and the permission model (RBAC).

Three roles, ordered by privilege:

    viewer   — read-only. Sees dashboards, alerts, reports, audit. Cannot change
               anything. (Auditors, execs, on-call observers.)
    analyst  — the operator. Everything viewer can do, plus investigate, run the
               AI/detection/decision engines, comment, and approve/execute/roll
               back remediation actions.
    admin    — full control, including destructive config, knowledge ingestion,
               and user/role management. Implicitly granted every permission.

We model authorization two ways that work together:
  - **Role checks** (coarse) — `require_roles("analyst", "admin")` on an endpoint.
  - **Permissions** (fine) — `"resource:action"` entries in each role's map, for
    `require_permission("actions", "approve")` and UI gating. `admin` holds the
    `*` wildcard, so it satisfies any check.
"""
from __future__ import annotations


class RoleName:
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


ALL_ROLES = [RoleName.VIEWER, RoleName.ANALYST, RoleName.ADMIN]

# Higher number = more privilege (used for "at least this role" checks).
ROLE_HIERARCHY: dict[str, int] = {
    RoleName.VIEWER: 0,
    RoleName.ANALYST: 1,
    RoleName.ADMIN: 2,
}

# resource → allowed actions, per role. "*" wildcard = everything.
ROLE_PERMISSIONS: dict[str, dict[str, list[str]]] = {
    RoleName.VIEWER: {
        "alerts": ["read"],
        "events": ["read"],
        "detection": ["read"],
        "reports": ["read"],
        "knowledge": ["read", "query"],
        "audit": ["read"],
    },
    RoleName.ANALYST: {
        "alerts": ["read", "write"],
        "events": ["read", "write"],
        "detection": ["read", "run"],
        "analysis": ["read", "run"],
        "decision": ["read", "run"],
        "actions": ["read", "approve", "deny", "execute", "rollback", "comment"],
        "reports": ["read", "generate"],
        "knowledge": ["read", "query"],
        "audit": ["read"],
    },
    RoleName.ADMIN: {"*": ["*"]},
}

# Human-friendly seed definitions: (name, label, description).
ROLE_DEFINITIONS = [
    (RoleName.VIEWER, "Viewer", "Read-only access to dashboards, alerts, and reports."),
    (RoleName.ANALYST, "Analyst", "Investigate, run the AI agents, and action remediations."),
    (RoleName.ADMIN, "Administrator", "Full system access including user and role management."),
]


def has_permission(role: str | None, resource: str, action: str) -> bool:
    """True if `role` may perform `action` on `resource`."""
    if role is None:
        return False
    perms = ROLE_PERMISSIONS.get(role, {})
    # admin (or any role with the global wildcard) passes everything
    if "*" in perms and "*" in perms["*"]:
        return True
    allowed = perms.get(resource) or perms.get("*") or []
    return action in allowed or "*" in allowed


def role_at_least(role: str | None, minimum: str) -> bool:
    return ROLE_HIERARCHY.get(role or "", -1) >= ROLE_HIERARCHY.get(minimum, 99)
