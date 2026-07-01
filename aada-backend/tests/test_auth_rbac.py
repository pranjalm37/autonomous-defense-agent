"""
Authentication & RBAC tests — JWT token semantics, the permission matrix, and the
role-guard behavior. Offline; no DB.
"""
from __future__ import annotations

import uuid

import pytest
from jose import jwt

from app.config import get_settings
from app.core import security
from app.core.roles import (
    ALL_ROLES, ROLE_DEFINITIONS, ROLE_PERMISSIONS, RoleName,
    has_permission, role_at_least,
)


# ── JWT ───────────────────────────────────────────────────────────────────────
def test_access_and_refresh_tokens_carry_type():
    uid = uuid.uuid4()
    access = security.create_access_token(uid)
    refresh = security.create_refresh_token(uid)
    assert security.decode_token(access)["type"] == "access"
    assert security.decode_token(refresh)["type"] == "refresh"
    # subject round-trips as the user id
    assert security.decode_token(access)["sub"] == str(uid)


def test_token_is_signed_and_tamper_evident():
    token = security.create_access_token(uuid.uuid4())
    settings = get_settings()
    # decoding with the wrong key must fail
    with pytest.raises(Exception):
        jwt.decode(token, "wrong-secret", algorithms=[settings.algorithm])


def test_password_hash_roundtrip():
    h = security.hash_password("s3cret!")
    assert h != "s3cret!"
    assert security.verify_password("s3cret!", h)
    assert not security.verify_password("wrong", h)


# ── Roles & permissions ───────────────────────────────────────────────────────
def test_three_canonical_roles_defined():
    names = {name for name, _, _ in ROLE_DEFINITIONS}
    assert names == {"viewer", "analyst", "admin"} == set(ALL_ROLES)


def test_viewer_is_read_only():
    assert has_permission(RoleName.VIEWER, "alerts", "read")
    assert not has_permission(RoleName.VIEWER, "alerts", "write")
    assert not has_permission(RoleName.VIEWER, "actions", "approve")
    assert not has_permission(RoleName.VIEWER, "detection", "run")


def test_analyst_can_operate_but_not_admin_only():
    for resource, action in [("alerts", "write"), ("detection", "run"),
                             ("actions", "approve"), ("actions", "execute"),
                             ("reports", "generate")]:
        assert has_permission(RoleName.ANALYST, resource, action)
    # analyst has no wildcard / user management
    assert not has_permission(RoleName.ANALYST, "users", "manage")


def test_admin_wildcard_grants_everything():
    for resource, action in [("alerts", "delete"), ("users", "manage"),
                             ("anything", "whatever")]:
        assert has_permission(RoleName.ADMIN, resource, action)


def test_unknown_role_has_nothing():
    assert not has_permission(None, "alerts", "read")
    assert not has_permission("ghost", "alerts", "read")


def test_role_hierarchy():
    assert role_at_least(RoleName.ADMIN, RoleName.ANALYST)
    assert role_at_least(RoleName.ANALYST, RoleName.VIEWER)
    assert not role_at_least(RoleName.VIEWER, RoleName.ANALYST)


def test_permission_map_has_no_typos():
    # every role in the map is a known role
    assert set(ROLE_PERMISSIONS) <= set(ALL_ROLES)


# ── require_roles / require_permission behavior (logic, no HTTP) ───────────────
class _FakeUser:
    def __init__(self, role_name):
        self.id = uuid.uuid4()
        self.role = type("R", (), {"name": role_name})()


async def _run_guard(dep, user):
    # Resolve the inner dependency function directly with our fake user.
    return await dep(current_user=user)


@pytest.mark.asyncio
async def test_require_roles_allows_admin_implicitly():
    from app.dependencies import require_roles
    guard = require_roles("analyst")          # admin not listed
    admin = _FakeUser("admin")
    assert await _run_guard(guard, admin) is admin   # admin still passes


@pytest.mark.asyncio
async def test_require_roles_denies_viewer_on_write():
    from app.dependencies import require_roles
    from app.core.exceptions import ForbiddenError
    guard = require_roles("analyst", "admin")
    with pytest.raises(ForbiddenError):
        await _run_guard(guard, _FakeUser("viewer"))


@pytest.mark.asyncio
async def test_require_permission_checks_map():
    from app.dependencies import require_permission
    from app.core.exceptions import ForbiddenError
    approve = require_permission("actions", "approve")
    assert await _run_guard(approve, _FakeUser("analyst"))
    with pytest.raises(ForbiddenError):
        await _run_guard(approve, _FakeUser("viewer"))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
