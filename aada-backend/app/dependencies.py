import uuid

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.roles import RoleName, has_permission
from app.core.security import decode_token
from app.db.session import get_db
from app.models.user import User

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validates the Bearer token and returns the active User.
    The role relationship is eager-loaded so RBAC checks and serialization
    never trigger a lazy load (which fails under async).
    Raises UnauthorizedError on any failure — no leaking of why.
    """
    if not credentials:
        raise UnauthorizedError()

    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise UnauthorizedError("Invalid token type")
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise UnauthorizedError("Invalid or expired token")

    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise UnauthorizedError("User not found or inactive")

    return user


def require_roles(*role_names: str):
    """
    Role-based access control factory (coarse). Compares against Role.name.
    `admin` always passes — it need not be listed at every call site.
    Usage: Depends(require_roles("analyst", "admin"))
    """
    allowed = set(role_names) | {RoleName.ADMIN}

    async def _check(current_user: User = Depends(get_current_user)) -> User:
        current = current_user.role.name if current_user.role else None
        if current not in allowed:
            raise ForbiddenError(f"Role '{current}' cannot access this resource")
        return current_user

    return _check


def require_permission(resource: str, action: str):
    """
    Permission-based access control factory (fine-grained). Checks the role's
    permission map. Usage: Depends(require_permission("actions", "approve"))
    """
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        role = current_user.role.name if current_user.role else None
        if not has_permission(role, resource, action):
            raise ForbiddenError(f"Role '{role}' lacks permission {resource}:{action}")
        return current_user

    return _check
