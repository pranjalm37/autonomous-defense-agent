import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.dependencies import get_current_user
from app.logging_config import get_logger
from app.models.role import Role
from app.models.user import User
from app.schemas.token import Token
from app.schemas.user import UserCreate, UserResponse
from app.services import audit
from app.services.audit import AuditAction

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(payload: UserCreate, request: Request, db: AsyncSession = Depends(get_db)) -> User:
    """Create a new account. `role` is a Role.name; defaults to 'viewer'."""
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise ConflictError(f"Email '{payload.email}' already registered")

    role = (await db.execute(select(Role).where(Role.name == payload.role))).scalar_one_or_none()
    if role is None:
        raise NotFoundError(f"Role '{payload.role}' does not exist")

    user = User(
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role_id=role.id,
    )
    user.role = role            # populate relationship in-memory (no lazy load on response)
    db.add(user)
    await db.flush()            # get user.id without committing (session.py commits on exit)
    audit.record(
        db, action=AuditAction.AUTH_REGISTER, resource_type="user", resource_id=user.id,
        ctx=audit.audit_context_from_request(request, user),
        new_value={"email": user.email, "role": role.name},
    )
    logger.info("user_registered", user_id=str(user.id), email=user.email, role=role.name)
    return user


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Token:
    """
    Standard OAuth2 password flow.
    Returns both access (30 min) and refresh (7 day) tokens.
    """
    result = await db.execute(select(User).where(User.email == form.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form.password, user.hashed_password):
        # Audit failed attempts (no user binding) — the email is the only signal.
        # Commit explicitly: the request raises, which would otherwise roll back
        # the session and lose this security-relevant record.
        audit.record(
            db, action=AuditAction.AUTH_LOGIN_FAILED, resource_type="user",
            ctx=audit.audit_context_from_request(request, None),
            user_email=form.username, new_value={"reason": "invalid_credentials"},
        )
        await db.commit()
        raise UnauthorizedError("Invalid email or password")
    if not user.is_active:
        raise UnauthorizedError("Account is disabled")

    audit.record(
        db, action=AuditAction.AUTH_LOGIN, resource_type="user", resource_id=user.id,
        ctx=audit.audit_context_from_request(request, user),
    )
    logger.info("user_login", user_id=str(user.id), email=user.email)
    return Token(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=Token)
async def refresh(refresh_token: str, db: AsyncSession = Depends(get_db)) -> Token:
    """Exchange a valid refresh token for a new token pair."""
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise UnauthorizedError("Not a refresh token")
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise UnauthorizedError("Invalid or expired refresh token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise UnauthorizedError()

    return Token(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user's profile."""
    return current_user
