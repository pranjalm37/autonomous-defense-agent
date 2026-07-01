"""
Database seeding — roles (and an optional bootstrap admin).

Roles must exist before anyone can register or log in (registration assigns a
role by name). This seeds the three canonical roles idempotently, so it is safe
to run on every startup and re-run any time.

    python -m app.db.seed          # seed roles (+ admin if configured in .env)

Startup also calls `seed()` best-effort (see app/main.py) when AUTO_SEED is on.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.roles import ROLE_DEFINITIONS, ROLE_PERMISSIONS
from app.core.security import hash_password
from app.logging_config import get_logger
from app.models.role import Role
from app.models.user import User

logger = get_logger(__name__)


async def seed_roles(db: AsyncSession) -> int:
    """Upsert the three canonical roles with their permission maps."""
    count = 0
    for name, label, description in ROLE_DEFINITIONS:
        perms = ROLE_PERMISSIONS.get(name, {})
        existing = (await db.execute(select(Role).where(Role.name == name))).scalar_one_or_none()
        if existing:
            existing.label = label
            existing.description = description
            existing.permissions = perms
        else:
            db.add(Role(name=name, label=label, description=description,
                        permissions=perms, is_system=True))
            count += 1
    logger.info("seed_roles", created=count, total=len(ROLE_DEFINITIONS))
    return count


async def seed_default_admin(db: AsyncSession, email: str | None, password: str | None) -> bool:
    """Create a bootstrap admin from config if one doesn't already exist.

    Idempotent on BOTH email and username, so repeated startups (and multiple
    uvicorn workers racing) don't hit the unique-constraint on either column.
    """
    if not email or not password:
        return False
    username = email.split("@")[0] or "admin"
    existing = (await db.execute(
        select(User).where(or_(User.email == email, User.username == username))
    )).scalar_one_or_none()
    if existing:
        return False
    admin_role = (await db.execute(select(Role).where(Role.name == "admin"))).scalar_one_or_none()
    db.add(User(
        email=email, username=username, full_name="Administrator",
        hashed_password=hash_password(password),
        role_id=admin_role.id if admin_role else None,
    ))
    logger.info("seed_default_admin", email=email, username=username)
    return True


async def seed(db: AsyncSession) -> None:
    from app.config import get_settings
    s = get_settings()
    await seed_roles(db)
    # Flush so the just-added roles are visible to the admin's role lookup —
    # the session has autoflush=False, so without this the lookup returns None
    # and the bootstrap admin would be created with no role.
    await db.flush()
    await seed_default_admin(
        db, getattr(s, "default_admin_email", None), getattr(s, "default_admin_password", None)
    )


async def _main() -> None:
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        await seed(session)
        await session.commit()
    print("Seeding complete.")


if __name__ == "__main__":
    asyncio.run(_main())
