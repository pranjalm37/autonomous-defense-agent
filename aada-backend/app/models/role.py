"""
roles — fine-grained permission sets assigned to users.
Exists so permissions can be updated at runtime without code deploys.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
from sqlalchemy import String, Text, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class Role(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "roles"

    # name is the unique machine key (e.g. "analyst_l1"); label is display text
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # JSON object: {"alerts": ["read","write"], "approvals": ["read"], ...}
    permissions: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")

    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="role")

    def __repr__(self) -> str:
        return f"<Role name={self.name}>"
