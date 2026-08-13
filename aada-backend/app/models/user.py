"""
users — SOC analysts, managers, and system accounts that interact with the agent.
Central auth identity; RBAC delegated to the roles table.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.approval import Approval
    from app.models.audit_log import AuditLog
    from app.models.incident import Incident
    from app.models.role import Role


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(255))

    # Auth session tracking
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(INET)
    failed_login_count: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # FK to roles
    role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL")
    )

    # Relationships
    role: Mapped["Role | None"] = relationship("Role", back_populates="users")
    assigned_alerts: Mapped[list["Alert"]] = relationship(
        "Alert", foreign_keys="Alert.assigned_to_id", back_populates="assigned_to"
    )
    assigned_incidents: Mapped[list["Incident"]] = relationship(
        "Incident", foreign_keys="Incident.assigned_to_id", back_populates="assigned_to"
    )
    approvals: Mapped[list["Approval"]] = relationship(
        "Approval", foreign_keys="Approval.reviewer_id", back_populates="reviewer"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
