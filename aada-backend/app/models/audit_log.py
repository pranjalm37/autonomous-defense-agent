"""
audit_logs — immutable record of every state-changing operation in the system.
Written by the AuditMiddleware on every mutating request. Never updated or deleted.
Used for compliance (SOC 2, ISO 27001) and forensic reconstruction.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_logs"

    # Who
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    user_email: Mapped[str | None] = mapped_column(String(255))  # denormalized — survives user deletion

    # What
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="system", index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)

    # Change payload
    old_value: Mapped[dict | None] = mapped_column(JSONB)
    new_value: Mapped[dict | None] = mapped_column(JSONB)

    # Request context
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Relationships
    user: Mapped["User | None"] = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} resource={self.resource_type}/{self.resource_id}>"
