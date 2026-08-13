"""
action_comments — collaborative review discussion on a proposed action.

Distinct from `approvals.notes` (which is the reviewer's decision rationale): a
comment is part of the back-and-forth *before* a decision — an L1 asking a
question, an L2 adding context. The thread is preserved for the audit trail.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.action import Action
    from app.models.user import User


class ActionComment(Base, UUIDMixin):
    __tablename__ = "action_comments"

    body: Mapped[str] = mapped_column(Text, nullable=False)
    author_email: Mapped[str | None] = mapped_column(String(255))  # denormalized — survives user deletion

    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("actions.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    action: Mapped["Action"] = relationship("Action", back_populates="comments")
    user: Mapped["User | None"] = relationship("User")

    def __repr__(self) -> str:
        return f"<ActionComment id={self.id} action={self.action_id}>"
