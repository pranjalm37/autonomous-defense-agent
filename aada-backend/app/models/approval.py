"""
approvals — human-in-the-loop decisions on proposed actions.
One action can have multiple approval records if a denial triggers escalation
and a different reviewer later approves. The latest record wins.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.action import Action
    from app.models.user import User


class ApprovalDecision(str, enum.Enum):
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"


class Approval(Base, UUIDMixin):
    __tablename__ = "approvals"

    decision: Mapped[ApprovalDecision] = mapped_column(
        SAEnum(ApprovalDecision), nullable=False, index=True
    )
    notes: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # FKs
    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("actions.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    reviewer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False, index=True
    )
    escalated_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    # Relationships
    action: Mapped["Action"] = relationship("Action", back_populates="approvals")
    reviewer: Mapped["User"] = relationship(
        "User", foreign_keys=[reviewer_id], back_populates="approvals"
    )
    escalated_to: Mapped["User | None"] = relationship("User", foreign_keys=[escalated_to_id])

    def __repr__(self) -> str:
        return f"<Approval id={self.id} decision={self.decision} action={self.action_id}>"
