"""
actions — remediation steps proposed by the AI agent.
Every action requires human approval before execution (human-in-the-loop gate),
except for auto-approved low-risk actions configured in settings.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.action_comment import ActionComment
    from app.models.alert import Alert
    from app.models.approval import Approval
    from app.models.incident import Incident
    from app.models.tool_log import ToolLog
    from app.models.user import User


class ActionType(str, enum.Enum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_HOST = "isolate_host"
    UNISOLATE_HOST = "unisolate_host"
    KILL_PROCESS = "kill_process"
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE = "delete_file"
    REVOKE_SESSION = "revoke_session"
    PATCH_VULNERABILITY = "patch_vulnerability"
    RESET_PASSWORD = "reset_password"
    # Response-engine notification / workflow actions
    SEND_ALERT = "send_alert"
    GENERATE_TICKET = "generate_ticket"
    INCREASE_LOGGING = "increase_logging"
    DECREASE_LOGGING = "decrease_logging"
    CUSTOM = "custom"


class ActionStatus(str, enum.Enum):
    PENDING = "pending"         # awaiting approval
    APPROVED = "approved"       # approval granted, not yet executed
    DENIED = "denied"           # reviewer rejected it
    EXECUTING = "executing"     # MCP tool call in progress
    COMPLETED = "completed"     # tool returned success
    FAILED = "failed"           # tool returned error
    ROLLED_BACK = "rolled_back" # reversal executed


class Action(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "actions"

    action_type: Mapped[ActionType] = mapped_column(SAEnum(ActionType), nullable=False, index=True)
    status: Mapped[ActionStatus] = mapped_column(
        SAEnum(ActionStatus), nullable=False, default=ActionStatus.PENDING, index=True
    )

    # What to act on
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ip / host / process / user / file
    target_value: Mapped[str] = mapped_column(Text, nullable=False)
    parameters: Mapped[dict | None] = mapped_column(JSONB)

    # AI reasoning for this action
    ai_justification: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[float | None] = mapped_column(Float)  # 0.0 (safe) – 1.0 (destructive)

    # Reversibility
    reversible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rollback_procedure: Mapped[str | None] = mapped_column(Text)

    # Execution metadata
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    # FKs
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    executed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    # Relationships
    alert: Mapped["Alert | None"] = relationship("Alert", back_populates="actions")
    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="actions")
    executed_by: Mapped["User | None"] = relationship("User", foreign_keys=[executed_by_id])
    approvals: Mapped[list["Approval"]] = relationship("Approval", back_populates="action")
    tool_logs: Mapped[list["ToolLog"]] = relationship("ToolLog", back_populates="action")
    comments: Mapped[list["ActionComment"]] = relationship(
        "ActionComment", back_populates="action", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Action id={self.id} type={self.action_type} status={self.status}>"
