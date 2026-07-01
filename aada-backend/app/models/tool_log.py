"""
tool_logs — granular record of every MCP tool invocation made by the AI agent.
Each Action triggers one or more tool calls (e.g. block_ip may call
firewall_api then verify_block). Captures input/output for debugging and auditing.
"""
from __future__ import annotations
import uuid
import enum
from datetime import datetime
from typing import TYPE_CHECKING
from sqlalchemy import String, Text, Integer, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.action import Action


class ToolStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class ToolLog(Base, UUIDMixin):
    __tablename__ = "tool_logs"

    # Tool identity
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tool_version: Mapped[str | None] = mapped_column(String(50))

    # Call details
    input_params: Mapped[dict | None] = mapped_column(JSONB)
    output: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[ToolStatus] = mapped_column(SAEnum(ToolStatus), nullable=False, index=True)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Performance
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # When
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # FK — which action triggered this tool call
    action_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("actions.id", ondelete="SET NULL"),
        nullable=True, index=True
    )

    # Relationships
    action: Mapped["Action | None"] = relationship("Action", back_populates="tool_logs")

    def __repr__(self) -> str:
        return f"<ToolLog id={self.id} tool={self.tool_name} status={self.status} {self.duration_ms}ms>"
