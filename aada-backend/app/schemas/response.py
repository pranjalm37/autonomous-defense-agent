import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.action import ActionStatus, ActionType
from app.models.approval import ApprovalDecision


class ActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    action_type: ActionType
    status: ActionStatus
    target_type: str
    target_value: str
    ai_justification: str | None
    risk_score: float | None
    reversible: bool
    alert_id: uuid.UUID | None
    created_at: datetime


class ReviewRequest(BaseModel):
    notes: str | None = None


class CommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class CommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    body: str
    author_email: str | None
    user_id: uuid.UUID | None
    created_at: datetime


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    decision: ApprovalDecision
    notes: str | None
    reviewer_id: uuid.UUID
    reviewed_at: datetime


class ActionDetailResponse(ActionResponse):
    """Full action view for the review screen: decision history + comment thread."""
    approvals: list[ApprovalRecord] = Field(default_factory=list)
    comments: list[CommentResponse] = Field(default_factory=list)


class ExecutionResponse(BaseModel):
    ok: bool
    summary: str
    status: ActionStatus
    output: dict = Field(default_factory=dict)
    error: str | None = None
