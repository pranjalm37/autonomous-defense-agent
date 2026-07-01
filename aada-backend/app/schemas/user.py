import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    password: str
    role: str = "viewer"       # Role.name; resolved to role_id on create (least privilege)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)  # enables ORM mode

    id: uuid.UUID
    email: EmailStr
    username: str
    full_name: str
    role: str | None = None        # serialized from the Role relationship
    role_id: uuid.UUID | None = None
    is_active: bool
    is_mfa_enabled: bool
    created_at: datetime

    @field_validator("role", mode="before")
    @classmethod
    def role_to_name(cls, v):
        """Accept either a Role ORM object or a plain string."""
        if v is None or isinstance(v, str):
            return v
        return getattr(v, "name", None)


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
