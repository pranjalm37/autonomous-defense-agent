import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.models.alert import Alert, Severity, AlertStatus
from app.models.user import User
from app.schemas.alert import AlertCreate, AlertUpdate, AlertResponse, AlertListResponse
from app.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    severity: Severity | None = Query(None),
    status: AlertStatus | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),   # any authenticated user
) -> AlertListResponse:
    q = select(Alert)
    if severity:
        q = q.where(Alert.severity == severity)
    if status:
        q = q.where(Alert.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    items_result = await db.execute(q.offset(offset).limit(limit).order_by(Alert.created_at.desc()))
    return AlertListResponse(total=total, items=list(items_result.scalars().all()))


@router.post("", response_model=AlertResponse, status_code=201)
async def create_alert(
    payload: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> Alert:
    alert = Alert(**payload.model_dump())
    db.add(alert)
    await db.flush()
    logger.info("alert_created", alert_id=str(alert.id), severity=alert.severity, user_id=str(current_user.id))
    return alert


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Alert:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise NotFoundError("Alert", str(alert_id))
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: uuid.UUID,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Alert:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise NotFoundError("Alert", str(alert_id))

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(alert, field, value)

    logger.info("alert_updated", alert_id=str(alert_id), changes=payload.model_dump(exclude_none=True), user_id=str(current_user.id))
    return alert


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> None:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise NotFoundError("Alert", str(alert_id))
    await db.delete(alert)
