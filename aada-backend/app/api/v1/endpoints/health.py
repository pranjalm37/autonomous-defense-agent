from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Liveness + DB connectivity check. Used by Docker/k8s probes."""
    await db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected"}
