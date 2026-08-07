from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, alerts, events, detection, knowledge, analyst, decision, response,
    audit, reports, health, simulator,
)

router = APIRouter()

router.include_router(health.router)
router.include_router(auth.router)
router.include_router(alerts.router)
router.include_router(events.router)
router.include_router(detection.router)
router.include_router(simulator.router)
router.include_router(knowledge.router)
router.include_router(analyst.router)
router.include_router(decision.router)
router.include_router(response.router)
router.include_router(audit.router)
router.include_router(reports.router)
