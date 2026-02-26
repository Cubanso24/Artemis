"""Case management and hunt scheduler API routes."""

import logging
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from artemis.managers import db_manager

logger = logging.getLogger("artemis.api.cases")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class CaseVerdictRequest(BaseModel):
    """Submit an analyst verdict for a case."""
    verdict: str       # tp, fp, uncertain
    notes: str = ""


class CaseUpdateRequest(BaseModel):
    """Update case fields."""
    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    severity: Optional[str] = None


class SchedulerConfigRequest(BaseModel):
    """Update scheduler configuration."""
    interval_minutes: Optional[int] = None
    enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# Case endpoints
# ---------------------------------------------------------------------------

@router.get("/api/cases")
async def list_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    escalation_level: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100,
):
    """List cases with optional filtering."""
    cases = db_manager.get_cases(
        limit=limit,
        status=status,
        severity=severity,
        escalation_level=escalation_level,
        source=source,
    )
    return {"cases": cases, "total": len(cases)}


@router.get("/api/cases/stats")
async def case_stats():
    """Get case summary statistics."""
    return db_manager.get_case_stats()


@router.get("/api/cases/timeline")
async def case_timeline(limit: int = 50):
    """Get recent cases ordered chronologically for timeline view."""
    cases = db_manager.get_cases(limit=limit)
    return {"timeline": cases}


@router.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    """Get a single case with linked findings."""
    case = db_manager.get_case(case_id)
    if not case:
        return JSONResponse(status_code=404, content={"error": "Case not found"})

    # Attach full finding details for the linked finding IDs
    finding_details = []
    for fid in case.get("findings", []):
        findings = db_manager.get_findings(limit=1)
        for f in db_manager.get_findings(limit=500):
            if f.get("finding_id") == fid:
                finding_details.append(f)
                break
    case["finding_details"] = finding_details
    return case


@router.patch("/api/cases/{case_id}")
async def update_case(case_id: str, body: CaseUpdateRequest):
    """Update case status or analyst notes."""
    existing = db_manager.get_case(case_id)
    if not existing:
        return JSONResponse(status_code=404, content={"error": "Case not found"})

    updates = {}
    if body.status is not None:
        updates["status"] = body.status
    if body.analyst_notes is not None:
        updates["analyst_notes"] = body.analyst_notes
    if body.severity is not None:
        updates["severity"] = body.severity

    if updates:
        db_manager.update_case(case_id, **updates)

    return db_manager.get_case(case_id)


@router.post("/api/cases/{case_id}/verdict")
async def submit_verdict(case_id: str, body: CaseVerdictRequest):
    """Submit an analyst verdict for a case.

    This triggers the self-learning feedback loop:
    1. Resolves the case with the verdict
    2. Updates technique precision for all linked MITRE techniques
    3. Feeds back into the adaptive learner (via coordinator)
    """
    if body.verdict not in ("tp", "fp", "uncertain"):
        return JSONResponse(
            status_code=400,
            content={"error": "verdict must be tp, fp, or uncertain"},
        )

    existing = db_manager.get_case(case_id)
    if not existing:
        return JSONResponse(status_code=404, content={"error": "Case not found"})

    # Resolve the case
    db_manager.resolve_case(case_id, body.verdict, body.notes)

    # Update technique precision for all techniques in the case
    for technique in existing.get("mitre_techniques", []):
        db_manager.update_technique_precision(technique, body.verdict)

    updated = db_manager.get_case(case_id)
    logger.info(
        f"Case {case_id} resolved as {body.verdict} — "
        f"updated precision for {len(existing.get('mitre_techniques', []))} techniques"
    )
    return {
        "case": updated,
        "feedback_applied": True,
        "techniques_updated": existing.get("mitre_techniques", []),
    }


# ---------------------------------------------------------------------------
# Technique precision endpoints
# ---------------------------------------------------------------------------

@router.get("/api/technique-precision")
async def get_technique_precision():
    """Get precision tracking data for all MITRE techniques with verdicts."""
    return db_manager.get_technique_precision()


# ---------------------------------------------------------------------------
# Scheduler endpoints
# ---------------------------------------------------------------------------

@router.get("/api/scheduler")
async def scheduler_status():
    """Get current hunt scheduler status."""
    state = db_manager.get_scheduler_state()
    if not state:
        return {"status": "not_initialized", "message": "Scheduler has not been started yet"}
    return state


@router.post("/api/scheduler/start")
async def start_scheduler():
    """Start the autonomous hunt scheduler.

    The actual scheduler instance is managed by the server lifecycle.
    This endpoint signals intent; the server's hunt_scheduler handles execution.
    """
    # Import the global scheduler reference set by artemis_server.py
    try:
        from artemis.managers import hunt_scheduler as _hs_module
        scheduler = getattr(_hs_module, '_global_scheduler', None)
        if scheduler:
            await scheduler.start()
            return {"status": "started", "message": "Hunt scheduler started"}
        else:
            db_manager.update_scheduler_state(status="running")
            return {"status": "started", "message": "Scheduler state updated"}
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/api/scheduler/stop")
async def stop_scheduler():
    """Stop the autonomous hunt scheduler."""
    try:
        from artemis.managers import hunt_scheduler as _hs_module
        scheduler = getattr(_hs_module, '_global_scheduler', None)
        if scheduler:
            await scheduler.stop()
            return {"status": "stopped", "message": "Hunt scheduler stopped"}
        else:
            db_manager.update_scheduler_state(status="stopped")
            return {"status": "stopped", "message": "Scheduler state updated"}
    except Exception as e:
        logger.error(f"Failed to stop scheduler: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.patch("/api/scheduler/config")
async def update_scheduler_config(body: SchedulerConfigRequest):
    """Update scheduler configuration (interval, enable/disable)."""
    try:
        from artemis.managers import hunt_scheduler as _hs_module
        scheduler = getattr(_hs_module, '_global_scheduler', None)
        if scheduler and body.interval_minutes is not None:
            scheduler.update_interval(body.interval_minutes)
        return {"message": "Scheduler configuration updated",
                "interval_minutes": body.interval_minutes}
    except Exception as e:
        logger.error(f"Failed to update scheduler config: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
