"""Hunt API routes."""

import logging
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse

from artemis.api.schemas import HuntRequest, ContinuousHuntRequest
from artemis.managers import db_manager, hunt_manager
from artemis.utils.report_generator import generate_html_report

logger = logging.getLogger("artemis.api.hunts")

router = APIRouter()


@router.post("/api/hunt")
async def start_hunt(request: HuntRequest, background_tasks: BackgroundTasks):
    """Start a new threat hunt."""
    hunt_id = f"hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    logger.info(
        f"Starting hunt {hunt_id}: time_range={request.time_range}, "
        f"mode={request.mode}"
    )
    background_tasks.add_task(
        hunt_manager.execute_hunt,
        hunt_id,
        request.time_range,
        request.mode,
        request.description,
    )
    return {'hunt_id': hunt_id, 'status': 'started'}


@router.get("/api/hunts")
async def list_hunts(limit: int = 50):
    """List recent hunts."""
    return db_manager.get_recent_hunts(limit)


@router.get("/api/hunts/active")
async def get_active_hunts():
    """Get currently running hunts with their latest progress state."""
    active = []
    for hunt_id, state in hunt_manager.active_hunts.items():
        if state.get('status') == 'running':
            entry = {
                'hunt_id': hunt_id,
                'status': 'running',
                'progress': state.get('progress', 0),
                'start_time': (
                    state['start_time'].isoformat()
                    if isinstance(state.get('start_time'), datetime)
                    else state.get('start_time')
                ),
                'last_progress': state.get('last_progress'),
            }
            active.append(entry)
    return active


@router.get("/api/hunts/{hunt_id}")
async def get_hunt(hunt_id: str):
    """Get hunt details."""
    hunt = db_manager.get_hunt_details(hunt_id)
    if not hunt:
        return JSONResponse(status_code=404, content={'error': 'Hunt not found'})
    return hunt


@router.get("/api/hunts/{hunt_id}/report")
async def get_hunt_report(hunt_id: str):
    """Generate and download an HTML report for a hunt."""
    hunt = db_manager.get_hunt_details(hunt_id)
    if not hunt:
        return JSONResponse(status_code=404, content={'error': 'Hunt not found'})
    html = generate_html_report(hunt)
    return HTMLResponse(
        content=html,
        headers={
            'Content-Disposition':
                f'attachment; filename="artemis_report_{hunt_id}.html"'
        },
    )


@router.delete("/api/hunts/{hunt_id}")
async def delete_hunt(hunt_id: str):
    """Delete a hunt and its findings."""
    if (hunt_id in hunt_manager.active_hunts
            and hunt_manager.active_hunts[hunt_id].get('status') == 'running'):
        return {'error': 'Cannot delete a running hunt'}
    deleted = db_manager.delete_hunt(hunt_id)
    if not deleted:
        return {'error': 'Hunt not found'}
    hunt_manager.active_hunts.pop(hunt_id, None)
    logger.info(f"Deleted hunt: {hunt_id}")
    return {'status': 'deleted', 'hunt_id': hunt_id}


# --- Continuous hunting ---------------------------------------------------

@router.post("/api/hunt/continuous/start")
async def start_continuous_hunt(request: ContinuousHuntRequest):
    """Start continuous hunting with a rolling time window."""
    try:
        hunt_manager.start_continuous(
            request.interval_minutes,
            request.lookback_minutes,
            request.mode,
        )
        return {
            'status': 'started',
            'interval_minutes': request.interval_minutes,
            'lookback_minutes': request.lookback_minutes,
        }
    except RuntimeError as e:
        return JSONResponse(status_code=409, content={'error': str(e)})


@router.post("/api/hunt/continuous/stop")
async def stop_continuous_hunt():
    """Stop continuous hunting after the current cycle finishes."""
    try:
        hunt_manager.stop_continuous()
        return {'status': 'stopping'}
    except RuntimeError as e:
        return JSONResponse(status_code=409, content={'error': str(e)})


@router.get("/api/hunt/continuous/status")
async def continuous_hunt_status():
    """Get continuous hunting status."""
    return hunt_manager.get_continuous_status()
