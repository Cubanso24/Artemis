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
    """Start a new threat hunt (or queue it if 2 are already running)."""
    hunt_id = f"hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    time_label = (f"{request.earliest_time} → {request.latest_time}"
                  if request.earliest_time and request.latest_time
                  else request.time_range)
    logger.info(
        f"Starting hunt {hunt_id}: time_range={time_label}, "
        f"mode={request.mode}, storage={request.storage_mode}"
    )
    background_tasks.add_task(
        hunt_manager.execute_hunt,
        hunt_id,
        request.time_range,
        request.mode,
        request.description,
        request.storage_mode,
        request.earliest_time,
        request.latest_time,
    )
    running = hunt_manager._running_count()
    if running >= hunt_manager.MAX_CONCURRENT:
        return {
            'hunt_id': hunt_id,
            'status': 'queued',
            'queue_position': len(hunt_manager._queue) + 1,
        }
    return {'hunt_id': hunt_id, 'status': 'started'}


@router.get("/api/hunts")
async def list_hunts(limit: int = 50):
    """List recent hunts."""
    return db_manager.get_recent_hunts(limit)


@router.get("/api/hunts/active")
async def get_active_hunts():
    """Get currently running and queued hunts with their latest progress state."""
    active = []
    for hunt_id, state in hunt_manager.active_hunts.items():
        status = state.get('status')
        if status in ('running', 'queued'):
            entry = {
                'hunt_id': hunt_id,
                'status': status,
                'progress': state.get('progress', 0),
                'start_time': (
                    state['start_time'].isoformat()
                    if isinstance(state.get('start_time'), datetime)
                    else state.get('start_time')
                ),
                'last_progress': state.get('last_progress'),
            }
            if status == 'queued':
                entry['queue_position'] = state.get('queue_position', 0)
            active.append(entry)
    return active


@router.get("/api/hunt/queue")
async def get_hunt_queue():
    """Get the current hunt queue."""
    return {
        'queue': hunt_manager.get_queue(),
        'running': hunt_manager._running_count(),
        'max_concurrent': hunt_manager.MAX_CONCURRENT,
    }


@router.delete("/api/hunt/queue/{hunt_id}")
async def remove_from_queue(hunt_id: str):
    """Remove a hunt from the queue (before it starts running)."""
    removed = hunt_manager.remove_from_queue(hunt_id)
    if not removed:
        return JSONResponse(
            status_code=404,
            content={'error': 'Hunt not found in queue'},
        )
    return {'status': 'removed', 'hunt_id': hunt_id}


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
