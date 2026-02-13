"""Core routes: health, static files, WebSocket."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from artemis.managers import hunt_manager, plugin_manager
from artemis.ws import active_connections

router = APIRouter()


@router.get("/")
async def root():
    """Serve the web UI."""
    return FileResponse("artemis/web/index.html")


@router.get("/api/status")
async def get_status():
    """Get server status."""
    return {
        'status': 'running',
        'active_hunts': len([
            h for h in hunt_manager.active_hunts.values()
            if h['status'] == 'running'
        ]),
        'plugins': plugin_manager.list_plugins(),
    }


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time hunt updates."""
    await websocket.accept()
    active_connections.append(websocket)

    # Send current state of any running hunts so reconnecting clients resume
    try:
        for hunt_id, state in hunt_manager.active_hunts.items():
            if state.get('status') == 'running' and state.get('last_progress'):
                await websocket.send_json(state['last_progress'])
    except Exception:
        pass

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


@router.get("/static/{path:path}")
async def serve_static(path: str):
    """Serve static files."""
    return FileResponse(f"artemis/web/static/{path}")
