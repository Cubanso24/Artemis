"""Core routes: health, static files, WebSocket."""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from artemis.managers import plugin_manager
from artemis.ws import active_connections

logger = logging.getLogger("artemis.api.routes_core")

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
        'plugins': plugin_manager.list_plugins(),
    }


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time progress updates."""
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


@router.get("/static/{path:path}")
async def serve_static(path: str):
    """Serve static files."""
    return FileResponse(f"artemis/web/static/{path}")
