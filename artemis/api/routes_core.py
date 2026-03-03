"""Core routes: health, static files, WebSocket, server lifecycle."""

import logging
import os
import signal
import threading

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from artemis.managers import hunt_manager, plugin_manager
from artemis.ws import active_connections, broadcast_progress

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


# ── Server shutdown ──────────────────────────────────────────────────

@router.post("/api/server/shutdown")
async def shutdown_server():
    """Kill all child processes and shut down the Artemis server.

    This kills every tracked subprocess (pipelines, profilers, etc.)
    then sends SIGTERM to the server's own process so uvicorn exits
    cleanly.  The response is returned before the server actually dies
    so the UI gets confirmation.
    """
    # 1. Kill all child processes synchronously
    result = hunt_manager.kill_all_processes()

    # 2. Stop the hunt scheduler if running
    try:
        import artemis.managers.hunt_scheduler as _hs_mod
        scheduler = getattr(_hs_mod, '_global_scheduler', None)
        if scheduler and scheduler.is_running:
            await scheduler.stop()
    except Exception:
        pass

    # 3. Notify WS clients before we go down
    try:
        await broadcast_progress({
            'type': 'server_shutdown',
            'message': 'Server is shutting down',
        })
    except Exception:
        pass

    # 4. Schedule the server to exit shortly (give time for HTTP response)
    def _deferred_exit():
        import time
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_deferred_exit, daemon=True).start()

    return {
        'status': 'shutting_down',
        'children_killed': result['killed'],
        'processes': result['processes'],
    }
