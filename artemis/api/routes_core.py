"""Core routes: health, static files, WebSocket, server lifecycle."""

import logging
import os
import signal
import threading

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from artemis.managers import hunt_manager, plugin_manager
from artemis.ws import active_connections, broadcast_progress, agent_activity_history

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


@router.get("/api/agent-activity")
async def get_agent_activity(since_id: int = 0):
    """Return agent activity events from the DB.

    Pass ``since_id`` to get only newer events (for incremental polling).
    """
    from artemis.managers.db_manager import DatabaseManager
    db = DatabaseManager()
    return db.get_agent_activity(since_id=since_id, limit=200)


@router.get("/api/system-resources")
async def get_system_resources():
    """Return current system resource usage (CPU, RAM, disk, GPU, network)."""
    import psutil
    import time

    cpu_pct = psutil.cpu_percent(interval=0)
    cpu_count = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq()

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')

    net = psutil.net_io_counters()
    boot_time = psutil.boot_time()
    uptime = int(time.time() - boot_time)

    result = {
        'cpu': {
            'percent': cpu_pct,
            'count': cpu_count,
            'freq_mhz': round(cpu_freq.current, 0) if cpu_freq else None,
        },
        'memory': {
            'total': mem.total,
            'used': mem.used,
            'available': mem.available,
            'percent': mem.percent,
        },
        'swap': {
            'total': swap.total,
            'used': swap.used,
            'percent': swap.percent,
        },
        'disk': {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent,
        },
        'network': {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv,
        },
        'uptime_seconds': uptime,
    }

    # GPU detection (nvidia-smi)
    try:
        import subprocess
        nv = subprocess.run(
            ['nvidia-smi', '--query-gpu=utilization.gpu,memory.used,memory.total,name',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=3,
        )
        if nv.returncode == 0 and nv.stdout.strip():
            gpus = []
            for line in nv.stdout.strip().split('\n'):
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 4:
                    gpus.append({
                        'name': parts[3],
                        'utilization': float(parts[0]),
                        'memory_used_mb': float(parts[1]),
                        'memory_total_mb': float(parts[2]),
                    })
            result['gpus'] = gpus
    except Exception:
        result['gpus'] = []

    return result


@router.delete("/api/agent-activity")
async def clear_agent_activity():
    """Delete all agent activity events from the DB."""
    from artemis.managers.db_manager import DatabaseManager
    db = DatabaseManager()
    db.clear_agent_activity()
    return {"status": "cleared"}


@router.get("/static/{path:path}")
async def serve_static(path: str):
    """Serve static files."""
    return FileResponse(f"artemis/web/static/{path}")


# ── Server shutdown ──────────────────────────────────────────────────

def _is_systemd() -> bool:
    """Return True if we were launched by the artemis systemd unit."""
    return os.environ.get('ARTEMIS_SYSTEMD') == '1'


@router.post("/api/server/shutdown")
async def shutdown_server():
    """Kill all child processes and shut down the Artemis server.

    Under systemd: ``systemctl stop artemis`` kills the whole cgroup.
    Dev mode: manually SIGTERM/SIGKILL tracked children, then self-SIGTERM.
    """
    # 1. Notify WS clients before we go down
    try:
        await broadcast_progress({
            'type': 'server_shutdown',
            'message': 'Server is shutting down',
        })
    except Exception:
        pass

    if _is_systemd():
        # systemd will SIGTERM our entire control-group (KillMode=control-group)
        # so every child process dies automatically — no manual PID work needed.
        def _deferred_systemctl():
            import subprocess, time
            time.sleep(0.5)
            subprocess.Popen(
                ['sudo', 'systemctl', 'stop', 'artemis'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        threading.Thread(target=_deferred_systemctl, daemon=True).start()
        return {
            'status': 'shutting_down',
            'method': 'systemctl',
            'children_killed': 'all (control-group)',
        }

    # ── Dev / manual mode ──────────────────────────────────────────
    result = hunt_manager.kill_all_processes()

    # Stop the hunt scheduler if running
    try:
        import artemis.managers.hunt_scheduler as _hs_mod
        scheduler = getattr(_hs_mod, '_global_scheduler', None)
        if scheduler and scheduler.is_running:
            await scheduler.stop()
    except Exception:
        pass

    # Schedule the server to exit shortly (give time for HTTP response)
    def _deferred_exit():
        import time
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_deferred_exit, daemon=True).start()

    return {
        'status': 'shutting_down',
        'method': 'manual',
        'children_killed': result['killed'],
        'processes': result['processes'],
    }
