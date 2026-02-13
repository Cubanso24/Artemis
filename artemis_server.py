#!/usr/bin/env python3
"""
Artemis Server — thin entry-point.

All business logic now lives in dedicated modules:

    artemis/managers/   – DatabaseManager, HuntManager, PluginManager
    artemis/api/        – FastAPI routers (core, hunts, plugins)
    artemis/ws.py       – WebSocket handler + log broadcasting
    artemis/models.py   – Pydantic request models

This file only wires them together, registers lifecycle hooks, and
launches uvicorn.
"""

import logging
import socket

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ── logging (before anything else) ────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("artemis.server")

# ── app ───────────────────────────────────────────────────────────────
app = FastAPI(title="Artemis Threat Hunting Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── routers ───────────────────────────────────────────────────────────
from artemis.api.routes_core import router as core_router        # noqa: E402
from artemis.api.routes_hunts import router as hunts_router      # noqa: E402
from artemis.api.routes_plugins import router as plugins_router  # noqa: E402

app.include_router(core_router)
app.include_router(hunts_router)
app.include_router(plugins_router)

# ── managers & plugins (singletons) ──────────────────────────────────
from artemis.managers import hunt_manager, plugin_manager  # noqa: E402
from artemis.ws import broadcast_progress, install_log_handler  # noqa: E402

# Tell the hunt manager how to push updates to WebSocket clients
hunt_manager._broadcast_fn = broadcast_progress

# Register and auto-enable built-in plugins
from artemis.plugins.network_mapper import NetworkMapperPlugin  # noqa: E402
from artemis.plugins.sigma_engine import SigmaEnginePlugin      # noqa: E402

plugin_manager.register_plugin('network_mapper', NetworkMapperPlugin)
plugin_manager.register_plugin('sigma_engine', SigmaEnginePlugin)
plugin_manager.enable_plugin('network_mapper', {'output_dir': 'network_maps'})
plugin_manager.enable_plugin('sigma_engine', {})


# ── lifecycle hooks ──────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup():
    """Runs once when uvicorn (re)starts the application."""
    install_log_handler()

    # Reconnect to any hunts that survived the previous server process
    hunt_manager.reconnect_running_hunts()
    logger.info("Artemis server started")


@app.on_event("shutdown")
async def on_shutdown():
    """Runs when uvicorn is shutting down (e.g. reload, ctrl-c).

    We intentionally do NOT wait for running hunts — they are non-daemon
    processes that write directly to SQLite, so they keep going on their
    own.  On the next startup we'll reconnect to them.
    """
    # Stop continuous hunting if active
    try:
        if (hunt_manager._continuous_task
                and not hunt_manager._continuous_task.done()):
            hunt_manager._continuous_stop = True
            hunt_manager._continuous_task.cancel()
    except Exception:
        pass

    # Cancel the progress-polling task (it will restart on next startup)
    if hunt_manager._poll_task and not hunt_manager._poll_task.done():
        hunt_manager._poll_task.cancel()

    logger.info("Artemis server shutting down (hunts continue in background)")


# ── main ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    def get_lan_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    lan_ip = get_lan_ip()

    print("=" * 80)
    print("  ARTEMIS THREAT HUNTING PLATFORM")
    print("=" * 80)
    print("\nStarting server on all network interfaces...")
    print("\nAccess Artemis from:")
    print(f"   Local:      http://localhost:8000")
    print(f"   LAN:        http://{lan_ip}:8000")
    print(f"   API Docs:   http://{lan_ip}:8000/docs")
    print(f"\nAnyone on your network can access Artemis at the LAN address")
    print("=" * 80 + "\n")

    uvicorn.run(
        "artemis_server:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=True,
        # Only watch the server entry-point and API routes — changes to
        # plugins, agents, integrations, etc. take effect on the next hunt
        # (they run in subprocesses) without requiring a server restart.
        reload_dirs=["artemis/api"],
        reload_includes=["artemis_server.py", "artemis/ws.py",
                         "artemis/api/*.py", "artemis/managers/*.py"],
    )
