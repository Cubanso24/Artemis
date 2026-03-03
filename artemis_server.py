#!/usr/bin/env python3
"""
Artemis Server — thin entry-point.

All business logic now lives in dedicated modules:

    artemis/managers/   – DatabaseManager, HuntManager, PluginManager
    artemis/api/        – FastAPI routers (core, plugins)
    artemis/ws.py       – WebSocket handler + log broadcasting

This file only wires them together, registers lifecycle hooks, and
launches uvicorn.
"""

import logging
import os
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
app = FastAPI(title="Artemis Network Mapping Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── routers ───────────────────────────────────────────────────────────
from artemis.api.routes_core import router as core_router        # noqa: E402
from artemis.api.routes_plugins import router as plugins_router  # noqa: E402
from artemis.api.routes_cases import router as cases_router      # noqa: E402

app.include_router(core_router)
app.include_router(plugins_router)
app.include_router(cases_router)

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

    # Reconnect to any profiling jobs that survived the previous server process
    hunt_manager.reconnect_running_jobs()

    # Start background threat intel enrichment worker
    from artemis.integrations.threat_intel import threat_intel_manager  # noqa: E402
    threat_intel_manager.start_background_worker()

    # Initialize autonomous case generation (connects coordinator → db_manager)
    from artemis.managers import db_manager as _db  # noqa: E402
    try:
        coordinator = getattr(hunt_manager, '_coordinator', None)
        if coordinator and hasattr(coordinator, 'init_case_generator'):
            coordinator.init_case_generator(
                db_manager=_db,
                auto_respond_threshold=0.95,
                auto_investigate_threshold=0.80,
                auto_case_threshold=0.60,
            )
            logger.info("Autonomous case generation enabled")
    except Exception as e:
        logger.warning(f"Case generator init skipped: {e}")

    # Start hunt scheduler if configured for auto-start
    try:
        from artemis.managers.hunt_scheduler import HuntScheduler  # noqa: E402
        import artemis.managers.hunt_scheduler as _hs_mod  # noqa: E402
        scheduler = HuntScheduler(
            hunt_manager=hunt_manager,
            db_manager=_db,
            interval_minutes=15,
        )
        _hs_mod._global_scheduler = scheduler
        # Auto-start is off by default; start via POST /api/scheduler/start
        logger.info("Hunt scheduler initialized (start via API)")
    except ImportError:
        logger.info("apscheduler not installed — hunt scheduler disabled")
    except Exception as e:
        logger.warning(f"Hunt scheduler init skipped: {e}")

    logger.info("Artemis server started")


@app.on_event("shutdown")
async def on_shutdown():
    """Runs when uvicorn is shutting down (systemctl stop, ctrl-c, reload).

    Under systemd KillMode=control-group ensures every child dies, but we
    still do orderly cleanup here so dev-mode ctrl-c is also clean.
    """
    # Kill all tracked child processes (pipelines, profilers, etc.)
    try:
        result = hunt_manager.kill_all_processes()
        logger.info(f"Shutdown: killed {result['killed']} child process(es)")
    except Exception as e:
        logger.warning(f"Shutdown: child cleanup failed: {e}")

    # Cancel the progress-polling task (it will restart on next startup)
    if hunt_manager._poll_task and not hunt_manager._poll_task.done():
        hunt_manager._poll_task.cancel()

    # Stop the hunt scheduler if running
    try:
        import artemis.managers.hunt_scheduler as _hs_mod  # noqa: E402
        scheduler = getattr(_hs_mod, '_global_scheduler', None)
        if scheduler and scheduler.is_running:
            await scheduler.stop()
    except Exception:
        pass

    logger.info("Artemis server shutting down")


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
    print("  ARTEMIS NETWORK MAPPING PLATFORM")
    print("=" * 80)
    print("\nStarting server on all network interfaces...")
    print("\nAccess Artemis from:")
    print(f"   Local:      http://localhost:6969")
    print(f"   LAN:        http://{lan_ip}:6969")
    print(f"   API Docs:   http://{lan_ip}:6969/docs")
    print(f"\nAnyone on your network can access Artemis at the LAN address")
    print("=" * 80 + "\n")

    is_systemd = os.environ.get('ARTEMIS_SYSTEMD') == '1'

    run_kwargs = dict(
        host="0.0.0.0",
        port=6969,
        log_level="info",
    )

    if not is_systemd:
        # Dev mode: hot-reload on code changes
        run_kwargs.update(
            reload=True,
            reload_dirs=["."],
            reload_includes=["*.py"],
            reload_excludes=["tests/*", "venv/*", "__pycache__/*"],
        )

    uvicorn.run("artemis_server:app", **run_kwargs)
