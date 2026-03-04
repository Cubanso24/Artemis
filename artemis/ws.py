"""WebSocket management and log broadcasting for Artemis.

Centralises the connection list, broadcast helper, and the custom log
handler so every module can import a single source of truth.
"""

import asyncio
import collections
import logging
from datetime import datetime
from typing import List

from fastapi import WebSocket

# Shared connection list — imported by route modules and the log handler.
active_connections: List[WebSocket] = []

# Ring buffer of recent agent activity events (accessible via API).
agent_activity_history: collections.deque = collections.deque(maxlen=200)

# Database path override — subprocesses set this so fire_agent_activity
# writes to the same DB as the rest of the pipeline.
_db_path: str = "artemis.db"


def set_db_path(path: str):
    """Set the database path for agent activity logging (call from subprocesses)."""
    global _db_path
    _db_path = path


async def broadcast_progress(data: dict):
    """Broadcast a progress dict to all connected WebSocket clients."""
    dead: list = []
    for connection in active_connections:
        try:
            await connection.send_json(data)
        except Exception:
            dead.append(connection)
    for connection in dead:
        try:
            active_connections.remove(connection)
        except ValueError:
            pass


class WebSocketLogHandler(logging.Handler):
    """Logging handler that pushes log records to WebSocket clients."""

    def emit(self, record):
        try:
            log_entry = self.format(record)
            if record.levelno >= logging.ERROR:
                log_type = 'error'
            elif record.levelno >= logging.WARNING:
                log_type = 'warning'
            else:
                log_type = 'info'

            message = {
                'type': 'server_log',
                'level': record.levelname,
                'message': log_entry,
                'log_type': log_type,
                'timestamp': datetime.now().isoformat(),
            }

            try:
                asyncio.get_running_loop()
                asyncio.create_task(broadcast_progress(message))
            except RuntimeError:
                pass  # No event loop — skip (e.g. from worker thread)
        except Exception:
            self.handleError(record)


async def broadcast_agent_activity(agent_name: str, activity_type: str, detail: dict):
    """Broadcast an LLM agent activity event to all connected clients.

    *activity_type* is one of: ``prompt``, ``response``, ``enrichment``,
    ``error``, ``stage``.
    """
    message = {
        "type": "agent_activity",
        "agent": agent_name,
        "activity": activity_type,
        "detail": detail,
        "timestamp": datetime.now().isoformat(),
    }
    agent_activity_history.append(message)
    await broadcast_progress(message)


def fire_agent_activity(agent_name: str, activity_type: str, detail: dict):
    """Non-async helper to fire agent activity from sync code.

    Works from any context — if an asyncio event loop is running
    (main web process), broadcast immediately via WebSocket.  In all
    cases, persist to the ``agent_activity`` database table so the
    web server can relay events from subprocess workers.
    """
    # Always persist to DB (works from subprocesses)
    try:
        from artemis.managers.db_manager import DatabaseManager
        db = DatabaseManager(_db_path)
        db.log_agent_activity(agent_name, activity_type, detail)
    except Exception:
        pass

    # Also broadcast live if we have an event loop (main process only)
    try:
        loop = asyncio.get_running_loop()
        asyncio.ensure_future(
            broadcast_agent_activity(agent_name, activity_type, detail)
        )
    except RuntimeError:
        pass  # No event loop running — DB write above covers it


def install_log_handler():
    """Attach the WebSocket log handler to the root logger (call once)."""
    handler = WebSocketLogHandler()
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logging.getLogger().addHandler(handler)
