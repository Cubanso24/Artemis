"""WebSocket management and log broadcasting for Artemis.

Centralises the connection list, broadcast helper, and the custom log
handler so every module can import a single source of truth.
"""

import asyncio
import logging
from datetime import datetime
from typing import List

from fastapi import WebSocket

# Shared connection list — imported by route modules and the log handler.
active_connections: List[WebSocket] = []


async def broadcast_progress(data: dict):
    """Broadcast a progress dict to all connected WebSocket clients."""
    for connection in active_connections:
        try:
            await connection.send_json(data)
        except Exception:
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
            pass


def install_log_handler():
    """Attach the WebSocket log handler to the root logger (call once)."""
    handler = WebSocketLogHandler()
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logging.getLogger().addHandler(handler)
