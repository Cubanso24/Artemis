#!/usr/bin/env python3
"""
Artemis Server - Long-running threat hunting service with web API
"""

import os
import sys
import json
import asyncio
import logging
import traceback
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import sqlite3

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from artemis.meta_learner.coordinator import MetaLearnerCoordinator
from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
from artemis.models.network_state import NetworkState


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("artemis.server")


# ============================================================================
# WebSocket Logging Handler
# ============================================================================

class WebSocketLogHandler(logging.Handler):
    """Custom logging handler that broadcasts logs to WebSocket clients."""

    def __init__(self):
        super().__init__()
        self.connections = []

    def emit(self, record):
        """Emit a log record to all WebSocket clients."""
        try:
            log_entry = self.format(record)

            # Determine log type for client-side styling
            if record.levelno >= logging.ERROR:
                log_type = 'error'
            elif record.levelno >= logging.WARNING:
                log_type = 'warning'
            else:
                log_type = 'info'

            # Create message for WebSocket
            message = {
                'type': 'server_log',
                'level': record.levelname,
                'message': log_entry,
                'log_type': log_type,
                'timestamp': datetime.now().isoformat()
            }

            # Broadcast to all connected clients asynchronously
            # Check if we're in an async context (not a worker thread)
            try:
                loop = asyncio.get_running_loop()
                # We're in an async context, create task directly
                asyncio.create_task(self.broadcast_log(message))
            except RuntimeError:
                # No event loop running (e.g., from worker thread)
                # Try to schedule on the main loop if it exists
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.run_coroutine_threadsafe(self.broadcast_log(message), loop)
                except:
                    # Can't broadcast from this thread, skip it
                    pass
        except Exception:
            # Silently ignore errors in log broadcasting to avoid recursion
            pass

    async def broadcast_log(self, message: dict):
        """Broadcast log message to all WebSocket clients."""
        # This will use the global active_connections list
        for connection in active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass  # Connection might be closed


# Create and configure WebSocket log handler
ws_log_handler = WebSocketLogHandler()
ws_log_handler.setLevel(logging.INFO)
ws_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# Add handler to root logger so all logs go to WebSocket
logging.getLogger().addHandler(ws_log_handler)
# Also add to artemis logger
logger.addHandler(ws_log_handler)


# ============================================================================
# Data Models
# ============================================================================

class HuntRequest(BaseModel):
    """Request to start a new hunt."""
    time_range: str = "-1h"
    mode: str = "PARALLEL"
    description: Optional[str] = None


class BulkHuntRequest(BaseModel):
    """Request to start a bulk hunt."""
    days_back: int = 7
    window_hours: int = 6
    mode: str = "PARALLEL"
    description: Optional[str] = None


class PluginConfig(BaseModel):
    """Configuration for a plugin."""
    name: str
    enabled: bool
    config: Dict = {}


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    """Manages hunt results database."""

    def __init__(self, db_path: str = "artemis.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Hunts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hunts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hunt_id TEXT UNIQUE,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                time_range TEXT,
                mode TEXT,
                status TEXT,
                total_findings INTEGER,
                overall_confidence REAL,
                description TEXT
            )
        """)

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hunt_id TEXT,
                agent_name TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                confidence REAL,
                mitre_tactics TEXT,
                mitre_techniques TEXT,
                affected_assets TEXT,
                timestamp TIMESTAMP,
                FOREIGN KEY (hunt_id) REFERENCES hunts(hunt_id)
            )
        """)

        # Plugin results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plugin_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_name TEXT,
                timestamp TIMESTAMP,
                result_type TEXT,
                result_data TEXT
            )
        """)

        conn.commit()
        conn.close()

    def save_hunt(self, hunt_id: str, hunt_data: Dict):
        """Save hunt results to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Insert hunt record
            cursor.execute("""
                INSERT OR REPLACE INTO hunts
                (hunt_id, start_time, end_time, time_range, mode, status,
                 total_findings, overall_confidence, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hunt_id,
                hunt_data.get('start_time'),
                hunt_data.get('end_time'),
                hunt_data.get('time_range'),
                hunt_data.get('mode'),
                hunt_data.get('status'),
                hunt_data.get('total_findings', 0),
                hunt_data.get('overall_confidence', 0.0),
                hunt_data.get('description')
            ))

            # Insert findings
            for agent_name, agent_result in hunt_data.get('agent_results', {}).items():
                for finding in agent_result.get('findings', []):
                    cursor.execute("""
                        INSERT INTO findings
                        (hunt_id, agent_name, title, description, severity,
                         confidence, mitre_tactics, mitre_techniques,
                         affected_assets, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        hunt_id,
                        agent_name,
                        finding.get('title'),
                        finding.get('description'),
                        finding.get('severity'),
                        finding.get('confidence'),
                        json.dumps(finding.get('mitre_tactics', [])),
                        json.dumps(finding.get('mitre_techniques', [])),
                        json.dumps(finding.get('affected_assets', [])),
                        datetime.now()
                    ))

            conn.commit()
        finally:
            conn.close()

    def get_recent_hunts(self, limit: int = 50) -> List[Dict]:
        """Get recent hunt records."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT hunt_id, start_time, end_time, time_range, mode, status,
                   total_findings, overall_confidence, description
            FROM hunts
            ORDER BY start_time DESC
            LIMIT ?
        """, (limit,))

        hunts = []
        for row in cursor.fetchall():
            hunts.append({
                'hunt_id': row[0],
                'start_time': row[1],
                'end_time': row[2],
                'time_range': row[3],
                'mode': row[4],
                'status': row[5],
                'total_findings': row[6],
                'overall_confidence': row[7],
                'description': row[8]
            })

        conn.close()
        return hunts

    def get_hunt_details(self, hunt_id: str) -> Dict:
        """Get detailed hunt results including findings."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get hunt info
        cursor.execute("""
            SELECT hunt_id, start_time, end_time, time_range, mode, status,
                   total_findings, overall_confidence, description
            FROM hunts
            WHERE hunt_id = ?
        """, (hunt_id,))

        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        hunt = {
            'hunt_id': row[0],
            'start_time': row[1],
            'end_time': row[2],
            'time_range': row[3],
            'mode': row[4],
            'status': row[5],
            'total_findings': row[6],
            'overall_confidence': row[7],
            'description': row[8],
            'findings': []
        }

        # Get findings
        cursor.execute("""
            SELECT agent_name, title, description, severity, confidence,
                   mitre_tactics, mitre_techniques, affected_assets, timestamp
            FROM findings
            WHERE hunt_id = ?
            ORDER BY confidence DESC
        """, (hunt_id,))

        for row in cursor.fetchall():
            hunt['findings'].append({
                'agent_name': row[0],
                'title': row[1],
                'description': row[2],
                'severity': row[3],
                'confidence': row[4],
                'mitre_tactics': json.loads(row[5]) if row[5] else [],
                'mitre_techniques': json.loads(row[6]) if row[6] else [],
                'affected_assets': json.loads(row[7]) if row[7] else [],
                'timestamp': row[8]
            })

        conn.close()
        return hunt


# ============================================================================
# Plugin Manager
# ============================================================================

class PluginManager:
    """Manages Artemis plugins/modules."""

    def __init__(self):
        self.plugins = {}
        self.plugin_dir = Path("artemis/plugins")
        self.plugin_dir.mkdir(exist_ok=True)

    def register_plugin(self, name: str, plugin_class):
        """Register a plugin."""
        self.plugins[name] = {
            'class': plugin_class,
            'instance': None,
            'enabled': False
        }
        logger.info(f"Registered plugin: {name}")

    def enable_plugin(self, name: str, config: Dict = None):
        """Enable and initialize a plugin."""
        if name not in self.plugins:
            raise ValueError(f"Plugin not found: {name}")

        if self.plugins[name]['instance'] is None:
            self.plugins[name]['instance'] = self.plugins[name]['class'](config or {})

        self.plugins[name]['enabled'] = True
        logger.info(f"Enabled plugin: {name}")

    def disable_plugin(self, name: str):
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name]['enabled'] = False
            logger.info(f"Disabled plugin: {name}")

    def get_plugin(self, name: str):
        """Get plugin instance."""
        if name in self.plugins and self.plugins[name]['enabled']:
            return self.plugins[name]['instance']
        return None

    def list_plugins(self) -> List[Dict]:
        """List all registered plugins."""
        return [
            {
                'name': name,
                'enabled': info['enabled'],
                'description': getattr(info['class'], 'DESCRIPTION', 'No description')
            }
            for name, info in self.plugins.items()
        ]


# ============================================================================
# Hunt Manager
# ============================================================================

class HuntManager:
    """Manages hunt execution and state."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.coordinator = MetaLearnerCoordinator()
        self.pipeline = None
        self.active_hunts = {}
        self.executor = ThreadPoolExecutor(max_workers=16)  # Maximize parallel hunt execution

    def initialize_pipeline(self):
        """Initialize data pipeline."""
        if self.pipeline is not None:
            return

        host = os.getenv('SPLUNK_HOST', '10.25.11.86')
        token = os.getenv('SPLUNK_TOKEN')
        username = os.getenv('SPLUNK_USERNAME')
        password = os.getenv('SPLUNK_PASSWORD')

        config = DataSourceConfig(
            splunk_host=host,
            splunk_port=8089,
            splunk_token=token if token else "",
            splunk_username=username if username else "",
            splunk_password=password if password else ""
        )

        self.pipeline = DataPipeline(config)

    async def execute_hunt(
        self,
        hunt_id: str,
        time_range: str,
        mode: str,
        description: str,
        progress_callback=None
    ):
        """Execute a hunt asynchronously."""
        try:
            self.active_hunts[hunt_id] = {
                'status': 'running',
                'progress': 0,
                'start_time': datetime.now()
            }

            if progress_callback:
                await progress_callback({'stage': 'init', 'message': 'Initializing hunt...', 'progress': 10})

            # Initialize pipeline if needed
            self.initialize_pipeline()

            if progress_callback:
                await progress_callback({'stage': 'collect', 'message': 'Collecting network data...', 'progress': 30})

            # Collect data
            logger.info(f"About to start data collection for time_range={time_range}")
            hunting_data = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.pipeline.collect_hunting_data,
                time_range
            )
            logger.info(f"Data collection completed, got {sum(len(v) for v in hunting_data.values() if isinstance(v, list))} events")

            total_events = sum(len(v) for v in hunting_data.values() if isinstance(v, list))

            if progress_callback:
                await progress_callback({
                    'stage': 'analyze',
                    'message': f'Analyzing {total_events} events...',
                    'progress': 50
                })

            if progress_callback:
                await progress_callback({'stage': 'hunt', 'message': 'Running hunting agents...', 'progress': 70})

            # Execute hunt
            # coordinator.hunt() signature: hunt(data, initial_signals=None, context_data=None)
            # It creates NetworkState internally from context_data
            hunt_result = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.coordinator.hunt,
                hunting_data,  # data: Dict[str, Any] - hunting data for agents
                None,          # initial_signals: Optional initial alerts
                None           # context_data: Optional context (hunt() creates NetworkState)
            )

            if progress_callback:
                await progress_callback({'stage': 'finalize', 'message': 'Finalizing results...', 'progress': 90})

            # Process results - use total_findings from aggregated assessment
            findings_count = hunt_result.get('total_findings', 0)

            # Prepare database record
            hunt_data = {
                'start_time': self.active_hunts[hunt_id]['start_time'].isoformat(),
                'end_time': datetime.now().isoformat(),
                'time_range': time_range,
                'mode': mode,
                'status': 'completed',
                'total_findings': findings_count,
                'overall_confidence': hunt_result.get('final_confidence', 0.0),
                'description': description,
                'agent_results': {}
            }

            # Extract findings from agent outputs
            # agent_outputs are already in dict format from to_dict()
            for agent_output in hunt_result.get('agent_outputs', []):
                agent_name = agent_output.get('agent_name', 'unknown')
                hunt_data['agent_results'][agent_name] = {
                    'confidence': agent_output.get('confidence', 0.0),
                    'severity': agent_output.get('severity', 'low'),
                    'findings': agent_output.get('findings', [])
                }

            # Update network mapper plugin if enabled
            network_mapper = plugin_manager.get_plugin('network_mapper')
            if network_mapper:
                try:
                    network_mapper.execute(
                        network_connections=hunting_data.get('network_connections', []),
                        dns_queries=hunting_data.get('dns_queries', [])
                    )
                except Exception as e:
                    logger.warning(f"Network mapper plugin failed: {e}")

            # Save to database
            self.db.save_hunt(hunt_id, hunt_data)

            self.active_hunts[hunt_id]['status'] = 'completed'
            self.active_hunts[hunt_id]['progress'] = 100

            if progress_callback:
                await progress_callback({
                    'stage': 'complete',
                    'message': f'Hunt complete! Found {findings_count} potential threats.',
                    'progress': 100,
                    'hunt_id': hunt_id
                })

            return hunt_data

        except Exception as e:
            error_msg = f"Hunt {hunt_id} failed: {str(e)}"
            error_traceback = traceback.format_exc()

            # Log error with full traceback
            logger.error(error_msg)
            logger.error(f"Traceback:\n{error_traceback}")

            self.active_hunts[hunt_id]['status'] = 'failed'
            self.active_hunts[hunt_id]['error'] = str(e)

            if progress_callback:
                await progress_callback({
                    'stage': 'error',
                    'message': f'Hunt failed: {str(e)}',
                    'error_detail': error_traceback,
                    'progress': 0,
                    'hunt_id': hunt_id
                })

            # Don't raise - just mark as failed
            return None


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(title="Artemis Threat Hunting Platform", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize managers
db_manager = DatabaseManager()
hunt_manager = HuntManager(db_manager)
plugin_manager = PluginManager()

# Register built-in plugins
from artemis.plugins.network_mapper import NetworkMapperPlugin
plugin_manager.register_plugin('network_mapper', NetworkMapperPlugin)

# WebSocket connections
active_connections: List[WebSocket] = []


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Serve the web UI."""
    return FileResponse("artemis/web/index.html")


@app.get("/api/status")
async def get_status():
    """Get server status."""
    return {
        'status': 'running',
        'active_hunts': len([h for h in hunt_manager.active_hunts.values() if h['status'] == 'running']),
        'plugins': plugin_manager.list_plugins()
    }


@app.post("/api/hunt")
async def start_hunt(request: HuntRequest, background_tasks: BackgroundTasks):
    """Start a new threat hunt."""
    hunt_id = f"hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Log hunt start to WebSocket clients
    logger.info(f"Starting hunt {hunt_id}: time_range={request.time_range}, mode={request.mode}")

    # Start hunt in background with progress callback
    background_tasks.add_task(
        hunt_manager.execute_hunt,
        hunt_id,
        request.time_range,
        request.mode,
        request.description,
        broadcast_progress  # Pass broadcast function as progress callback
    )

    return {'hunt_id': hunt_id, 'status': 'started'}


@app.get("/api/hunts")
async def list_hunts(limit: int = 50):
    """List recent hunts."""
    return db_manager.get_recent_hunts(limit)


@app.get("/api/hunts/{hunt_id}")
async def get_hunt(hunt_id: str):
    """Get hunt details."""
    hunt = db_manager.get_hunt_details(hunt_id)
    if not hunt:
        return {'error': 'Hunt not found'}, 404
    return hunt


@app.get("/api/plugins")
async def list_plugins():
    """List available plugins."""
    return plugin_manager.list_plugins()


@app.post("/api/plugins/{plugin_name}/enable")
async def enable_plugin(plugin_name: str, config: PluginConfig):
    """Enable a plugin."""
    try:
        plugin_manager.enable_plugin(plugin_name, config.config)
        return {'status': 'enabled'}
    except Exception as e:
        return {'error': str(e)}, 400


@app.post("/api/plugins/{plugin_name}/disable")
async def disable_plugin(plugin_name: str):
    """Disable a plugin."""
    plugin_manager.disable_plugin(plugin_name)
    return {'status': 'disabled'}


@app.get("/api/network-graph")
async def get_network_graph(
    sensor_id: Optional[str] = None,
    max_nodes: int = 200,
):
    """Get network topology graph from network mapper plugin."""
    plugin = plugin_manager.get_plugin('network_mapper')

    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}, 404

    try:
        graph_data = plugin.get_network_graph(
            sensor_id=sensor_id,
            max_nodes=max_nodes,
        )
        return graph_data
    except Exception as e:
        return {'error': str(e)}, 500


@app.get("/api/network-summary")
async def get_network_summary(sensor_id: Optional[str] = None):
    """Get network summary statistics, optionally filtered by sensor."""
    plugin = plugin_manager.get_plugin('network_mapper')

    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}, 404

    try:
        return plugin.get_summary(sensor_id=sensor_id)
    except Exception as e:
        return {'error': str(e)}, 500


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time hunt updates."""
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast_progress(data: dict):
    """Broadcast progress to all connected clients."""
    for connection in active_connections:
        try:
            await connection.send_json(data)
        except:
            pass


# ============================================================================
# Serve static files
# ============================================================================

@app.get("/static/{path:path}")
async def serve_static(path: str):
    """Serve static files."""
    return FileResponse(f"artemis/web/static/{path}")


if __name__ == "__main__":
    import uvicorn
    import socket

    # Get LAN IP address
    def get_lan_ip():
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
            s.close()
            return lan_ip
        except Exception:
            return "0.0.0.0"

    lan_ip = get_lan_ip()

    print("=" * 80)
    print("  🏹 ARTEMIS THREAT HUNTING PLATFORM")
    print("=" * 80)
    print("\n🚀 Starting server on all network interfaces...")
    print("\n📡 Access Artemis from:")
    print(f"   Local:      http://localhost:8000")
    print(f"   LAN:        http://{lan_ip}:8000")
    print(f"   API Docs:   http://{lan_ip}:8000/docs")
    print("\n💡 Anyone on your network can access Artemis at the LAN address")
    print("=" * 80 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
