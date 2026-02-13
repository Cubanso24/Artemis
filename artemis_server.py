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
import multiprocessing
import queue
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import shutil
import sqlite3

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig


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
                # severity and confidence live at agent level, not per-finding
                agent_severity = agent_result.get('severity', 'low')
                agent_confidence = agent_result.get('confidence', 0.0)
                agent_tactics = agent_result.get('mitre_tactics', [])

                for finding in agent_result.get('findings', []):
                    # Coordinator uses 'activity_type' not 'title'
                    title = finding.get('title') or finding.get('activity_type') or 'Unknown'
                    cursor.execute("""
                        INSERT INTO findings
                        (hunt_id, agent_name, title, description, severity,
                         confidence, mitre_tactics, mitre_techniques,
                         affected_assets, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        hunt_id,
                        agent_name,
                        title,
                        finding.get('description', ''),
                        finding.get('severity') or agent_severity,
                        finding.get('confidence') or agent_confidence,
                        json.dumps(finding.get('mitre_tactics') or agent_tactics),
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

    def delete_hunt(self, hunt_id: str) -> bool:
        """Delete a hunt and its findings from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM findings WHERE hunt_id = ?", (hunt_id,))
            cursor.execute("DELETE FROM hunts WHERE hunt_id = ?", (hunt_id,))
            conn.commit()
            deleted = cursor.rowcount > 0
            return deleted
        finally:
            conn.close()

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
            # Initialize only on first enable (loads rules, caches, etc.)
            if hasattr(self.plugins[name]['instance'], 'initialize'):
                self.plugins[name]['instance'].initialize()

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
        result = []
        for name, info in self.plugins.items():
            plugin_info = {
                'name': name,
                'enabled': info['enabled'],
                'description': getattr(info['class'], 'DESCRIPTION', 'No description'),
            }
            # Add plugin-specific stats
            instance = info['instance']
            if instance and hasattr(instance, 'rules'):
                plugin_info['rules_loaded'] = len(instance.rules)
            result.append(plugin_info)
        return result


# ============================================================================
# Hunt Worker Process
# ============================================================================

def _hunt_worker_process(hunt_id, time_range, mode, description,
                         db_path, enabled_plugins, progress_queue):
    """
    Run a complete hunt in a separate process.

    Creates its own Splunk pipeline, coordinator, and plugins so the main
    web server process stays entirely free for HTTP requests.  All progress
    updates are sent back through ``progress_queue``.
    """
    # Local imports so the child process bootstraps its own copies
    import os, json, logging, traceback
    from datetime import datetime
    from artemis.meta_learner.coordinator import MetaLearnerCoordinator
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    log = logging.getLogger('artemis.hunt_worker')

    def send(data):
        try:
            progress_queue.put_nowait(data)
        except Exception:
            pass

    try:
        hunt_start = datetime.now()
        send({'stage': 'init', 'message': 'Initializing hunt process...', 'progress': 5})

        # --- build pipeline ------------------------------------------------
        host = os.getenv('SPLUNK_HOST', '10.25.11.86')
        token = os.getenv('SPLUNK_TOKEN')
        username = os.getenv('SPLUNK_USERNAME')
        password = os.getenv('SPLUNK_PASSWORD')
        cfg = DataSourceConfig(
            splunk_host=host, splunk_port=8089,
            splunk_token=token or '',
            splunk_username=username or '',
            splunk_password=password or '',
        )
        pipeline = DataPipeline(cfg)
        coordinator = MetaLearnerCoordinator()

        # --- data collection -----------------------------------------------
        send({
            'stage': 'collect',
            'message': 'Starting data collection from Splunk...',
            'progress': 10,
            'collection': {
                'started_at': hunt_start.isoformat(),
                'time_range': time_range,
                'queries_done': 0, 'queries_total': 9,
                'events_by_type': {}, 'total_events': 0,
                'window': 0, 'total_windows': 0,
            },
        })

        collection_stats = {}

        def on_collection_progress(info):
            if info.get('type') == 'query_done':
                collection_stats[info['query_name']] = info['query_events']
                total_events = sum(collection_stats.values())
                qd = info['queries_done']
                qt = info['queries_total']
                w = info.get('window', 1)
                tw = info.get('total_windows', 1)
                if tw > 1:
                    pct = 10 + int(((w - 1) / tw + qd / qt / tw) * 50)
                else:
                    pct = 10 + int((qd / qt) * 50)
                elapsed = (datetime.now() - hunt_start).total_seconds()
                parts = []
                if tw > 1:
                    parts.append(f'Window {w}/{tw}')
                parts += [f'Queries: {qd}/{qt}',
                          f'{total_events:,} events collected',
                          f'{elapsed:.0f}s elapsed']
                send({
                    'stage': 'collect',
                    'message': ' | '.join(parts),
                    'progress': min(pct, 60),
                    'collection': {
                        'started_at': hunt_start.isoformat(),
                        'time_range': time_range,
                        'queries_done': qd, 'queries_total': qt,
                        'events_by_type': dict(collection_stats),
                        'total_events': total_events,
                        'window': w, 'total_windows': tw,
                        'elapsed_seconds': elapsed,
                        'last_query': info['query_name'],
                    },
                })
            elif info.get('type') == 'window_done':
                total = info.get('running_total', 0)
                w = info.get('window', 1)
                tw = info.get('total_windows', 1)
                elapsed = (datetime.now() - hunt_start).total_seconds()
                send({
                    'stage': 'collect',
                    'message': (f'Window {w}/{tw} done | '
                                f'{total:,} total events | {elapsed:.0f}s elapsed'),
                    'progress': 10 + int((w / tw) * 50),
                    'collection': {
                        'started_at': hunt_start.isoformat(),
                        'time_range': time_range,
                        'queries_done': 9, 'queries_total': 9,
                        'events_by_type': info.get('events_by_type', {}),
                        'total_events': total,
                        'window': w, 'total_windows': tw,
                        'elapsed_seconds': elapsed,
                    },
                })

        hunting_data = pipeline.collect_hunting_data(
            time_range, progress_callback=on_collection_progress,
        )
        total_events = sum(len(v) for v in hunting_data.values() if isinstance(v, list))
        collect_elapsed = (datetime.now() - hunt_start).total_seconds()
        log.info(f'Data collection done: {total_events} events in {collect_elapsed:.0f}s')
        send({
            'stage': 'analyze',
            'message': f'Collected {total_events:,} events in {collect_elapsed:.0f}s. Running hunting agents...',
            'progress': 65,
            'collection': {
                'total_events': total_events,
                'events_by_type': {k: len(v) for k, v in hunting_data.items() if isinstance(v, list)},
                'elapsed_seconds': collect_elapsed,
                'phase': 'complete',
            },
        })

        # --- hunt analysis -------------------------------------------------
        send({'stage': 'hunt', 'message': 'Running hunting agents...', 'progress': 70})
        hunt_result = coordinator.hunt(hunting_data, None, None)
        send({'stage': 'finalize', 'message': 'Finalizing results...', 'progress': 90})

        findings_count = hunt_result.get('total_findings', 0)
        hunt_data = {
            'start_time': hunt_start.isoformat(),
            'end_time': datetime.now().isoformat(),
            'time_range': time_range,
            'mode': mode,
            'status': 'completed',
            'total_findings': findings_count,
            'overall_confidence': hunt_result.get('final_confidence', 0.0),
            'description': description,
            'agent_results': {},
        }
        for agent_output in hunt_result.get('agent_outputs', []):
            aname = agent_output.get('agent_name', 'unknown')
            hunt_data['agent_results'][aname] = {
                'confidence': agent_output.get('confidence', 0.0),
                'severity': agent_output.get('severity', 'low'),
                'findings': agent_output.get('findings', []),
            }

        # --- plugins -------------------------------------------------------
        if 'network_mapper' in enabled_plugins:
            send({'stage': 'finalize', 'message': 'Running network mapper...', 'progress': 91})
            try:
                from artemis.plugins.network_mapper import NetworkMapperPlugin
                nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
                nm.initialize()
                nm.execute(
                    network_connections=hunting_data.get('network_connections', []),
                    dns_queries=hunting_data.get('dns_queries', []),
                    ntlm_logs=hunting_data.get('ntlm_logs', []),
                )
                nm.save_map()
            except Exception as e:
                log.warning(f'Network mapper failed: {e}')

        if 'sigma_engine' in enabled_plugins:
            send({'stage': 'finalize', 'message': 'Running Sigma rule engine...', 'progress': 93})
            try:
                from artemis.plugins.sigma_engine import SigmaEnginePlugin
                se = SigmaEnginePlugin({})
                se.initialize()
                sigma_result = se.execute(**hunting_data)
                sigma_matches = sigma_result.get('matches', [])
                if sigma_matches:
                    log.info(f"Sigma engine: {sigma_result['total_matches']} matches across {len(sigma_matches)} rules")
                    sigma_findings = []
                    max_sev = 'low'
                    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
                    for match in sigma_matches:
                        lvl = match.get('level', 'medium')
                        if sev_rank.get(lvl, 0) > sev_rank.get(max_sev, 0):
                            max_sev = lvl
                        sigma_findings.append({
                            'title': f"Sigma: {match.get('rule_title', 'Unknown Rule')}",
                            'description': match.get('rule_description', ''),
                            'severity': lvl,
                            'confidence': 0.85,
                            'mitre_tactics': match.get('mitre_tactics', []),
                            'mitre_techniques': match.get('mitre_techniques', []),
                            'affected_assets': [],
                        })
                    hunt_data['agent_results']['sigma_engine'] = {
                        'confidence': 0.85,
                        'severity': max_sev,
                        'findings': sigma_findings,
                    }
                    findings_count += len(sigma_findings)
                    hunt_data['total_findings'] = findings_count
            except Exception as e:
                log.warning(f'Sigma engine failed: {e}')

        # --- save to DB ----------------------------------------------------
        send({'stage': 'finalize', 'message': 'Saving hunt results...', 'progress': 98})
        db = DatabaseManager(db_path)
        db.save_hunt(hunt_id, hunt_data)

        send({
            'stage': 'complete',
            'message': f'Hunt complete! Found {findings_count} potential threats.',
            'progress': 100,
            'hunt_id': hunt_id,
        })

    except Exception as e:
        log.error(f'Hunt {hunt_id} failed: {e}')
        log.error(traceback.format_exc())
        send({
            'stage': 'error',
            'message': f'Hunt failed: {str(e)}',
            'error_detail': traceback.format_exc(),
            'progress': 0,
            'hunt_id': hunt_id,
        })
    finally:
        # Signal the parent that this process is done
        send({'_done': True, 'hunt_id': hunt_id})


# ============================================================================
# Hunt Manager
# ============================================================================

class HuntManager:
    """Manages hunt execution and state."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.active_hunts = {}
        self.hunt_processes = {}  # hunt_id -> Process
        self._splunk = None  # Lazy Splunk connector for profile_devices

    def get_splunk_connector(self):
        """Get a Splunk connector for API use (e.g. device profiling). Lazy-initialized."""
        if self._splunk is None:
            host = os.getenv('SPLUNK_HOST', '10.25.11.86')
            token = os.getenv('SPLUNK_TOKEN')
            username = os.getenv('SPLUNK_USERNAME')
            password = os.getenv('SPLUNK_PASSWORD')
            cfg = DataSourceConfig(
                splunk_host=host, splunk_port=8089,
                splunk_token=token or '',
                splunk_username=username or '',
                splunk_password=password or '',
            )
            pipeline = DataPipeline(cfg)
            self._splunk = pipeline.splunk
        return self._splunk

    async def execute_hunt(
        self,
        hunt_id: str,
        time_range: str,
        mode: str,
        description: str,
        progress_callback=None
    ):
        """
        Execute a hunt in a separate process.

        The entire hunt (data collection, analysis, plugins, DB save) runs
        in a child process so the web server's event loop and threads remain
        completely free for HTTP / WebSocket traffic.

        Progress messages arrive via a multiprocessing.Queue and are
        forwarded to the WebSocket broadcast callback.
        """
        self.active_hunts[hunt_id] = {
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now(),
            'collection_stats': {},
            'last_progress': None,
        }

        # Determine which plugins the hunt process should run
        enabled_plugins = [
            name for name in ('network_mapper', 'sigma_engine')
            if plugin_manager.get_plugin(name) is not None
        ]

        progress_queue = multiprocessing.Queue()

        proc = multiprocessing.Process(
            target=_hunt_worker_process,
            args=(
                hunt_id, time_range, mode, description,
                self.db.db_path, enabled_plugins, progress_queue,
            ),
            daemon=True,
        )
        proc.start()
        self.hunt_processes[hunt_id] = proc
        logger.info(f'Hunt {hunt_id} started in subprocess (pid {proc.pid})')

        # Drain the progress queue and forward to WebSocket clients
        try:
            while True:
                # Non-blocking poll so the event loop stays responsive
                try:
                    msg = progress_queue.get_nowait()
                except queue.Empty:
                    # Check if process died unexpectedly
                    if not proc.is_alive():
                        break
                    await asyncio.sleep(0.3)
                    continue

                # Internal "done" sentinel
                if msg.get('_done'):
                    break

                # Update local tracking state
                self.active_hunts[hunt_id]['last_progress'] = msg
                if msg.get('progress'):
                    self.active_hunts[hunt_id]['progress'] = msg['progress']

                # Broadcast to WebSocket clients
                if progress_callback:
                    await progress_callback(msg)

                # Terminal states
                if msg.get('stage') in ('complete', 'error'):
                    self.active_hunts[hunt_id]['status'] = (
                        'completed' if msg['stage'] == 'complete' else 'failed'
                    )
                    break

        except Exception as e:
            logger.error(f'Error draining hunt progress queue: {e}')

        # Wait for the process to exit (should already be done)
        proc.join(timeout=10)
        if proc.is_alive():
            logger.warning(f'Hunt process {proc.pid} did not exit, terminating')
            proc.terminate()

        # Reload plugin state from disk so API endpoints serve fresh data
        self._reload_plugins_from_disk(enabled_plugins)

        self.hunt_processes.pop(hunt_id, None)

    def _reload_plugins_from_disk(self, plugin_names):
        """Re-initialize plugin instances so they load results written by the hunt subprocess."""
        for name in plugin_names:
            plugin = plugin_manager.get_plugin(name)
            if plugin and hasattr(plugin, 'initialize'):
                try:
                    plugin.initialize()
                    logger.info(f'Reloaded plugin "{name}" from disk')
                except Exception as e:
                    logger.warning(f'Failed to reload plugin "{name}": {e}')


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
from artemis.plugins.sigma_engine import SigmaEnginePlugin
plugin_manager.register_plugin('network_mapper', NetworkMapperPlugin)
plugin_manager.register_plugin('sigma_engine', SigmaEnginePlugin)

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
        return JSONResponse(status_code=404, content={'error': 'Hunt not found'})
    return hunt


@app.get("/api/hunts/active")
async def get_active_hunts():
    """Get currently running hunts with their latest progress state."""
    active = []
    for hunt_id, state in hunt_manager.active_hunts.items():
        if state.get('status') == 'running':
            entry = {
                'hunt_id': hunt_id,
                'status': 'running',
                'progress': state.get('progress', 0),
                'start_time': state['start_time'].isoformat() if isinstance(state.get('start_time'), datetime) else state.get('start_time'),
                'last_progress': state.get('last_progress'),
            }
            active.append(entry)
    return active


@app.delete("/api/hunts/{hunt_id}")
async def delete_hunt(hunt_id: str):
    """Delete a hunt and its findings."""
    # Don't allow deleting running hunts
    if hunt_id in hunt_manager.active_hunts and hunt_manager.active_hunts[hunt_id].get('status') == 'running':
        return {'error': 'Cannot delete a running hunt'}
    deleted = db_manager.delete_hunt(hunt_id)
    if not deleted:
        return {'error': 'Hunt not found'}
    # Clean up from active hunts cache too
    hunt_manager.active_hunts.pop(hunt_id, None)
    logger.info(f"Deleted hunt: {hunt_id}")
    return {'status': 'deleted', 'hunt_id': hunt_id}


@app.get("/api/network-maps")
async def list_network_maps():
    """List saved network map snapshots."""
    maps_dir = Path("network_maps")
    maps_dir.mkdir(exist_ok=True)

    maps = []
    for f in sorted(maps_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.suffix == '.json':
            try:
                # Read just the header line for metadata
                with open(f) as fh:
                    first_line = fh.readline().strip()
                    if first_line:
                        header = json.loads(first_line)
                        maps.append({
                            'filename': f.name,
                            'timestamp': header.get('timestamp', ''),
                            'total_nodes': header.get('total_nodes', 0),
                            'sensors': header.get('sensors', []),
                            'size_bytes': f.stat().st_size,
                            'is_current': f.name == 'current_map.json',
                        })
            except Exception:
                maps.append({
                    'filename': f.name,
                    'timestamp': '',
                    'total_nodes': 0,
                    'sensors': [],
                    'size_bytes': f.stat().st_size,
                    'is_current': f.name == 'current_map.json',
                })
    return maps


@app.post("/api/network-maps/snapshot")
async def save_network_map_snapshot(name: Optional[str] = None):
    """Save a named snapshot of the current network map."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}

    # Save current state first
    plugin.save_map()

    # Copy current_map.json to a named snapshot
    maps_dir = Path("network_maps")
    current = maps_dir / "current_map.json"
    if not current.exists():
        return {'error': 'No current map to snapshot'}

    if not name:
        name = f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    # Sanitize name
    safe_name = "".join(c for c in name if c.isalnum() or c in ('_', '-'))
    snapshot_file = maps_dir / f"{safe_name}.json"

    shutil.copy2(current, snapshot_file)
    logger.info(f"Saved network map snapshot: {snapshot_file.name}")

    return {'status': 'saved', 'filename': snapshot_file.name}


@app.post("/api/network-maps/{filename}/load")
async def load_network_map(filename: str):
    """Load a saved network map, replacing the current one."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}

    maps_dir = Path("network_maps")
    map_file = maps_dir / filename

    if not map_file.exists():
        return {'error': 'Map file not found'}

    # Copy chosen file to current_map.json then reload
    current = maps_dir / "current_map.json"
    if filename != "current_map.json":
        shutil.copy2(map_file, current)

    # Reload into plugin
    plugin.nodes.clear()
    plugin.sensors.clear()
    plugin._load_existing_map()

    logger.info(f"Loaded network map: {filename} ({len(plugin.nodes)} nodes)")
    return {
        'status': 'loaded',
        'filename': filename,
        'total_nodes': len(plugin.nodes),
        'sensors': sorted(plugin.sensors),
    }


@app.delete("/api/network-maps/{filename}")
async def delete_network_map(filename: str):
    """Delete a saved network map snapshot."""
    if filename == "current_map.json":
        return {'error': 'Cannot delete the current active map'}

    maps_dir = Path("network_maps")
    map_file = maps_dir / filename

    if not map_file.exists():
        return {'error': 'Map file not found'}

    map_file.unlink()
    # Also delete companion summary if it exists
    summary = maps_dir / filename.replace('.json', '_summary.txt')
    if summary.exists():
        summary.unlink()

    logger.info(f"Deleted network map: {filename}")
    return {'status': 'deleted', 'filename': filename}


@app.post("/api/network-maps/reset")
async def reset_network_map():
    """Clear the current network map (start fresh)."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}

    plugin.nodes.clear()
    plugin.sensors.clear()
    plugin._dirty_nodes.clear()
    plugin._stats_cache = None
    plugin.save_map()

    logger.info("Network map reset to empty")
    return {'status': 'reset', 'total_nodes': 0}


@app.get("/api/plugins")
async def list_plugins():
    """List available plugins."""
    return plugin_manager.list_plugins()


@app.post("/api/plugins/{plugin_name}/enable")
def enable_plugin(plugin_name: str, config: PluginConfig):
    """Enable a plugin. Uses def (not async) so blocking init runs in a threadpool."""
    try:
        plugin_manager.enable_plugin(plugin_name, config.config)
        return {'status': 'enabled', 'plugin': plugin_name}
    except Exception as e:
        logger.error(f"Failed to enable plugin {plugin_name}: {e}")
        return JSONResponse(status_code=400, content={'error': str(e)})


@app.post("/api/plugins/{plugin_name}/disable")
def disable_plugin(plugin_name: str):
    """Disable a plugin."""
    plugin_manager.disable_plugin(plugin_name)
    return {'status': 'disabled', 'plugin': plugin_name}


@app.get("/api/network-graph")
async def get_network_graph(
    sensor_id: Optional[str] = None,
    max_nodes: int = 200,
):
    """Get network topology graph from network mapper plugin."""
    plugin = plugin_manager.get_plugin('network_mapper')

    if not plugin:
        return JSONResponse(status_code=404, content={'error': 'Network mapper plugin not enabled'})

    try:
        graph_data = plugin.get_network_graph(
            sensor_id=sensor_id,
            max_nodes=max_nodes,
        )
        return graph_data
    except Exception as e:
        return JSONResponse(status_code=500, content={'error': str(e)})


@app.get("/api/network-summary")
async def get_network_summary(sensor_id: Optional[str] = None):
    """Get network summary statistics, optionally filtered by sensor."""
    plugin = plugin_manager.get_plugin('network_mapper')

    if not plugin:
        return JSONResponse(status_code=404, content={'error': 'Network mapper plugin not enabled'})

    try:
        return plugin.get_summary(sensor_id=sensor_id)
    except Exception as e:
        return JSONResponse(status_code=500, content={'error': str(e)})


class ProfileRequest(BaseModel):
    """Request for device profiling."""
    time_range: str = "-24h"


@app.post("/api/network-graph/profile")
def profile_devices(request: ProfileRequest):
    """
    Profile network devices by querying Splunk zeek:conn logs.

    Uses def (not async) so the blocking Splunk queries run in a threadpool.
    """
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(status_code=404, content={'error': 'Network mapper plugin not enabled'})

    # Get Splunk connector for profiling queries
    splunk = hunt_manager.get_splunk_connector()
    if not splunk:
        return JSONResponse(status_code=400, content={'error': 'Splunk connection not configured'})

    try:
        result = plugin.profile_devices(
            splunk,
            time_range=request.time_range,
        )
        return result
    except Exception as e:
        logger.error(f"Device profiling failed: {e}")
        return JSONResponse(status_code=500, content={'error': str(e)})


# ============================================================================
# Sigma Engine Endpoints
# ============================================================================

@app.get("/api/sigma/rules")
async def get_sigma_rules():
    """List loaded Sigma rules."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if not plugin:
        return {'error': 'Sigma engine plugin not enabled'}
    return plugin.get_rules()


@app.get("/api/sigma/results")
async def get_sigma_results():
    """Get latest Sigma scan results."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if plugin:
        return plugin.get_last_results()
    # Fall back to reading results file directly even if plugin is disabled
    results_file = Path('sigma_results') / 'latest.json'
    if results_file.exists():
        try:
            with open(results_file) as f:
                return json.load(f)
        except Exception:
            pass
    return {'error': 'Sigma engine plugin not enabled'}


@app.post("/api/sigma/reload")
async def reload_sigma_rules():
    """Reload Sigma rules from disk."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if not plugin:
        return {'error': 'Sigma engine plugin not enabled'}
    plugin.reload_rules()
    return {'status': 'reloaded', 'rules_count': len(plugin.rules)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time hunt updates."""
    await websocket.accept()
    active_connections.append(websocket)

    # Send current state of any running hunts so reconnecting clients can resume
    try:
        for hunt_id, state in hunt_manager.active_hunts.items():
            if state.get('status') == 'running' and state.get('last_progress'):
                await websocket.send_json(state['last_progress'])
    except Exception:
        pass

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast_progress(data: dict):
    """Broadcast progress to all connected clients and cache for reconnects."""
    # Cache last progress in active_hunts so reconnecting clients can resume
    for hunt_id, hunt_state in hunt_manager.active_hunts.items():
        if hunt_state.get('status') == 'running':
            hunt_state['last_progress'] = data
            break

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

    uvicorn.run(
        "artemis_server:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=True,
        reload_dirs=[".", "artemis"],
    )
