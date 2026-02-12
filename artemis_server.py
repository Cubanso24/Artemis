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
import shutil
import sqlite3

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
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
# Hunt Manager
# ============================================================================

class HuntManager:
    """Manages hunt execution and state."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.coordinator = MetaLearnerCoordinator()
        self.pipeline = None
        self.active_hunts = {}
        # Dedicated executor for long-running hunt operations (data collection,
        # analysis, plugins). Kept separate so hunts never starve HTTP requests.
        self.hunt_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='hunt')
        # Lightweight executor for quick API operations (DB reads, plugin queries).
        # Never used by hunts, so always has threads available.
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='api')

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
            hunt_start = datetime.now()
            self.active_hunts[hunt_id] = {
                'status': 'running',
                'progress': 0,
                'start_time': hunt_start,
                'collection_stats': {},
                'last_progress': None,
            }

            if progress_callback:
                await progress_callback({'stage': 'init', 'message': 'Initializing hunt...', 'progress': 5})

            # Initialize pipeline if needed
            self.initialize_pipeline()

            if progress_callback:
                await progress_callback({
                    'stage': 'collect',
                    'message': 'Starting data collection from Splunk...',
                    'progress': 10,
                    'collection': {
                        'started_at': hunt_start.isoformat(),
                        'time_range': time_range,
                        'queries_done': 0,
                        'queries_total': 8,
                        'events_by_type': {},
                        'total_events': 0,
                        'window': 0,
                        'total_windows': 0,
                    }
                })

            # Collection progress callback (called from worker thread)
            main_loop = asyncio.get_event_loop()

            def collection_progress(info):
                """Bridge sync callback from pipeline to async broadcast."""
                if not progress_callback:
                    return

                stats = self.active_hunts.get(hunt_id, {})
                collection_stats = stats.get('collection_stats', {})

                if info.get('type') == 'query_done':
                    collection_stats[info['query_name']] = info['query_events']
                    total_events = sum(collection_stats.values())
                    queries_done = info['queries_done']
                    queries_total = info['queries_total']
                    window = info.get('window', 1)
                    total_windows = info.get('total_windows', 1)

                    # Calculate progress: 10-60% for collection phase
                    if total_windows > 1:
                        window_pct = (window - 1) / total_windows
                        query_pct = queries_done / queries_total / total_windows
                        collect_progress = 10 + int((window_pct + query_pct) * 50)
                    else:
                        collect_progress = 10 + int((queries_done / queries_total) * 50)

                    elapsed = (datetime.now() - hunt_start).total_seconds()

                    msg_parts = []
                    if total_windows > 1:
                        msg_parts.append(f"Window {window}/{total_windows}")
                    msg_parts.append(
                        f"Queries: {queries_done}/{queries_total}"
                    )
                    msg_parts.append(f"{total_events:,} events collected")
                    msg_parts.append(f"{elapsed:.0f}s elapsed")

                    data = {
                        'stage': 'collect',
                        'message': ' | '.join(msg_parts),
                        'progress': min(collect_progress, 60),
                        'collection': {
                            'started_at': hunt_start.isoformat(),
                            'time_range': time_range,
                            'queries_done': queries_done,
                            'queries_total': queries_total,
                            'events_by_type': dict(collection_stats),
                            'total_events': total_events,
                            'window': window,
                            'total_windows': total_windows,
                            'elapsed_seconds': elapsed,
                            'last_query': info['query_name'],
                        }
                    }

                    asyncio.run_coroutine_threadsafe(
                        progress_callback(data), main_loop
                    )

                elif info.get('type') == 'window_done':
                    total = info.get('running_total', 0)
                    window = info.get('window', 1)
                    total_windows = info.get('total_windows', 1)
                    elapsed = (datetime.now() - hunt_start).total_seconds()

                    data = {
                        'stage': 'collect',
                        'message': (
                            f"Window {window}/{total_windows} done | "
                            f"{total:,} total events | {elapsed:.0f}s elapsed"
                        ),
                        'progress': 10 + int((window / total_windows) * 50),
                        'collection': {
                            'started_at': hunt_start.isoformat(),
                            'time_range': time_range,
                            'events_by_type': info.get('events_by_type', {}),
                            'total_events': total,
                            'window': window,
                            'total_windows': total_windows,
                            'elapsed_seconds': elapsed,
                        }
                    }

                    asyncio.run_coroutine_threadsafe(
                        progress_callback(data), main_loop
                    )

                stats['collection_stats'] = collection_stats

            # Collect data with progress tracking (uses hunt_executor to avoid
            # starving the API executor during long Splunk pagination)
            hunting_data = await asyncio.get_event_loop().run_in_executor(
                self.hunt_executor,
                lambda: self.pipeline.collect_hunting_data(
                    time_range,
                    progress_callback=collection_progress,
                )
            )

            total_events = sum(len(v) for v in hunting_data.values() if isinstance(v, list))
            logger.info(f"Data collection completed, got {total_events} events")

            collect_elapsed = (datetime.now() - hunt_start).total_seconds()
            if progress_callback:
                await progress_callback({
                    'stage': 'analyze',
                    'message': f'Collected {total_events:,} events in {collect_elapsed:.0f}s. Running hunting agents...',
                    'progress': 65,
                    'collection': {
                        'total_events': total_events,
                        'events_by_type': {
                            k: len(v) for k, v in hunting_data.items()
                            if isinstance(v, list)
                        },
                        'elapsed_seconds': collect_elapsed,
                        'phase': 'complete',
                    }
                })

            if progress_callback:
                await progress_callback({'stage': 'hunt', 'message': 'Running hunting agents...', 'progress': 70})

            # Execute hunt
            # coordinator.hunt() signature: hunt(data, initial_signals=None, context_data=None)
            # It creates NetworkState internally from context_data
            hunt_result = await asyncio.get_event_loop().run_in_executor(
                self.hunt_executor,
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

            # Run enabled plugins against collected data
            # Plugins run in executor to avoid blocking the event loop
            # (which would prevent WebSocket progress messages from being sent)
            loop = asyncio.get_event_loop()

            network_mapper = plugin_manager.get_plugin('network_mapper')
            if network_mapper:
                if progress_callback:
                    await progress_callback({'stage': 'finalize', 'message': 'Running network mapper...', 'progress': 91})
                try:
                    await loop.run_in_executor(self.hunt_executor, lambda: network_mapper.execute(
                        network_connections=hunting_data.get('network_connections', []),
                        dns_queries=hunting_data.get('dns_queries', [])
                    ))
                except Exception as e:
                    logger.warning(f"Network mapper plugin failed: {e}")

            sigma_engine = plugin_manager.get_plugin('sigma_engine')
            if sigma_engine:
                if progress_callback:
                    await progress_callback({'stage': 'finalize', 'message': 'Running Sigma rule engine...', 'progress': 93})
                try:
                    sigma_result = await loop.run_in_executor(self.hunt_executor, lambda: sigma_engine.execute(**hunting_data))
                    sigma_matches = sigma_result.get('matches', [])
                    if sigma_matches:
                        logger.info(f"Sigma engine: {sigma_result['total_matches']} matches across {len(sigma_matches)} rules")
                        # Add sigma matches as hunt findings so they appear in hunt details
                        sigma_findings = []
                        max_severity = 'low'
                        severity_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
                        for match in sigma_matches:
                            lvl = match.get('level', 'medium')
                            if severity_rank.get(lvl, 0) > severity_rank.get(max_severity, 0):
                                max_severity = lvl
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
                            'severity': max_severity,
                            'findings': sigma_findings,
                        }
                        findings_count += len(sigma_findings)
                        hunt_data['total_findings'] = findings_count
                except Exception as e:
                    logger.warning(f"Sigma engine plugin failed: {e}")

            geoip_mapper = plugin_manager.get_plugin('geoip_mapper')
            if geoip_mapper:
                if progress_callback:
                    await progress_callback({'stage': 'finalize', 'message': 'Running GeoIP mapper...', 'progress': 96})
                try:
                    await loop.run_in_executor(self.hunt_executor, lambda: geoip_mapper.execute(
                        network_connections=hunting_data.get('network_connections', []),
                        dns_queries=hunting_data.get('dns_queries', [])
                    ))
                except Exception as e:
                    logger.warning(f"GeoIP mapper plugin failed: {e}")

            if progress_callback:
                await progress_callback({'stage': 'finalize', 'message': 'Saving hunt results...', 'progress': 98})

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
from artemis.plugins.sigma_engine import SigmaEnginePlugin
from artemis.plugins.geoip_mapper import GeoIPMapperPlugin
plugin_manager.register_plugin('network_mapper', NetworkMapperPlugin)
plugin_manager.register_plugin('sigma_engine', SigmaEnginePlugin)
plugin_manager.register_plugin('geoip_mapper', GeoIPMapperPlugin)

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

    # Get Splunk connector from the hunt manager's pipeline
    hunt_manager.initialize_pipeline()
    if not hunt_manager.pipeline or not hunt_manager.pipeline.splunk:
        return JSONResponse(status_code=400, content={'error': 'Splunk connection not configured'})

    try:
        result = plugin.profile_devices(
            hunt_manager.pipeline.splunk,
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


# ============================================================================
# GeoIP Mapper Endpoints
# ============================================================================

@app.get("/api/geoip/map")
async def get_geoip_map():
    """Get GeoIP map data for visualization."""
    plugin = plugin_manager.get_plugin('geoip_mapper')
    if not plugin:
        return {'error': 'GeoIP mapper plugin not enabled'}
    return plugin.get_map_data()


@app.get("/api/geoip/stats")
async def get_geoip_stats():
    """Get GeoIP cache statistics."""
    plugin = plugin_manager.get_plugin('geoip_mapper')
    if not plugin:
        return {'error': 'GeoIP mapper plugin not enabled'}
    return plugin.get_cache_stats()


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
