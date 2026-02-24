"""Database manager for Artemis network mapping and progress tracking."""

import json
import sqlite3
import logging
from datetime import datetime, date
from typing import Dict, List

logger = logging.getLogger("artemis.db")


class _SafeEncoder(json.JSONEncoder):
    """Handle datetime and other non-serializable types from agent outputs."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        return super().default(obj)


def _dumps(obj):
    """json.dumps with datetime-safe encoding."""
    return json.dumps(obj, cls=_SafeEncoder)


class DatabaseManager:
    """Manages Artemis database for network mapping, profiling, and enrichment."""

    # Default busy timeout (ms) — how long SQLite waits on a locked DB
    # before raising OperationalError.  5 seconds is plenty for the brief
    # write locks that occur during normal operation.
    BUSY_TIMEOUT_MS = 5000

    def __init__(self, db_path: str = "artemis.db"):
        self.db_path = db_path
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        """Create a new SQLite connection with WAL mode and busy timeout."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute(f"PRAGMA busy_timeout = {self.BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_db(self):
        """Initialize database schema."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plugin_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_name TEXT,
                timestamp TIMESTAMP,
                result_type TEXT,
                result_data TEXT
            )
        """)

        # Job progress table — written by subprocess, polled by web server.
        # Subprocesses survive server restarts; progress is stored in SQLite.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hunt_progress (
                hunt_id TEXT PRIMARY KEY,
                pid INTEGER,
                stage TEXT,
                message TEXT,
                progress INTEGER DEFAULT 0,
                data TEXT,
                updated_at TIMESTAMP
            )
        """)

        # LAN groups — user-defined groupings of network devices
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lan_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                color TEXT DEFAULT '#667eea',
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)

        # Members of each LAN group (node IDs like "sensor:vlan:ip")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lan_group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                node_id TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES lan_groups(id) ON DELETE CASCADE,
                UNIQUE(group_id, node_id)
            )
        """)

        # Device flags — mark devices as malicious or suspicious
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL UNIQUE,
                flag_type TEXT NOT NULL CHECK(flag_type IN ('malicious', 'suspicious')),
                reason TEXT DEFAULT '',
                flagged_at TIMESTAMP
            )
        """)

        # Enrichment results — threat intel linked to IPs from findings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS enrichment_results (
                ip TEXT PRIMARY KEY,
                verdict TEXT NOT NULL,
                sources TEXT NOT NULL,
                enriched_at TIMESTAMP NOT NULL
            )
        """)

        # Enrichment queue — IPs waiting to be enriched by the background worker
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS enrichment_queue (
                ip TEXT PRIMARY KEY,
                hunt_id TEXT,
                queued_at TIMESTAMP NOT NULL
            )
        """)

        # Agent findings — threat detections from hunting agents
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL UNIQUE,
                agent_name TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                description TEXT NOT NULL,
                indicators TEXT DEFAULT '[]',
                affected_assets TEXT DEFAULT '[]',
                mitre_tactics TEXT DEFAULT '[]',
                mitre_techniques TEXT DEFAULT '[]',
                evidence_count INTEGER DEFAULT 0,
                recommended_actions TEXT DEFAULT '[]',
                source_cycle INTEGER DEFAULT 0,
                dismissed INTEGER DEFAULT 0,
                created_at TIMESTAMP NOT NULL
            )
        """)

        # LLM synthesis reports — stored per hunt cycle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS llm_syntheses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cycle INTEGER NOT NULL,
                overall_severity TEXT NOT NULL DEFAULT 'low',
                overall_confidence REAL NOT NULL DEFAULT 0.0,
                reasoning TEXT DEFAULT '',
                kill_chain TEXT DEFAULT '{}',
                correlations TEXT DEFAULT '[]',
                false_positive_flags TEXT DEFAULT '[]',
                recommended_actions TEXT DEFAULT '[]',
                full_synthesis TEXT DEFAULT '{}',
                created_at TIMESTAMP NOT NULL
            )
        """)

        # ------------------------------------------------------------------
        # Decoupled pipeline: persistent event store + analysis queue
        # ------------------------------------------------------------------

        # Persistent event store — all Splunk events keyed by cycle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hunt_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cycle INTEGER NOT NULL,
                data_type TEXT NOT NULL,
                event_json TEXT NOT NULL,
                collected_at TIMESTAMP NOT NULL
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_hunt_events_cycle_type "
            "ON hunt_events(cycle, data_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_hunt_events_collected "
            "ON hunt_events(collected_at)"
        )

        # Analysis queue — cycles waiting for LLM/agent analysis
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_queue (
                cycle INTEGER PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'pending',
                event_counts TEXT DEFAULT '{}',
                created_at TIMESTAMP NOT NULL,
                started_at TIMESTAMP,
                completed_at TIMESTAMP
            )
        """)

        # ------------------------------------------------------------------
        # Interactive map: layout positions + annotations
        # ------------------------------------------------------------------

        # Saved node positions (drag-and-drop)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS map_layout (
                node_id TEXT PRIMARY KEY,
                x REAL NOT NULL,
                y REAL NOT NULL,
                pinned INTEGER DEFAULT 0,
                updated_at TIMESTAMP NOT NULL
            )
        """)

        # User annotations on the network map
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS map_annotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT,
                annotation_type TEXT NOT NULL DEFAULT 'note',
                content TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Agent findings
    # ------------------------------------------------------------------

    def save_finding(self, finding_id: str, agent_name: str,
                     activity_type: str, severity: str, confidence: float,
                     description: str, indicators: list = None,
                     affected_assets: list = None, mitre_tactics: list = None,
                     mitre_techniques: list = None, evidence_count: int = 0,
                     recommended_actions: list = None,
                     source_cycle: int = 0) -> Dict:
        """Save an agent finding to the database."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            conn.execute(
                "INSERT OR IGNORE INTO agent_findings "
                "(finding_id, agent_name, activity_type, severity, confidence, "
                "description, indicators, affected_assets, mitre_tactics, "
                "mitre_techniques, evidence_count, recommended_actions, "
                "source_cycle, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding_id, agent_name, activity_type, severity, confidence,
                 description,
                 _dumps(indicators or []),
                 _dumps(affected_assets or []),
                 _dumps(mitre_tactics or []),
                 _dumps(mitre_techniques or []),
                 evidence_count,
                 _dumps(recommended_actions or []),
                 source_cycle, now),
            )
            conn.commit()
            return {'finding_id': finding_id, 'agent_name': agent_name,
                    'activity_type': activity_type, 'created_at': now}
        finally:
            conn.close()

    def get_findings(self, limit: int = 100, include_dismissed: bool = False,
                     agent_name: str = None, min_severity: str = None) -> List[Dict]:
        """Get agent findings with optional filtering."""
        conn = self._connect()
        try:
            query = "SELECT * FROM agent_findings WHERE 1=1"
            params = []

            if not include_dismissed:
                query += " AND dismissed = 0"
            if agent_name:
                query += " AND agent_name = ?"
                params.append(agent_name)
            if min_severity:
                severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                threshold = severity_order.get(min_severity.lower(), 3)
                allowed = [s for s, v in severity_order.items() if v <= threshold]
                placeholders = ",".join("?" for _ in allowed)
                query += f" AND severity IN ({placeholders})"
                params.extend(allowed)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                results.append({
                    'id': r['id'],
                    'finding_id': r['finding_id'],
                    'agent_name': r['agent_name'],
                    'activity_type': r['activity_type'],
                    'severity': r['severity'],
                    'confidence': r['confidence'],
                    'description': r['description'],
                    'indicators': json.loads(r['indicators']),
                    'affected_assets': json.loads(r['affected_assets']),
                    'mitre_tactics': json.loads(r['mitre_tactics']),
                    'mitre_techniques': json.loads(r['mitre_techniques']),
                    'evidence_count': r['evidence_count'],
                    'recommended_actions': json.loads(r['recommended_actions']),
                    'source_cycle': r['source_cycle'],
                    'dismissed': bool(r['dismissed']),
                    'created_at': r['created_at'],
                })
            return results
        finally:
            conn.close()

    def dismiss_finding(self, finding_id: str) -> bool:
        """Mark a finding as dismissed."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE agent_findings SET dismissed = 1 WHERE finding_id = ?",
                (finding_id,),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def get_findings_summary(self) -> Dict:
        """Get a summary of findings by severity and agent."""
        conn = self._connect()
        try:
            # Count by severity
            rows = conn.execute(
                "SELECT severity, COUNT(*) FROM agent_findings "
                "WHERE dismissed = 0 GROUP BY severity"
            ).fetchall()
            by_severity = {r[0]: r[1] for r in rows}

            # Count by agent
            rows = conn.execute(
                "SELECT agent_name, COUNT(*) FROM agent_findings "
                "WHERE dismissed = 0 GROUP BY agent_name"
            ).fetchall()
            by_agent = {r[0]: r[1] for r in rows}

            total = conn.execute(
                "SELECT COUNT(*) FROM agent_findings WHERE dismissed = 0"
            ).fetchone()[0]

            return {
                'total': total,
                'by_severity': by_severity,
                'by_agent': by_agent,
            }
        finally:
            conn.close()

    def clear_findings(self) -> int:
        """Delete all findings and LLM syntheses. Returns count deleted."""
        conn = self._connect()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM agent_findings"
            ).fetchone()[0]
            conn.execute("DELETE FROM agent_findings")
            conn.execute("DELETE FROM llm_syntheses")
            conn.commit()
            return count
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # LLM synthesis reports
    # ------------------------------------------------------------------

    def save_synthesis(self, cycle: int, synthesis: Dict) -> Dict:
        """Save an LLM synthesis report."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            conn.execute(
                "INSERT INTO llm_syntheses "
                "(cycle, overall_severity, overall_confidence, reasoning, "
                "kill_chain, correlations, false_positive_flags, "
                "recommended_actions, full_synthesis, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cycle,
                 synthesis.get('overall_severity', 'low'),
                 synthesis.get('overall_confidence', 0.0),
                 synthesis.get('reasoning', ''),
                 _dumps(synthesis.get('kill_chain_assessment', {})),
                 _dumps(synthesis.get('correlations', [])),
                 _dumps(synthesis.get('false_positive_flags', [])),
                 _dumps(synthesis.get('recommended_actions', [])),
                 _dumps(synthesis),
                 now),
            )
            conn.commit()
            return {'cycle': cycle, 'created_at': now}
        finally:
            conn.close()

    def get_syntheses(self, limit: int = 20) -> List[Dict]:
        """Get recent LLM synthesis reports."""
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM llm_syntheses ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            results = []
            for r in rows:
                results.append({
                    'id': r['id'],
                    'cycle': r['cycle'],
                    'overall_severity': r['overall_severity'],
                    'overall_confidence': r['overall_confidence'],
                    'reasoning': r['reasoning'],
                    'kill_chain': json.loads(r['kill_chain']),
                    'correlations': json.loads(r['correlations']),
                    'false_positive_flags': json.loads(r['false_positive_flags']),
                    'recommended_actions': json.loads(r['recommended_actions']),
                    'full_synthesis': json.loads(r['full_synthesis']),
                    'created_at': r['created_at'],
                })
            return results
        finally:
            conn.close()

    def get_latest_synthesis(self) -> Dict | None:
        """Get the most recent LLM synthesis report."""
        results = self.get_syntheses(limit=1)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # LAN groups
    # ------------------------------------------------------------------

    def create_lan_group(self, name: str, description: str = '',
                         color: str = '#667eea',
                         member_ids: List[str] = None) -> Dict:
        """Create a new LAN group with optional initial members."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO lan_groups (name, description, color, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, description, color, now, now),
            )
            group_id = cursor.lastrowid
            if member_ids:
                for nid in member_ids:
                    cursor.execute(
                        "INSERT OR IGNORE INTO lan_group_members (group_id, node_id) "
                        "VALUES (?, ?)",
                        (group_id, nid),
                    )
            conn.commit()
            return {'id': group_id, 'name': name, 'description': description,
                    'color': color, 'members': member_ids or []}
        finally:
            conn.close()

    def get_lan_groups(self) -> List[Dict]:
        """Get all LAN groups with their members."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, name, description, color, created_at, updated_at "
                "FROM lan_groups ORDER BY name"
            ).fetchall()
            groups = []
            for r in rows:
                members = conn.execute(
                    "SELECT node_id FROM lan_group_members WHERE group_id = ?",
                    (r[0],)
                ).fetchall()
                groups.append({
                    'id': r[0], 'name': r[1], 'description': r[2],
                    'color': r[3], 'created_at': r[4], 'updated_at': r[5],
                    'members': [m[0] for m in members],
                })
            return groups
        finally:
            conn.close()

    def update_lan_group(self, group_id: int, name: str = None,
                         description: str = None, color: str = None,
                         member_ids: List[str] = None) -> bool:
        """Update a LAN group's properties and/or members."""
        conn = self._connect()
        try:
            updates = []
            params = []
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            if color is not None:
                updates.append("color = ?")
                params.append(color)
            if updates:
                updates.append("updated_at = ?")
                params.append(datetime.now().isoformat())
                params.append(group_id)
                conn.execute(
                    f"UPDATE lan_groups SET {', '.join(updates)} WHERE id = ?",
                    params,
                )
            if member_ids is not None:
                conn.execute(
                    "DELETE FROM lan_group_members WHERE group_id = ?",
                    (group_id,),
                )
                for nid in member_ids:
                    conn.execute(
                        "INSERT OR IGNORE INTO lan_group_members (group_id, node_id) "
                        "VALUES (?, ?)",
                        (group_id, nid),
                    )
            conn.commit()
            return True
        finally:
            conn.close()

    def delete_lan_group(self, group_id: int) -> bool:
        """Delete a LAN group and its memberships."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM lan_group_members WHERE group_id = ?", (group_id,))
            conn.execute("DELETE FROM lan_groups WHERE id = ?", (group_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Device flags
    # ------------------------------------------------------------------

    def set_device_flag(self, node_id: str, flag_type: str,
                        reason: str = '') -> Dict:
        """Flag a device as malicious or suspicious."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO device_flags (node_id, flag_type, reason, flagged_at) "
                "VALUES (?, ?, ?, ?)",
                (node_id, flag_type, reason, now),
            )
            conn.commit()
            return {'node_id': node_id, 'flag_type': flag_type,
                    'reason': reason, 'flagged_at': now}
        finally:
            conn.close()

    def remove_device_flag(self, node_id: str) -> bool:
        """Remove a flag from a device."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM device_flags WHERE node_id = ?", (node_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def get_device_flags(self) -> Dict[str, Dict]:
        """Get all device flags as a dict keyed by node_id."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT node_id, flag_type, reason, flagged_at FROM device_flags"
            ).fetchall()
            return {
                r[0]: {'flag_type': r[1], 'reason': r[2], 'flagged_at': r[3]}
                for r in rows
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Job progress (written by subprocess, polled by server)
    # ------------------------------------------------------------------

    def write_progress(self, hunt_id: str, pid: int, stage: str,
                       message: str, progress: int, data: dict = None):
        """Write job progress from the subprocess."""
        conn = self._connect()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO hunt_progress
                    (hunt_id, pid, stage, message, progress, data, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                hunt_id, pid, stage, message, progress,
                _dumps(data) if data else None,
                datetime.now().isoformat(),
            ))
            conn.commit()
        finally:
            conn.close()

    def read_progress(self, hunt_id: str) -> dict | None:
        """Read current progress for a job."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT hunt_id, pid, stage, message, progress, data, updated_at "
                "FROM hunt_progress WHERE hunt_id = ?", (hunt_id,)
            ).fetchone()
            if not row:
                return None
            return {
                'hunt_id': row[0], 'pid': row[1], 'stage': row[2],
                'message': row[3], 'progress': row[4],
                'data': json.loads(row[5]) if row[5] else {},
                'updated_at': row[6],
            }
        finally:
            conn.close()

    def get_all_running_progress(self) -> List[dict]:
        """Get progress rows for all jobs that haven't reached a terminal state."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT hunt_id, pid, stage, message, progress, data, updated_at "
                "FROM hunt_progress WHERE stage NOT IN ('complete', 'error')"
            ).fetchall()
            return [{
                'hunt_id': r[0], 'pid': r[1], 'stage': r[2],
                'message': r[3], 'progress': r[4],
                'data': json.loads(r[5]) if r[5] else {},
                'updated_at': r[6],
            } for r in rows]
        finally:
            conn.close()

    def clear_progress(self, hunt_id: str):
        """Remove progress row after job completes."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM hunt_progress WHERE hunt_id = ?", (hunt_id,))
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def save_enrichment(self, ip: str, verdict: str, sources: Dict):
        """Save enrichment result for an IP."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO enrichment_results "
                "(ip, verdict, sources, enriched_at) VALUES (?, ?, ?, ?)",
                (ip, verdict, _dumps(sources), datetime.now().isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

    def get_enrichment(self, ip: str) -> Dict | None:
        """Get enrichment result for an IP."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT ip, verdict, sources, enriched_at "
                "FROM enrichment_results WHERE ip = ?", (ip,)
            ).fetchone()
            if not row:
                return None
            return {
                'ip': row[0], 'verdict': row[1],
                'sources': json.loads(row[2]), 'enriched_at': row[3],
            }
        finally:
            conn.close()

    def get_enrichments_bulk(self, ips: List[str]) -> Dict[str, Dict]:
        """Get enrichment results for multiple IPs at once."""
        if not ips:
            return {}
        conn = self._connect()
        try:
            placeholders = ",".join("?" for _ in ips)
            rows = conn.execute(
                f"SELECT ip, verdict, sources, enriched_at "
                f"FROM enrichment_results WHERE ip IN ({placeholders})",
                ips,
            ).fetchall()
            return {
                r[0]: {'verdict': r[1], 'sources': json.loads(r[2]),
                       'enriched_at': r[3]}
                for r in rows
            }
        finally:
            conn.close()

    def queue_enrichment(self, ips: List[str], hunt_id: str = ""):
        """Add IPs to the enrichment queue (skips already-queued IPs)."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            for ip in ips:
                conn.execute(
                    "INSERT OR IGNORE INTO enrichment_queue "
                    "(ip, hunt_id, queued_at) VALUES (?, ?, ?)",
                    (ip, hunt_id, now),
                )
            conn.commit()
        finally:
            conn.close()

    def dequeue_enrichment(self, batch_size: int = 10) -> List[str]:
        """Pop up to batch_size IPs from the enrichment queue."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT ip FROM enrichment_queue ORDER BY queued_at LIMIT ?",
                (batch_size,),
            ).fetchall()
            ips = [r[0] for r in rows]
            if ips:
                placeholders = ",".join("?" for _ in ips)
                conn.execute(
                    f"DELETE FROM enrichment_queue WHERE ip IN ({placeholders})",
                    ips,
                )
                conn.commit()
            return ips
        finally:
            conn.close()

    def enrichment_queue_size(self) -> int:
        """Get number of IPs waiting in the enrichment queue."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM enrichment_queue"
            ).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

    def get_all_enrichments(self) -> List[Dict]:
        """Get all enrichment results."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT ip, verdict, sources, enriched_at "
                "FROM enrichment_results ORDER BY enriched_at DESC"
            ).fetchall()
            return [{
                'ip': r[0], 'verdict': r[1],
                'sources': json.loads(r[2]), 'enriched_at': r[3],
            } for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Persistent event store (decoupled pipeline)
    # ------------------------------------------------------------------

    def store_events(self, cycle: int, data_type: str,
                     events: List[Dict]) -> int:
        """Bulk-insert events for a cycle into the persistent store."""
        if not events:
            return 0
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            conn.executemany(
                "INSERT INTO hunt_events (cycle, data_type, event_json, "
                "collected_at) VALUES (?, ?, ?, ?)",
                [(cycle, data_type, _dumps(e), now) for e in events],
            )
            conn.commit()
            return len(events)
        finally:
            conn.close()

    def get_events_for_cycle(self, cycle: int) -> Dict[str, List[Dict]]:
        """Retrieve all events for a cycle, grouped by data_type."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT data_type, event_json FROM hunt_events "
                "WHERE cycle = ? ORDER BY id",
                (cycle,),
            ).fetchall()
            result: Dict[str, List[Dict]] = {}
            for data_type, event_json in rows:
                result.setdefault(data_type, []).append(json.loads(event_json))
            return result
        finally:
            conn.close()

    def get_event_counts_for_cycle(self, cycle: int) -> Dict[str, int]:
        """Get event counts by data_type for a cycle."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT data_type, COUNT(*) FROM hunt_events "
                "WHERE cycle = ? GROUP BY data_type",
                (cycle,),
            ).fetchall()
            return {r[0]: r[1] for r in rows}
        finally:
            conn.close()

    def get_latest_event_cycle(self) -> int:
        """Get the highest cycle number in the event store."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT MAX(cycle) FROM hunt_events"
            ).fetchone()
            return row[0] or 0
        finally:
            conn.close()

    def cleanup_old_events(self, max_age_hours: int = 72) -> int:
        """Delete events older than max_age_hours. Returns count deleted."""
        conn = self._connect()
        try:
            from datetime import timedelta
            cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
            cursor = conn.execute(
                "DELETE FROM hunt_events WHERE collected_at < ?",
                (cutoff,),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Analysis queue (decoupled pipeline)
    # ------------------------------------------------------------------

    def queue_analysis(self, cycle: int, event_counts: Dict[str, int] = None):
        """Queue a cycle for agent/LLM analysis."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO analysis_queue "
                "(cycle, status, event_counts, created_at) "
                "VALUES (?, 'pending', ?, ?)",
                (cycle, _dumps(event_counts or {}),
                 datetime.now().isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

    def get_pending_analysis(self) -> Dict | None:
        """Get the next cycle waiting for analysis."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT cycle, event_counts, created_at "
                "FROM analysis_queue WHERE status = 'pending' "
                "ORDER BY cycle ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            return {
                'cycle': row[0],
                'event_counts': json.loads(row[1]) if row[1] else {},
                'created_at': row[2],
            }
        finally:
            conn.close()

    def mark_analysis_started(self, cycle: int):
        """Mark a cycle as being analyzed."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE analysis_queue SET status = 'in_progress', "
                "started_at = ? WHERE cycle = ?",
                (datetime.now().isoformat(), cycle),
            )
            conn.commit()
        finally:
            conn.close()

    def mark_analysis_complete(self, cycle: int):
        """Mark a cycle's analysis as complete."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE analysis_queue SET status = 'complete', "
                "completed_at = ? WHERE cycle = ?",
                (datetime.now().isoformat(), cycle),
            )
            conn.commit()
        finally:
            conn.close()

    def get_analysis_queue_status(self) -> Dict:
        """Get summary of the analysis queue."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM analysis_queue GROUP BY status"
            ).fetchall()
            by_status = {r[0]: r[1] for r in rows}
            latest = conn.execute(
                "SELECT cycle, status, created_at, started_at, completed_at "
                "FROM analysis_queue ORDER BY cycle DESC LIMIT 1"
            ).fetchone()
            return {
                'pending': by_status.get('pending', 0),
                'in_progress': by_status.get('in_progress', 0),
                'complete': by_status.get('complete', 0),
                'latest': {
                    'cycle': latest[0],
                    'status': latest[1],
                    'created_at': latest[2],
                    'started_at': latest[3],
                    'completed_at': latest[4],
                } if latest else None,
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Map layout (saved node positions)
    # ------------------------------------------------------------------

    def save_layout(self, positions: Dict[str, Dict]) -> int:
        """Save node positions. positions = {node_id: {x, y, pinned}}."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            count = 0
            for node_id, pos in positions.items():
                conn.execute(
                    "INSERT OR REPLACE INTO map_layout "
                    "(node_id, x, y, pinned, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (node_id, pos['x'], pos['y'],
                     1 if pos.get('pinned') else 0, now),
                )
                count += 1
            conn.commit()
            return count
        finally:
            conn.close()

    def get_layout(self) -> Dict[str, Dict]:
        """Get all saved node positions."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT node_id, x, y, pinned, updated_at FROM map_layout"
            ).fetchall()
            return {
                r[0]: {'x': r[1], 'y': r[2], 'pinned': bool(r[3]),
                       'updated_at': r[4]}
                for r in rows
            }
        finally:
            conn.close()

    def clear_layout(self) -> int:
        """Delete all saved positions (reset to auto-layout)."""
        conn = self._connect()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM map_layout"
            ).fetchone()[0]
            conn.execute("DELETE FROM map_layout")
            conn.commit()
            return count
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Map annotations
    # ------------------------------------------------------------------

    def create_annotation(self, node_id: str | None,
                          annotation_type: str, content: str,
                          metadata: Dict = None) -> Dict:
        """Create a map annotation."""
        conn = self._connect()
        try:
            now = datetime.now().isoformat()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO map_annotations "
                "(node_id, annotation_type, content, metadata, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (node_id, annotation_type, content,
                 _dumps(metadata or {}), now, now),
            )
            ann_id = cursor.lastrowid
            conn.commit()
            return {
                'id': ann_id, 'node_id': node_id,
                'annotation_type': annotation_type,
                'content': content,
                'metadata': metadata or {},
                'created_at': now, 'updated_at': now,
            }
        finally:
            conn.close()

    def get_annotations(self, node_id: str = None) -> List[Dict]:
        """Get annotations, optionally filtered by node_id."""
        conn = self._connect()
        try:
            if node_id:
                rows = conn.execute(
                    "SELECT id, node_id, annotation_type, content, metadata, "
                    "created_at, updated_at FROM map_annotations "
                    "WHERE node_id = ? ORDER BY created_at DESC",
                    (node_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, node_id, annotation_type, content, metadata, "
                    "created_at, updated_at FROM map_annotations "
                    "ORDER BY created_at DESC"
                ).fetchall()
            return [{
                'id': r[0], 'node_id': r[1],
                'annotation_type': r[2], 'content': r[3],
                'metadata': json.loads(r[4]) if r[4] else {},
                'created_at': r[5], 'updated_at': r[6],
            } for r in rows]
        finally:
            conn.close()

    def update_annotation(self, ann_id: int, content: str = None,
                          metadata: Dict = None) -> bool:
        """Update an annotation's content or metadata."""
        conn = self._connect()
        try:
            updates = []
            params = []
            if content is not None:
                updates.append("content = ?")
                params.append(content)
            if metadata is not None:
                updates.append("metadata = ?")
                params.append(_dumps(metadata))
            if not updates:
                return False
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            params.append(ann_id)
            conn.execute(
                f"UPDATE map_annotations SET {', '.join(updates)} "
                f"WHERE id = ?",
                params,
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def delete_annotation(self, ann_id: int) -> bool:
        """Delete an annotation."""
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM map_annotations WHERE id = ?", (ann_id,),
            )
            conn.commit()
            return True
        finally:
            conn.close()

