"""Database manager for Artemis network mapping and progress tracking."""

import json
import sqlite3
import logging
import time as _time
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
    BUSY_TIMEOUT_MS = 30000  # 30 s — three pipelines write concurrently

    def __init__(self, db_path: str = "artemis.db"):
        self.db_path = db_path
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        """Create a new SQLite connection with WAL mode and busy timeout."""
        conn = sqlite3.connect(self.db_path, timeout=60)
        conn.execute(f"PRAGMA busy_timeout = {self.BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _exec_with_retry(self, fn, max_retries=6):
        """Execute *fn(conn)* with automatic retry on database-locked errors.

        Three pipeline processes write concurrently; despite WAL mode and a
        busy timeout, transient OperationalError can still occur.  This
        helper retries with exponential back-off (1s, 2s, 4s, 8s, 16s).
        """
        for attempt in range(max_retries):
            conn = self._connect()
            try:
                result = fn(conn)
                conn.commit()
                return result
            except sqlite3.OperationalError:
                if attempt < max_retries - 1:
                    _time.sleep(1.0 * (2 ** attempt))
                else:
                    raise
            finally:
                conn.close()

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

        # Agent activity log — written by analysis subprocess, polled by web server
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent TEXT NOT NULL,
                activity TEXT NOT NULL,
                detail TEXT DEFAULT '{}',
                created_at TIMESTAMP NOT NULL
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_activity_created "
            "ON agent_activity(created_at)"
        )

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

        # ------------------------------------------------------------------
        # Autonomous case management
        # ------------------------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                description TEXT DEFAULT '',
                mitre_techniques TEXT DEFAULT '[]',
                affected_assets TEXT DEFAULT '[]',
                kill_chain_stages TEXT DEFAULT '[]',
                recommended_actions TEXT DEFAULT '[]',
                hunt_cycle INTEGER DEFAULT 0,
                source TEXT DEFAULT 'autonomous',
                escalation_level TEXT DEFAULT 'human_review',
                iris_case_id TEXT,
                analyst_verdict TEXT,
                analyst_notes TEXT DEFAULT '',
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                resolved_at TIMESTAMP
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_status "
            "ON cases(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_severity "
            "ON cases(severity)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_created "
            "ON cases(created_at)"
        )

        # Junction table: case <-> finding (many-to-many)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS case_findings (
                case_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                added_at TIMESTAMP NOT NULL,
                PRIMARY KEY (case_id, finding_id),
                FOREIGN KEY (case_id) REFERENCES cases(case_id),
                FOREIGN KEY (finding_id) REFERENCES agent_findings(finding_id)
            )
        """)

        # Technique precision tracking (for self-learning feedback loop)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS technique_precision (
                technique_id TEXT PRIMARY KEY,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                uncertain INTEGER DEFAULT 0,
                precision REAL DEFAULT 0.5,
                last_updated TIMESTAMP
            )
        """)

        # Hunt scheduler state
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scheduler_state (
                id INTEGER PRIMARY KEY DEFAULT 1,
                status TEXT DEFAULT 'stopped',
                last_run_at TIMESTAMP,
                last_run_result TEXT,
                next_run_at TIMESTAMP,
                total_hunts INTEGER DEFAULT 0,
                total_cases_created INTEGER DEFAULT 0,
                updated_at TIMESTAMP
            )
        """)

        # Adaptive learning state (survives server restarts)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learning_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Learning state persistence
    # ------------------------------------------------------------------

    def save_learning_state(self, key: str, value_dict: dict) -> None:
        """Persist a learning-state blob (JSON-serialisable dict)."""
        def _do(conn):
            conn.execute(
                "INSERT OR REPLACE INTO learning_state (key, value, updated_at) "
                "VALUES (?, ?, ?)",
                (key, _dumps(value_dict), datetime.now().isoformat()),
            )
        self._exec_with_retry(_do)

    def load_learning_state(self, key: str) -> dict:
        """Load a previously saved learning-state blob, or empty dict."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM learning_state WHERE key = ?", (key,)
            ).fetchone()
            return json.loads(row[0]) if row else {}
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(self, case_id: str, title: str, severity: str,
                    confidence: float, description: str = "",
                    mitre_techniques: list = None,
                    affected_assets: list = None,
                    kill_chain_stages: list = None,
                    recommended_actions: list = None,
                    hunt_cycle: int = 0, source: str = "autonomous",
                    escalation_level: str = "human_review",
                    finding_ids: list = None) -> Dict:
        """Create a new case and link findings to it."""
        now = datetime.now().isoformat()

        def _do(conn):
            conn.execute(
                "INSERT INTO cases "
                "(case_id, title, status, severity, confidence, description, "
                "mitre_techniques, affected_assets, kill_chain_stages, "
                "recommended_actions, hunt_cycle, source, escalation_level, "
                "created_at, updated_at) "
                "VALUES (?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, title, severity, confidence, description,
                 _dumps(mitre_techniques or []),
                 _dumps(affected_assets or []),
                 _dumps(kill_chain_stages or []),
                 _dumps(recommended_actions or []),
                 hunt_cycle, source, escalation_level, now, now),
            )
            # Link findings
            if finding_ids:
                for fid in finding_ids:
                    conn.execute(
                        "INSERT OR IGNORE INTO case_findings "
                        "(case_id, finding_id, added_at) VALUES (?, ?, ?)",
                        (case_id, fid, now),
                    )
            return {"case_id": case_id, "title": title, "created_at": now}
        return self._exec_with_retry(_do)

    def get_cases(self, limit: int = 100, status: str = None,
                  severity: str = None, escalation_level: str = None,
                  source: str = None) -> List[Dict]:
        """Get cases with optional filtering."""
        conn = self._connect()
        try:
            query = "SELECT * FROM cases WHERE 1=1"
            params = []

            if status:
                query += " AND status = ?"
                params.append(status)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if escalation_level:
                query += " AND escalation_level = ?"
                params.append(escalation_level)
            if source:
                query += " AND source = ?"
                params.append(source)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                case_dict = self._row_to_case_dict(r)
                # Attach linked finding IDs
                findings = conn.execute(
                    "SELECT finding_id FROM case_findings WHERE case_id = ?",
                    (r["case_id"],),
                ).fetchall()
                case_dict["findings"] = [f[0] for f in findings]
                results.append(case_dict)
            return results
        finally:
            conn.close()

    def get_case(self, case_id: str) -> Dict | None:
        """Get a single case by ID with linked findings."""
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if not row:
                return None
            case_dict = self._row_to_case_dict(row)
            findings = conn.execute(
                "SELECT finding_id FROM case_findings WHERE case_id = ?",
                (case_id,),
            ).fetchall()
            case_dict["findings"] = [f[0] for f in findings]
            return case_dict
        finally:
            conn.close()

    def update_case(self, case_id: str, **kwargs) -> bool:
        """Update case fields. Accepts any column name as keyword argument."""
        conn = self._connect()
        try:
            updates = []
            params = []
            json_fields = {
                "mitre_techniques", "affected_assets", "kill_chain_stages",
                "recommended_actions",
            }
            for key, value in kwargs.items():
                if key in json_fields:
                    updates.append(f"{key} = ?")
                    params.append(_dumps(value))
                else:
                    updates.append(f"{key} = ?")
                    params.append(value)
            if not updates:
                return False
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            params.append(case_id)
            conn.execute(
                f"UPDATE cases SET {', '.join(updates)} WHERE case_id = ?",
                params,
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def resolve_case(self, case_id: str, verdict: str,
                     notes: str = "") -> bool:
        """Resolve a case with an analyst verdict (tp, fp, uncertain)."""
        now = datetime.now().isoformat()
        status_map = {"tp": "confirmed_tp", "fp": "confirmed_fp",
                      "uncertain": "closed"}
        status = status_map.get(verdict, "closed")

        conn = self._connect()
        try:
            conn.execute(
                "UPDATE cases SET status = ?, analyst_verdict = ?, "
                "analyst_notes = ?, resolved_at = ?, updated_at = ? "
                "WHERE case_id = ?",
                (status, verdict, notes, now, now, case_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def link_finding_to_case(self, case_id: str, finding_id: str) -> bool:
        """Add a finding to an existing case."""
        now = datetime.now().isoformat()

        def _do(conn):
            conn.execute(
                "INSERT OR IGNORE INTO case_findings "
                "(case_id, finding_id, added_at) VALUES (?, ?, ?)",
                (case_id, finding_id, now),
            )
            conn.execute(
                "UPDATE cases SET updated_at = ? WHERE case_id = ?",
                (now, case_id),
            )
            return True
        return self._exec_with_retry(_do)

    def get_case_stats(self) -> Dict:
        """Get summary statistics for cases."""
        conn = self._connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM cases"
            ).fetchone()[0]

            by_status = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) FROM cases GROUP BY status"
            ).fetchall():
                by_status[row[0]] = row[1]

            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) FROM cases GROUP BY severity"
            ).fetchall():
                by_severity[row[0]] = row[1]

            by_escalation = {}
            for row in conn.execute(
                "SELECT escalation_level, COUNT(*) FROM cases "
                "GROUP BY escalation_level"
            ).fetchall():
                by_escalation[row[0]] = row[1]

            # TP/FP rates
            resolved = conn.execute(
                "SELECT analyst_verdict, COUNT(*) FROM cases "
                "WHERE analyst_verdict IS NOT NULL "
                "GROUP BY analyst_verdict"
            ).fetchall()
            verdict_counts = {r[0]: r[1] for r in resolved}

            return {
                "total": total,
                "by_status": by_status,
                "by_severity": by_severity,
                "by_escalation": by_escalation,
                "verdicts": verdict_counts,
            }
        finally:
            conn.close()

    def get_open_cases_for_dedup(self, mitre_techniques: list,
                                 affected_assets: list,
                                 window_hours: int = 1) -> List[Dict]:
        """Find open cases matching techniques/assets within a time window.

        Used by CaseGenerator to deduplicate findings into existing cases.
        """
        conn = self._connect()
        try:
            from datetime import timedelta
            cutoff = (datetime.now() - timedelta(hours=window_hours)).isoformat()
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM cases "
                "WHERE status IN ('new', 'investigating') "
                "AND created_at >= ? "
                "ORDER BY created_at DESC",
                (cutoff,),
            ).fetchall()

            technique_set = set(mitre_techniques)
            asset_set = set(affected_assets)
            matches = []
            for r in rows:
                case_techniques = set(json.loads(r["mitre_techniques"]))
                case_assets = set(json.loads(r["affected_assets"]))
                # Match if overlapping techniques AND overlapping assets
                if (technique_set & case_techniques) and (asset_set & case_assets):
                    matches.append(self._row_to_case_dict(r))
            return matches
        finally:
            conn.close()

    def _row_to_case_dict(self, r) -> Dict:
        """Convert a sqlite3.Row from cases table to a dict."""
        return {
            "case_id": r["case_id"],
            "title": r["title"],
            "status": r["status"],
            "severity": r["severity"],
            "confidence": r["confidence"],
            "description": r["description"],
            "mitre_techniques": json.loads(r["mitre_techniques"]),
            "affected_assets": json.loads(r["affected_assets"]),
            "kill_chain_stages": json.loads(r["kill_chain_stages"]),
            "recommended_actions": json.loads(r["recommended_actions"]),
            "hunt_cycle": r["hunt_cycle"],
            "source": r["source"],
            "escalation_level": r["escalation_level"],
            "iris_case_id": r["iris_case_id"],
            "analyst_verdict": r["analyst_verdict"],
            "analyst_notes": r["analyst_notes"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "resolved_at": r["resolved_at"],
        }

    # ------------------------------------------------------------------
    # Technique precision (self-learning feedback)
    # ------------------------------------------------------------------

    def update_technique_precision(self, technique_id: str,
                                   verdict: str) -> Dict:
        """Update precision tracking for a MITRE technique after a case verdict.

        Args:
            technique_id: MITRE technique ID (e.g. T1071)
            verdict: tp, fp, or uncertain
        """
        now = datetime.now().isoformat()

        def _do(conn):
            # Ensure row exists
            conn.execute(
                "INSERT OR IGNORE INTO technique_precision "
                "(technique_id, last_updated) VALUES (?, ?)",
                (technique_id, now),
            )
            # Increment the appropriate counter
            col = {"tp": "true_positives", "fp": "false_positives",
                    "uncertain": "uncertain"}.get(verdict, "uncertain")
            conn.execute(
                f"UPDATE technique_precision SET {col} = {col} + 1, "
                "last_updated = ? WHERE technique_id = ?",
                (now, technique_id),
            )
            # Recalculate precision = tp / (tp + fp) or 0.5 if no data
            row = conn.execute(
                "SELECT true_positives, false_positives "
                "FROM technique_precision WHERE technique_id = ?",
                (technique_id,),
            ).fetchone()
            tp, fp = row[0], row[1]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.5
            conn.execute(
                "UPDATE technique_precision SET precision = ? "
                "WHERE technique_id = ?",
                (precision, technique_id),
            )
            return {"technique_id": technique_id, "precision": precision,
                    "tp": tp, "fp": fp}
        return self._exec_with_retry(_do)

    def get_technique_precision(self, technique_ids: list = None) -> Dict[str, Dict]:
        """Get precision data for techniques. Returns all if no IDs specified."""
        conn = self._connect()
        try:
            if technique_ids:
                placeholders = ",".join("?" for _ in technique_ids)
                rows = conn.execute(
                    f"SELECT technique_id, true_positives, false_positives, "
                    f"uncertain, precision, last_updated "
                    f"FROM technique_precision "
                    f"WHERE technique_id IN ({placeholders})",
                    technique_ids,
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT technique_id, true_positives, false_positives, "
                    "uncertain, precision, last_updated "
                    "FROM technique_precision"
                ).fetchall()
            return {
                r[0]: {"true_positives": r[1], "false_positives": r[2],
                       "uncertain": r[3], "precision": r[4],
                       "last_updated": r[5]}
                for r in rows
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Scheduler state
    # ------------------------------------------------------------------

    def get_scheduler_state(self) -> Dict | None:
        """Get current scheduler state."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status, last_run_at, last_run_result, next_run_at, "
                "total_hunts, total_cases_created, updated_at "
                "FROM scheduler_state WHERE id = 1"
            ).fetchone()
            if not row:
                return None
            return {
                "status": row[0], "last_run_at": row[1],
                "last_run_result": row[2], "next_run_at": row[3],
                "total_hunts": row[4], "total_cases_created": row[5],
                "updated_at": row[6],
            }
        finally:
            conn.close()

    def update_scheduler_state(self, **kwargs) -> bool:
        """Update scheduler state fields."""
        conn = self._connect()
        try:
            # Ensure row exists
            conn.execute(
                "INSERT OR IGNORE INTO scheduler_state (id, updated_at) "
                "VALUES (1, ?)",
                (datetime.now().isoformat(),),
            )
            updates = []
            params = []
            for key, value in kwargs.items():
                updates.append(f"{key} = ?")
                params.append(value)
            if not updates:
                return False
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            conn.execute(
                f"UPDATE scheduler_state SET {', '.join(updates)} WHERE id = 1",
                params,
            )
            conn.commit()
            return True
        finally:
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
        now = datetime.now().isoformat()

        def _do(conn):
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
            return {'finding_id': finding_id, 'agent_name': agent_name,
                    'activity_type': activity_type, 'created_at': now}
        return self._exec_with_retry(_do)

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
        now = datetime.now().isoformat()

        def _do(conn):
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
            return {'cycle': cycle, 'created_at': now}
        return self._exec_with_retry(_do)

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
        def _do(conn):
            conn.execute("""
                INSERT OR REPLACE INTO hunt_progress
                    (hunt_id, pid, stage, message, progress, data, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                hunt_id, pid, stage, message, progress,
                _dumps(data) if data else None,
                datetime.now().isoformat(),
            ))
        self._exec_with_retry(_do)

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
        now = datetime.now().isoformat()
        rows = [(cycle, data_type, _dumps(e), now) for e in events]

        def _do(conn):
            conn.executemany(
                "INSERT INTO hunt_events (cycle, data_type, event_json, "
                "collected_at) VALUES (?, ?, ?, ?)",
                rows,
            )
            return len(events)
        return self._exec_with_retry(_do)

    def get_events_for_cycle(self, cycle: int,
                             max_per_type: int = 200_000) -> Dict[str, List[Dict]]:
        """Retrieve events for a cycle, grouped by data_type.

        When a data_type has more than *max_per_type* rows, a uniformly
        spaced sample is returned so agents get representative coverage
        without loading millions of rows into RAM.  The ``_counts`` key
        (added by the caller) preserves the real totals for LLM prompts.

        Set *max_per_type* to 0 to load everything (original behaviour).
        """
        conn = self._connect()
        try:
            if max_per_type <= 0:
                # Original unlimited path
                rows = conn.execute(
                    "SELECT data_type, event_json FROM hunt_events "
                    "WHERE cycle = ? ORDER BY id",
                    (cycle,),
                ).fetchall()
                result: Dict[str, List[Dict]] = {}
                for data_type, event_json in rows:
                    result.setdefault(data_type, []).append(
                        json.loads(event_json))
                return result

            # Get per-type counts first to decide whether to sample
            type_counts = self.get_event_counts_for_cycle(cycle)
            result: Dict[str, List[Dict]] = {}

            for data_type, total in type_counts.items():
                if total <= max_per_type:
                    # Small enough — load all
                    rows = conn.execute(
                        "SELECT event_json FROM hunt_events "
                        "WHERE cycle = ? AND data_type = ? ORDER BY id",
                        (cycle, data_type),
                    ).fetchall()
                    result[data_type] = [
                        json.loads(r[0]) for r in rows]
                else:
                    # Sample uniformly via rowid modulo
                    # Pick every Nth row so we get ~max_per_type events
                    # spread evenly across the cycle's time range.
                    step = total // max_per_type
                    rows = conn.execute(
                        "SELECT event_json FROM ("
                        "  SELECT event_json, ROW_NUMBER() OVER "
                        "    (ORDER BY id) AS rn "
                        "  FROM hunt_events "
                        "  WHERE cycle = ? AND data_type = ?"
                        ") WHERE rn % ? = 1",
                        (cycle, data_type, step),
                    ).fetchall()
                    result[data_type] = [
                        json.loads(r[0]) for r in rows]

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

    def get_event_time_range(self) -> Dict[str, str]:
        """Return the earliest and latest collected_at timestamps from stored events.

        Returns dict with 'earliest' and 'latest' ISO timestamps, or empty
        strings if no events exist.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT MIN(collected_at), MAX(collected_at) "
                "FROM hunt_events"
            ).fetchone()
            return {
                'earliest': row[0] or '' if row else '',
                'latest': row[1] or '' if row else '',
            }
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

    def get_unqueued_event_cycles(self) -> List[Dict]:
        """Return cycles that have stored events but no analysis_queue entry.

        Used on restart to re-queue existing events instead of re-downloading
        from Splunk.
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT he.cycle, COUNT(*) as event_count "
                "FROM hunt_events he "
                "LEFT JOIN analysis_queue aq ON he.cycle = aq.cycle "
                "WHERE aq.cycle IS NULL "
                "GROUP BY he.cycle ORDER BY he.cycle"
            ).fetchall()
            return [{'cycle': r[0], 'event_count': r[1]} for r in rows]
        finally:
            conn.close()

    def get_total_event_count(self) -> int:
        """Return total number of rows in hunt_events."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) FROM hunt_events").fetchone()
            return row[0] or 0
        finally:
            conn.close()

    def cleanup_analyzed_events(self, batch_size: int = 100_000) -> int:
        """Delete events for cycles that have completed analysis.

        Keeps events for pending/in_progress cycles so agents can still
        read them.  Deletes in batches to avoid massive WAL growth.
        Returns total rows deleted.
        """
        total_deleted = 0
        conn = self._connect()
        try:
            # Find cycles that are fully analyzed
            complete = conn.execute(
                "SELECT cycle FROM analysis_queue WHERE status = 'complete'"
            ).fetchall()
            complete_cycles = [r[0] for r in complete]
        finally:
            conn.close()

        for cyc in complete_cycles:
            while True:
                conn = self._connect()
                try:
                    cursor = conn.execute(
                        "DELETE FROM hunt_events WHERE rowid IN "
                        "(SELECT rowid FROM hunt_events "
                        " WHERE cycle = ? LIMIT ?)",
                        (cyc, batch_size),
                    )
                    conn.commit()
                    deleted = cursor.rowcount
                finally:
                    conn.close()
                if deleted == 0:
                    break
                total_deleted += deleted

        return total_deleted

    def cleanup_old_events(self, max_age_hours: int = 72,
                           batch_size: int = 50_000) -> int:
        """Delete events older than max_age_hours in batches.

        Deletes in chunks of *batch_size* rows to avoid generating a
        massive WAL file that could fill the disk.  Returns the total
        number of rows deleted across all batches.
        """
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
        total_deleted = 0

        while True:
            conn = self._connect()
            try:
                cursor = conn.execute(
                    "DELETE FROM hunt_events WHERE rowid IN "
                    "(SELECT rowid FROM hunt_events "
                    " WHERE collected_at < ? LIMIT ?)",
                    (cutoff, batch_size),
                )
                conn.commit()
                deleted = cursor.rowcount
            finally:
                conn.close()

            if deleted == 0:
                break
            total_deleted += deleted

        return total_deleted

    def full_reset(self) -> dict:
        """Wipe ALL data by renaming the old DB file and creating a fresh one.

        This is instant regardless of database size — no slow DELETE or
        VACUUM operations.  The old DB file is kept as a timestamped
        backup (``artemis.db.bak.YYYYMMDD_HHMMSS``) in case recovery is
        needed; it can be deleted manually to reclaim disk space.
        """
        import os
        import shutil

        old_path = self.db_path
        backup_name = f"{old_path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        old_size = 0

        try:
            old_size = os.path.getsize(old_path)
        except OSError:
            pass

        # Rename the old DB (and WAL/SHM files if present)
        for suffix in ('', '-wal', '-shm'):
            src = f"{old_path}{suffix}"
            dst = f"{backup_name}{suffix}"
            try:
                if os.path.exists(src):
                    shutil.move(src, dst)
            except OSError as e:
                logger.warning(f"Could not move {src} → {dst}: {e}")

        logger.info(
            f"Factory reset: renamed {old_path} → {backup_name} "
            f"({old_size / 1_048_576:.0f} MB)"
        )

        # Recreate a fresh empty database with the full schema
        self.init_db()

        return {
            'events_deleted': -1,       # -1 signals "entire DB replaced"
            'findings_deleted': -1,
            'syntheses_deleted': -1,
            'queue_deleted': -1,
            'cases_deleted': -1,
            'enrichment_deleted': -1,
            'backup_file': backup_name,
            'old_size_mb': round(old_size / 1_048_576, 1),
        }

    # ------------------------------------------------------------------
    # Agent activity log (cross-process)
    # ------------------------------------------------------------------

    def log_agent_activity(self, agent: str, activity: str, detail: dict):
        """Persist an agent activity event (safe to call from subprocesses)."""
        def _do(conn):
            conn.execute(
                "INSERT INTO agent_activity (agent, activity, detail, created_at) "
                "VALUES (?, ?, ?, ?)",
                (agent, activity, _dumps(detail),
                 datetime.now().isoformat()),
            )
        self._exec_with_retry(_do)

    def get_agent_activity(self, since_id: int = 0, limit: int = 200) -> List[Dict]:
        """Return agent activity events after *since_id*."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, agent, activity, detail, created_at "
                "FROM agent_activity WHERE id > ? "
                "ORDER BY id ASC LIMIT ?",
                (since_id, limit),
            ).fetchall()
            return [
                {
                    'id': r[0],
                    'agent': r[1],
                    'activity': r[2],
                    'detail': json.loads(r[3]) if r[3] else {},
                    'timestamp': r[4],
                }
                for r in rows
            ]
        finally:
            conn.close()

    def clear_agent_activity(self):
        """Remove all agent activity events."""
        def _do(conn):
            conn.execute("DELETE FROM agent_activity")
        self._exec_with_retry(_do)

    # ------------------------------------------------------------------
    # Analysis queue (decoupled pipeline)
    # ------------------------------------------------------------------

    def queue_analysis(self, cycle: int, event_counts: Dict[str, int] = None):
        """Queue a cycle for agent/LLM analysis."""
        def _do(conn):
            conn.execute(
                "INSERT OR IGNORE INTO analysis_queue "
                "(cycle, status, event_counts, created_at) "
                "VALUES (?, 'pending', ?, ?)",
                (cycle, _dumps(event_counts or {}),
                 datetime.now().isoformat()),
            )
        self._exec_with_retry(_do)

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
        def _do(conn):
            conn.execute(
                "UPDATE analysis_queue SET status = 'in_progress', "
                "started_at = ? WHERE cycle = ?",
                (datetime.now().isoformat(), cycle),
            )
        self._exec_with_retry(_do)

    def mark_analysis_complete(self, cycle: int):
        """Mark a cycle's analysis as complete."""
        def _do(conn):
            conn.execute(
                "UPDATE analysis_queue SET status = 'complete', "
                "completed_at = ? WHERE cycle = ?",
                (datetime.now().isoformat(), cycle),
            )
        self._exec_with_retry(_do)

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

