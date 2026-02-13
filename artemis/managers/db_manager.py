"""Database manager for Artemis hunt results and progress tracking."""

import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("artemis.db")


class DatabaseManager:
    """Manages hunt results database."""

    def __init__(self, db_path: str = "artemis.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

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
                fingerprint TEXT,
                timestamp TIMESTAMP,
                FOREIGN KEY (hunt_id) REFERENCES hunts(hunt_id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
            ON findings(fingerprint)
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plugin_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_name TEXT,
                timestamp TIMESTAMP,
                result_type TEXT,
                result_data TEXT
            )
        """)

        # Hunt progress table — written by subprocess, polled by web server.
        # Replaces the old multiprocessing.Queue approach so hunts survive
        # server restarts.
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

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Hunt progress (written by subprocess, polled by server)
    # ------------------------------------------------------------------

    def write_progress(self, hunt_id: str, pid: int, stage: str,
                       message: str, progress: int, data: dict = None):
        """Write hunt progress from the subprocess."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO hunt_progress
                    (hunt_id, pid, stage, message, progress, data, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                hunt_id, pid, stage, message, progress,
                json.dumps(data) if data else None,
                datetime.now().isoformat(),
            ))
            conn.commit()
        finally:
            conn.close()

    def read_progress(self, hunt_id: str) -> dict | None:
        """Read current progress for a hunt."""
        conn = sqlite3.connect(self.db_path)
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
        """Get progress rows for all hunts that haven't reached a terminal state."""
        conn = sqlite3.connect(self.db_path)
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
        """Remove progress row after hunt completes."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM hunt_progress WHERE hunt_id = ?", (hunt_id,))
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Finding fingerprint
    # ------------------------------------------------------------------

    def _compute_finding_fingerprint(self, agent_name: str, finding: Dict) -> str:
        import hashlib
        title = finding.get('title') or finding.get('activity_type') or 'Unknown'
        indicators = sorted(finding.get('indicators', []))
        assets = sorted(finding.get('affected_assets', []))
        techniques = sorted(finding.get('mitre_techniques', []))
        parts = [
            title,
            "|".join(indicators),
            "|".join(assets),
            "|".join(techniques),
        ]
        raw = "::".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Hunt CRUD
    # ------------------------------------------------------------------

    def save_hunt(self, hunt_id: str, hunt_data: Dict):
        """Save hunt results to database, deduplicating findings by fingerprint."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
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

            cursor.execute("""
                SELECT fingerprint FROM findings
                WHERE fingerprint IS NOT NULL
                  AND timestamp >= datetime('now', '-24 hours')
            """)
            recent_fingerprints = {row[0] for row in cursor.fetchall()}

            inserted = 0
            skipped = 0
            for agent_name, agent_result in hunt_data.get('agent_results', {}).items():
                agent_severity = agent_result.get('severity', 'low')
                agent_confidence = agent_result.get('confidence', 0.0)
                agent_tactics = agent_result.get('mitre_tactics', [])

                for finding in agent_result.get('findings', []):
                    fp = (finding.get('fingerprint')
                          or self._compute_finding_fingerprint(agent_name, finding))

                    if fp in recent_fingerprints:
                        skipped += 1
                        continue

                    title = (finding.get('title')
                             or finding.get('activity_type')
                             or 'Unknown')
                    cursor.execute("""
                        INSERT INTO findings
                        (hunt_id, agent_name, title, description, severity,
                         confidence, mitre_tactics, mitre_techniques,
                         affected_assets, fingerprint, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        fp,
                        datetime.now()
                    ))
                    recent_fingerprints.add(fp)
                    inserted += 1

            if skipped > 0:
                logger.info(
                    f"Finding dedup: inserted {inserted}, skipped {skipped} duplicates"
                )

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

    def get_hunt_details(self, hunt_id: str) -> Dict | None:
        """Get detailed hunt results including findings."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

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
