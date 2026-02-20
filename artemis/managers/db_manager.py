"""Database manager for Artemis network mapping and progress tracking."""

import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("artemis.db")


class DatabaseManager:
    """Manages Artemis database for network mapping, profiling, and enrichment."""

    def __init__(self, db_path: str = "artemis.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
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

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # LAN groups
    # ------------------------------------------------------------------

    def create_lan_group(self, name: str, description: str = '',
                         color: str = '#667eea',
                         member_ids: List[str] = None) -> Dict:
        """Create a new LAN group with optional initial members."""
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM device_flags WHERE node_id = ?", (node_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def get_device_flags(self) -> Dict[str, Dict]:
        """Get all device flags as a dict keyed by node_id."""
        conn = sqlite3.connect(self.db_path)
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
        """Read current progress for a job."""
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
        """Get progress rows for all jobs that haven't reached a terminal state."""
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
        """Remove progress row after job completes."""
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO enrichment_results "
                "(ip, verdict, sources, enriched_at) VALUES (?, ?, ?, ?)",
                (ip, verdict, json.dumps(sources), datetime.now().isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

    def get_enrichment(self, ip: str) -> Dict | None:
        """Get enrichment result for an IP."""
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM enrichment_queue"
            ).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

    def get_all_enrichments(self) -> List[Dict]:
        """Get all enrichment results."""
        conn = sqlite3.connect(self.db_path)
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

