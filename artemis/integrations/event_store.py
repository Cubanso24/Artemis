"""SQLite-backed event store for large hunting data collections.

When a hunt pulls millions of events from Splunk, keeping them all in
Python lists can exhaust RAM.  ``SqliteEventStore`` provides the same
``Dict[str, List[Dict]]`` interface that the rest of the codebase
expects, but spills events to a temporary SQLite file so only one
data-type's worth of events needs to be in memory at a time.
"""

import json
import os
import sqlite3
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple


class SqliteEventStore:
    """Dict-like container that stores event lists in a SQLite file.

    Usage::

        store = SqliteEventStore()
        store.extend("network_connections", [{"src": "1.2.3.4", ...}, ...])
        for event in store["network_connections"]:
            ...
        store.close()  # deletes the temp file
    """

    def __init__(self, path: Optional[str] = None):
        if path:
            self._path = path
            self._delete_on_close = False
        else:
            fd, self._path = tempfile.mkstemp(
                suffix=".db", prefix="artemis_events_"
            )
            os.close(fd)
            self._delete_on_close = True

        self._conn = sqlite3.connect(self._path)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                data_type TEXT NOT NULL,
                event_json TEXT NOT NULL
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(data_type)"
        )
        self._conn.commit()
        self._counts: Dict[str, int] = {}

    # -- dict-like interface -----------------------------------------------

    def __getitem__(self, key: str) -> List[Dict]:
        """Materialize all events for *key* into a Python list."""
        rows = self._conn.execute(
            "SELECT event_json FROM events WHERE data_type = ?", (key,)
        ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def __contains__(self, key: str) -> bool:
        return key in self._counts

    def __len__(self) -> int:
        return len(self._counts)

    def get(self, key: str, default=None):
        if key in self._counts:
            return self[key]
        return default

    def keys(self) -> list:
        return list(self._counts.keys())

    def values(self) -> Iterator[List[Dict]]:
        for key in self._counts:
            yield self[key]

    def items(self) -> Iterator[Tuple[str, List[Dict]]]:
        for key in self._counts:
            yield key, self[key]

    def update(self, other: dict):
        """Bulk-load from a plain dict (e.g. from a Splunk window)."""
        for key, events in other.items():
            if isinstance(events, list):
                self.extend(key, events)

    # -- write helpers -----------------------------------------------------

    def extend(self, key: str, events: List[Dict]):
        """Append *events* under *key* (bulk insert)."""
        if not events:
            self._counts.setdefault(key, 0)
            return
        self._conn.executemany(
            "INSERT INTO events (data_type, event_json) VALUES (?, ?)",
            [(key, json.dumps(e)) for e in events],
        )
        self._conn.commit()
        self._counts[key] = self._counts.get(key, 0) + len(events)

    # -- count helpers (avoid materializing) --------------------------------

    def count(self, key: str) -> int:
        """Event count for *key* without loading into RAM."""
        return self._counts.get(key, 0)

    def total_count(self) -> int:
        return sum(self._counts.values())

    def counts_by_type(self) -> Dict[str, int]:
        return dict(self._counts)

    # -- lifecycle ---------------------------------------------------------

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass
        if self._delete_on_close:
            try:
                os.unlink(self._path)
            except OSError:
                pass

    def __del__(self):
        self.close()
