"""Artemis manager singletons.

Importing from this package gives every module the *same* instances,
regardless of which file imports them.  The objects are created lazily
on first access so import order doesn't matter.
"""

from artemis.managers.db_manager import DatabaseManager
from artemis.managers.plugin_manager import PluginManager
from artemis.managers.hunt_manager import HuntManager

__all__ = [
    "db_manager",
    "hunt_manager",
    "plugin_manager",
]

# ── singletons (created once, shared everywhere) ──────────────────────
db_manager = DatabaseManager()
hunt_manager = HuntManager(db_manager)
plugin_manager = PluginManager()
