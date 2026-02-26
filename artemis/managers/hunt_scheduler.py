"""
Autonomous hunt scheduler for Artemis.

Runs threat hunts on a configurable cadence (default: 15 minutes) using
APScheduler.  Prevents overlapping hunts, tracks state in the database,
and feeds results through the case generation pipeline.
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Optional

logger = logging.getLogger("artemis.hunt_scheduler")

# Global reference so API routes can access the running scheduler
_global_scheduler: Optional['HuntScheduler'] = None


class HuntScheduler:
    """Manages autonomous hunt scheduling with overlap prevention.

    Usage::

        scheduler = HuntScheduler(hunt_manager, db_manager, coordinator)
        await scheduler.start()   # begins 15-min cadence
        await scheduler.stop()    # graceful shutdown
    """

    def __init__(
        self,
        hunt_manager,
        db_manager,
        coordinator=None,
        interval_minutes: int = 15,
        auto_start: bool = False,
    ):
        self.hunt_manager = hunt_manager
        self.db = db_manager
        self.coordinator = coordinator
        self.interval_minutes = interval_minutes
        self.auto_start = auto_start
        self._scheduler = None
        self._running = False
        self._hunt_in_progress = False

    async def start(self):
        """Start the autonomous hunt schedule."""
        global _global_scheduler

        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
        except ImportError:
            logger.error(
                "apscheduler not installed — scheduler disabled. "
                "Install with: pip install apscheduler"
            )
            return

        if self._running:
            logger.warning("Scheduler already running")
            return

        self._scheduler = AsyncIOScheduler()
        self._scheduler.add_job(
            self._execute_hunt_cycle,
            'interval',
            minutes=self.interval_minutes,
            id='autonomous_hunt',
            max_instances=1,
            coalesce=True,
            next_run_time=datetime.now(),  # run immediately on start
        )
        self._scheduler.start()
        self._running = True
        _global_scheduler = self

        self.db.update_scheduler_state(
            status="running",
            next_run_at=datetime.now().isoformat(),
        )
        logger.info(
            f"Hunt scheduler started — running every {self.interval_minutes} minutes"
        )

    async def stop(self):
        """Gracefully stop the scheduler."""
        global _global_scheduler

        if self._scheduler and self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False
            _global_scheduler = None
            self.db.update_scheduler_state(status="stopped")
            logger.info("Hunt scheduler stopped")

    def update_interval(self, minutes: int):
        """Change the hunt interval (takes effect next cycle)."""
        self.interval_minutes = minutes
        if self._scheduler and self._running:
            self._scheduler.reschedule_job(
                'autonomous_hunt',
                trigger='interval',
                minutes=minutes,
            )
            logger.info(f"Hunt interval updated to {minutes} minutes")

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Hunt execution
    # ------------------------------------------------------------------

    async def _execute_hunt_cycle(self):
        """Execute one autonomous hunt cycle.

        This is called by APScheduler on each tick.  It:
        1. Collects data via the existing hunt pipeline
        2. Runs the coordinator's hunt() method
        3. Auto-generates cases (via coordinator Stage 8)
        4. Updates scheduler stats
        """
        if self._hunt_in_progress:
            logger.info("Hunt already in progress — skipping this cycle")
            return

        self._hunt_in_progress = True
        cycle_start = datetime.now()
        hunt_result = "success"

        try:
            logger.info("=" * 60)
            logger.info("Autonomous hunt cycle starting")

            # Use the existing hunt_manager infrastructure
            # The hunt_manager.run_hunt_subprocess handles:
            #   - Splunk data collection
            #   - Coordinator.hunt() execution
            #   - Finding storage
            #   - LLM synthesis
            # We trigger it the same way the API does for continuous hunts.
            await self._run_hunt()

            logger.info("Autonomous hunt cycle completed successfully")

        except Exception as e:
            hunt_result = f"error: {e}"
            logger.error(f"Autonomous hunt cycle failed: {e}")

        finally:
            self._hunt_in_progress = False
            # Update scheduler state
            state = self.db.get_scheduler_state() or {}
            total_hunts = (state.get("total_hunts") or 0) + 1
            self.db.update_scheduler_state(
                last_run_at=cycle_start.isoformat(),
                last_run_result=hunt_result,
                total_hunts=total_hunts,
            )

    async def _run_hunt(self):
        """Run a hunt using the existing hunt manager infrastructure.

        The hunt manager runs hunts in subprocesses; we use the same
        mechanism as the continuous-hunt API but trigger just a single
        cycle.
        """
        # Import here to avoid circular imports at module load time
        from artemis.managers.hunt_manager import (
            _read_splunk_credentials,
            _run_hunt_cycle,
        )

        host, token, username, password = _read_splunk_credentials()
        if not host:
            logger.warning("No Splunk host configured — cannot run autonomous hunt")
            return

        # Run a single hunt cycle in the event loop's executor
        # to avoid blocking the async scheduler
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            _run_hunt_cycle,
            host, token, username, password,
            "-20m",   # lookback window (matches 15-min interval + 5min overlap)
            "ADAPTIVE",
            self.db.db_path,
            None,     # target_hosts
        )
