"""Hunt execution manager.

Key design decisions that differ from the original monolith:

1. Hunt subprocesses use ``daemon=False`` so they keep running even if
   the web server restarts (uvicorn reload, code change, etc.).
2. Progress is communicated through SQLite (``hunt_progress`` table)
   instead of ``multiprocessing.Queue``, so no data is lost on restart.
3. The server polls the progress table and broadcasts to WebSocket
   clients.  On startup it detects hunts that were already running
   and resumes monitoring them.
"""

import os
import asyncio
import logging
import signal
from datetime import datetime
from typing import Optional

from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig

logger = logging.getLogger("artemis.hunt")


# ---------------------------------------------------------------------------
# Hunt worker — runs in its own process
# ---------------------------------------------------------------------------

def _hunt_worker_process(hunt_id, time_range, mode, description, db_path,
                         storage_mode="ram", earliest_time=None,
                         latest_time=None):
    """
    Run a complete hunt in a separate process.

    Creates its own Splunk pipeline, coordinator, and plugins so the main
    web server process stays entirely free for HTTP requests.  All progress
    is written to the ``hunt_progress`` table in SQLite.

    Args:
        storage_mode: "ram" keeps collected logs in memory (fast, default).
                      "sqlite" spills them to a temporary SQLite database so
                      very large collections don't exhaust RAM.
    """
    import os, json, logging, traceback
    from datetime import datetime
    from artemis.meta_learner.coordinator import MetaLearnerCoordinator
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
    from artemis.managers.db_manager import DatabaseManager

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.hunt_worker')

    db = DatabaseManager(db_path)
    pid = os.getpid()

    def send(stage, message, progress, extra=None):
        try:
            db.write_progress(hunt_id, pid, stage, message, progress, extra)
        except Exception:
            pass

    try:
        hunt_start = datetime.now()
        send('init', 'Initializing hunt process...', 5)

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
        time_label = (f"{earliest_time} → {latest_time}"
                      if earliest_time and latest_time else time_range)
        send('collect', 'Starting data collection from Splunk...', 10, {
            'started_at': hunt_start.isoformat(),
            'time_range': time_label,
            'queries_done': 0, 'queries_total': 9,
            'events_by_type': {}, 'total_events': 0,
            'window': 0, 'total_windows': 0,
        })

        # Tracks the running total of events *across* all windows.
        # Per-window query counts overwrite the same keys in window_stats,
        # so we snapshot the cumulative totals at each window boundary.
        cumulative_by_type = {}   # query_name -> total events across all windows
        window_stats = {}         # query_name -> events in *current* window only
        prev_window = [0]         # mutable so the closure can update it

        def on_collection_progress(info):
            if info.get('type') == 'query_done':
                w = info.get('window', 1)
                # Detect window transition: reset the per-window dict and
                # fold its counts into the cumulative totals.
                if w != prev_window[0]:
                    for k, v in window_stats.items():
                        cumulative_by_type[k] = cumulative_by_type.get(k, 0) + v
                    window_stats.clear()
                    prev_window[0] = w

                window_stats[info['query_name']] = info['query_events']

                # Running total = prior windows + current window
                total_events = (sum(cumulative_by_type.values())
                                + sum(window_stats.values()))

                qd = info['queries_done']
                qt = info['queries_total']
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

                # Merge cumulative + current-window for per-type breakdown
                merged_by_type = dict(cumulative_by_type)
                for k, v in window_stats.items():
                    merged_by_type[k] = merged_by_type.get(k, 0) + v

                send('collect', ' | '.join(parts), min(pct, 60), {
                    'started_at': hunt_start.isoformat(),
                    'time_range': time_label,
                    'queries_done': qd, 'queries_total': qt,
                    'events_by_type': merged_by_type,
                    'total_events': total_events,
                    'window': w, 'total_windows': tw,
                    'elapsed_seconds': elapsed,
                    'last_query': info['query_name'],
                })
            elif info.get('type') == 'window_done':
                # The pipeline already computed the true running_total
                total = info.get('running_total', 0)
                w = info.get('window', 1)
                tw = info.get('total_windows', 1)
                elapsed = (datetime.now() - hunt_start).total_seconds()
                send('collect',
                     f'Window {w}/{tw} done | {total:,} total events | {elapsed:.0f}s elapsed',
                     10 + int((w / tw) * 50), {
                         'started_at': hunt_start.isoformat(),
                         'time_range': time_label,
                         'queries_done': 9, 'queries_total': 9,
                         'events_by_type': info.get('events_by_type', {}),
                         'total_events': total,
                         'window': w, 'total_windows': tw,
                         'elapsed_seconds': elapsed,
                     })

        hunting_data = pipeline.collect_hunting_data(
            time_range, progress_callback=on_collection_progress,
            storage_mode=storage_mode,
            earliest_time=earliest_time,
            latest_time=latest_time,
        )
        if hasattr(hunting_data, 'total_count'):
            total_events = hunting_data.total_count()
            events_by_type = hunting_data.counts_by_type()
        else:
            total_events = sum(len(v) for v in hunting_data.values() if isinstance(v, list))
            events_by_type = {k: len(v) for k, v in hunting_data.items() if isinstance(v, list)}
        collect_elapsed = (datetime.now() - hunt_start).total_seconds()
        log.info(f'Data collection done: {total_events} events in {collect_elapsed:.0f}s')
        send('analyze',
             f'Collected {total_events:,} events in {collect_elapsed:.0f}s. Running hunting agents...',
             65, {
                 'total_events': total_events,
                 'events_by_type': events_by_type,
                 'elapsed_seconds': collect_elapsed,
                 'phase': 'complete',
             })

        # --- hunt analysis -------------------------------------------------
        send('hunt', 'Running hunting agents...', 70)
        hunt_result = coordinator.hunt(hunting_data, None, None)
        send('finalize', 'Finalizing results...', 90)

        findings_count = hunt_result.get('total_findings', 0)
        hunt_data = {
            'start_time': hunt_start.isoformat(),
            'end_time': datetime.now().isoformat(),
            'time_range': time_label,
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
        send('finalize', 'Running network mapper...', 91)
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
            log.info(f'Network mapper: {len(nm.nodes)} nodes saved to disk')
        except Exception as e:
            log.warning(f'Network mapper failed: {e}')

        send('finalize', 'Running Sigma rule engine...', 93)
        try:
            from artemis.plugins.sigma_engine import SigmaEnginePlugin
            se = SigmaEnginePlugin({})
            se.initialize()
            sigma_result = se.execute(**hunting_data)
            sigma_matches = sigma_result.get('matches', [])
            if sigma_matches:
                log.info(
                    f"Sigma engine: {sigma_result['total_matches']} matches "
                    f"across {len(sigma_matches)} rules"
                )
                sigma_findings = []
                max_sev = 'low'
                sev_rank = {
                    'critical': 4, 'high': 3, 'medium': 2,
                    'low': 1, 'informational': 0,
                }
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
        send('finalize', 'Saving hunt results...', 98)
        db.save_hunt(hunt_id, hunt_data)

        send('complete',
             f'Hunt complete! Found {findings_count} potential threats.', 100,
             {'hunt_id': hunt_id})

    except Exception as e:
        log.error(f'Hunt {hunt_id} failed: {e}')
        import traceback
        log.error(traceback.format_exc())
        send('error', f'Hunt failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc(), 'hunt_id': hunt_id})


# ---------------------------------------------------------------------------
# Profile worker — runs in its own process (like hunts)
# ---------------------------------------------------------------------------

def _profile_worker_process(profile_id, time_range, db_path):
    """Run device profiling in a subprocess so it survives page reloads."""
    import os, logging, traceback, json
    from datetime import datetime
    from artemis.managers.db_manager import DatabaseManager
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
    from artemis.plugins.network_mapper import NetworkMapperPlugin

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.profile_worker')

    db = DatabaseManager(db_path)
    pid = os.getpid()

    def send(stage, message, progress, extra=None):
        try:
            db.write_progress(profile_id, pid, stage, message, progress, extra)
        except Exception:
            pass

    try:
        send('init', 'Initializing profiler...', 5)

        # Build Splunk connector
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
        splunk = pipeline.splunk

        send('collect', 'Running Splunk queries (conn, NTLM, Kerberos, DHCP, SNMP, SMB, SSH, software)...', 15)

        # Load the network mapper plugin (reads existing map from disk)
        nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
        nm.initialize()

        send('collect', 'Querying Splunk — this may take a minute...', 25)

        # Run the actual profiling (blocking — all queries + classification)
        result = nm.profile_devices(splunk, time_range=time_range)

        send('complete',
             f"Profiled {result.get('classified', 0)} / {result.get('total_internal', 0)} devices. "
             f"{result.get('unclassified', 0)} unclassified.",
             100, result)

    except Exception as e:
        log.error(f'Profile {profile_id} failed: {e}')
        log.error(traceback.format_exc())
        send('error', f'Profiling failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc()})


# ---------------------------------------------------------------------------
# HuntManager — lives in the web server process
# ---------------------------------------------------------------------------

class HuntManager:
    """Manages hunt execution and state.

    Hunts run in non-daemon subprocesses and write progress to SQLite.
    The manager polls the DB and broadcasts updates to WebSocket clients.
    Supports up to ``max_concurrent`` hunts running simultaneously; extras
    are placed in a FIFO queue and auto-launched when a slot opens.
    """

    MAX_CONCURRENT = 2  # how many hunts can run at the same time

    def __init__(self, db_manager):
        self.db = db_manager
        self.active_hunts: dict = {}          # hunt_id -> state dict
        self._monitored_hunts: dict = {}      # hunt_id -> pid
        self._poll_task: Optional[asyncio.Task] = None
        self._splunk = None

        # Hunt queue: list of dicts with hunt params, FIFO order
        self._queue: list = []  # [{'hunt_id': ..., 'time_range': ..., ...}, ...]

        # Continuous hunting state
        self._continuous_task = None
        self._continuous_stop = False
        self._continuous_config = {
            'interval_minutes': 0,
            'lookback_minutes': 0,
            'mode': '',
            'started_at': None,
            'cycles': 0,
            'last_hunt_id': None,
        }

    # WebSocket broadcast callback — set by the app at startup
    _broadcast_fn = None

    def get_splunk_connector(self):
        """Get a Splunk connector for API use (e.g. device profiling)."""
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

    # ------------------------------------------------------------------
    # Running-hunt count
    # ------------------------------------------------------------------

    def _running_count(self) -> int:
        """Return the number of hunts currently executing."""
        return sum(
            1 for s in self.active_hunts.values()
            if s.get('status') == 'running'
        )

    # ------------------------------------------------------------------
    # Launch / queue a hunt
    # ------------------------------------------------------------------

    async def execute_hunt(
        self,
        hunt_id: str,
        time_range: str,
        mode: str,
        description: str,
        storage_mode: str = "ram",
        earliest_time: str = None,
        latest_time: str = None,
    ):
        """Launch a hunt immediately if a slot is free, else queue it."""
        params = dict(
            hunt_id=hunt_id,
            time_range=time_range,
            mode=mode,
            description=description,
            storage_mode=storage_mode,
            earliest_time=earliest_time,
            latest_time=latest_time,
        )

        if self._running_count() < self.MAX_CONCURRENT:
            await self._launch_hunt(params)
        else:
            self._queue.append(params)
            self.active_hunts[hunt_id] = {
                'status': 'queued',
                'progress': 0,
                'start_time': None,
                'collection_stats': {},
                'last_progress': None,
                'queue_position': len(self._queue),
            }
            logger.info(
                f'Hunt {hunt_id} queued (position {len(self._queue)}, '
                f'{self._running_count()} running)'
            )
            # Broadcast queue state so the UI updates immediately
            if self._broadcast_fn:
                await self._broadcast_fn({
                    'hunt_id': hunt_id,
                    'stage': 'queued',
                    'message': f'Queued — position {len(self._queue)}',
                    'progress': 0,
                })

    async def _launch_hunt(self, params: dict):
        """Actually spawn the subprocess for a hunt."""
        import multiprocessing

        hunt_id = params['hunt_id']

        self.active_hunts[hunt_id] = {
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now(),
            'collection_stats': {},
            'last_progress': None,
        }

        proc = multiprocessing.Process(
            target=_hunt_worker_process,
            args=(
                hunt_id,
                params['time_range'],
                params['mode'],
                params['description'],
                self.db.db_path,
                params['storage_mode'],
                params['earliest_time'],
                params['latest_time'],
            ),
            daemon=False,
        )
        proc.start()
        self._monitored_hunts[hunt_id] = proc.pid
        logger.info(f'Hunt {hunt_id} started in subprocess (pid {proc.pid})')

        self._ensure_poll_task()

    async def _drain_queue(self):
        """Launch queued hunts until all slots are filled or queue is empty."""
        while self._queue and self._running_count() < self.MAX_CONCURRENT:
            params = self._queue.pop(0)
            hunt_id = params['hunt_id']
            logger.info(
                f'Dequeuing hunt {hunt_id} '
                f'({len(self._queue)} still queued)'
            )
            await self._launch_hunt(params)
        # Update queue positions for remaining entries
        for idx, params in enumerate(self._queue, 1):
            hid = params['hunt_id']
            if hid in self.active_hunts:
                self.active_hunts[hid]['queue_position'] = idx

    # ------------------------------------------------------------------
    # Queue management helpers
    # ------------------------------------------------------------------

    def get_queue(self) -> list:
        """Return the current queue in FIFO order."""
        return [
            {
                'hunt_id': p['hunt_id'],
                'position': idx,
                'time_range': p.get('time_range', ''),
                'mode': p.get('mode', ''),
                'description': p.get('description', ''),
            }
            for idx, p in enumerate(self._queue, 1)
        ]

    def remove_from_queue(self, hunt_id: str) -> bool:
        """Remove a queued hunt by ID.  Returns True if found."""
        for i, p in enumerate(self._queue):
            if p['hunt_id'] == hunt_id:
                self._queue.pop(i)
                self.active_hunts.pop(hunt_id, None)
                # Re-index remaining positions
                for idx, pp in enumerate(self._queue, 1):
                    hid = pp['hunt_id']
                    if hid in self.active_hunts:
                        self.active_hunts[hid]['queue_position'] = idx
                logger.info(f'Removed {hunt_id} from queue')
                return True
        return False

    # ------------------------------------------------------------------
    # Device profiling (subprocess-based, survives page reload)
    # ------------------------------------------------------------------

    _profile_id: Optional[str] = None
    _profile_pid: Optional[int] = None

    async def start_profile(self, time_range: str) -> str:
        """Launch device profiling in a subprocess and monitor via poll loop."""
        import multiprocessing

        if self._profile_id and self._profile_pid and _pid_alive(self._profile_pid):
            raise RuntimeError(
                f"Profiling already running ({self._profile_id})"
            )

        profile_id = f"profile_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        proc = multiprocessing.Process(
            target=_profile_worker_process,
            args=(profile_id, time_range, self.db.db_path),
            daemon=False,
        )
        proc.start()

        self._profile_id = profile_id
        self._profile_pid = proc.pid
        self._monitored_hunts[profile_id] = proc.pid
        self.active_hunts[profile_id] = {
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now(),
            'collection_stats': {},
            'last_progress': None,
        }
        logger.info(
            f'Profile {profile_id} started (pid {proc.pid}, '
            f'time_range={time_range})'
        )
        self._ensure_poll_task()
        return profile_id

    def get_profile_status(self) -> dict:
        """Return the current profiling state for the UI."""
        pid = self._profile_id
        if not pid:
            return {'running': False}

        # Check active_hunts for status
        state = self.active_hunts.get(pid, {})
        status = state.get('status', 'unknown')
        if status not in ('running',) and not (
            self._profile_pid and _pid_alive(self._profile_pid)
        ):
            return {'running': False, 'last_profile_id': pid}

        row = state.get('last_progress') or {}
        return {
            'running': True,
            'profile_id': pid,
            'progress': state.get('progress', 0),
            'stage': row.get('stage', 'init'),
            'message': row.get('message', 'Running...'),
        }

    # ------------------------------------------------------------------
    # Progress polling loop
    # ------------------------------------------------------------------

    def _ensure_poll_task(self):
        """Start the progress-polling background task if it isn't running."""
        if self._poll_task is None or self._poll_task.done():
            self._poll_task = asyncio.ensure_future(self._poll_progress())

    async def _poll_progress(self):
        """Poll hunt_progress table and broadcast updates to WebSocket clients."""
        from artemis.managers import plugin_manager

        try:
            while self._monitored_hunts:
                finished = []

                for hunt_id, pid in list(self._monitored_hunts.items()):
                    row = self.db.read_progress(hunt_id)
                    if not row:
                        await asyncio.sleep(0.1)
                        continue

                    # Update local tracking
                    if hunt_id in self.active_hunts:
                        self.active_hunts[hunt_id]['last_progress'] = row
                        self.active_hunts[hunt_id]['progress'] = row.get('progress', 0)

                    # Broadcast to WebSocket clients
                    if self._broadcast_fn:
                        is_profile = hunt_id.startswith('profile_')
                        msg = {
                            'type': 'profile_progress' if is_profile else 'hunt_progress',
                            'stage': row['stage'],
                            'message': row['message'],
                            'progress': row['progress'],
                            'hunt_id': hunt_id,
                        }
                        if row.get('data'):
                            if is_profile:
                                msg['result'] = row['data']
                            elif 'collection' not in msg:
                                msg['collection'] = row['data']
                        await self._broadcast_fn(msg)

                    # Terminal states
                    if row['stage'] in ('complete', 'error'):
                        status = 'completed' if row['stage'] == 'complete' else 'failed'
                        if hunt_id in self.active_hunts:
                            self.active_hunts[hunt_id]['status'] = status
                        self.db.clear_progress(hunt_id)
                        plugin_manager.reload_from_disk(
                            ['network_mapper', 'sigma_engine']
                        )
                        # Clear profile tracking if this was a profile job
                        if hunt_id == self._profile_id:
                            self._profile_pid = None
                        finished.append(hunt_id)
                    elif not _pid_alive(pid):
                        # Process died without writing terminal state
                        logger.warning(
                            f'Hunt {hunt_id} subprocess (pid {pid}) '
                            f'exited without completing'
                        )
                        if hunt_id in self.active_hunts:
                            self.active_hunts[hunt_id]['status'] = 'failed'
                        self.db.clear_progress(hunt_id)
                        finished.append(hunt_id)

                for hid in finished:
                    self._monitored_hunts.pop(hid, None)

                # When a slot opens, launch the next queued hunt(s)
                if finished:
                    await self._drain_queue()

                await asyncio.sleep(0.5)

                # Keep polling while there are queued hunts even if
                # nothing is currently monitored (queue drain just
                # added new entries to _monitored_hunts).
                if not self._monitored_hunts and not self._queue:
                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f'Progress polling error: {e}')

    # ------------------------------------------------------------------
    # Reconnect to hunts that survived a server restart
    # ------------------------------------------------------------------

    def reconnect_running_hunts(self):
        """Called at startup.  Finds hunts that are still running from
        before a server restart and resumes monitoring them."""
        rows = self.db.get_all_running_progress()
        reconnected = 0

        for row in rows:
            hunt_id = row['hunt_id']
            pid = row['pid']

            if _pid_alive(pid):
                logger.info(
                    f'Reconnecting to running {"profile" if hunt_id.startswith("profile_") else "hunt"} '
                    f'{hunt_id} (pid {pid})'
                )
                self._monitored_hunts[hunt_id] = pid
                self.active_hunts[hunt_id] = {
                    'status': 'running',
                    'progress': row.get('progress', 0),
                    'start_time': row.get('updated_at', datetime.now()),
                    'collection_stats': {},
                    'last_progress': row,
                }
                # Restore profile tracking
                if hunt_id.startswith('profile_'):
                    self._profile_id = hunt_id
                    self._profile_pid = pid
                reconnected += 1
            else:
                logger.warning(
                    f'Hunt {hunt_id} subprocess (pid {pid}) is no longer '
                    f'alive — marking as failed'
                )
                self.db.clear_progress(hunt_id)

        if reconnected:
            logger.info(f'Reconnected to {reconnected} running hunt(s)')
            self._ensure_poll_task()

    # ------------------------------------------------------------------
    # Continuous hunting
    # ------------------------------------------------------------------

    def start_continuous(self, interval_minutes, lookback_minutes, mode,
                         progress_callback=None):
        if self._continuous_task and not self._continuous_task.done():
            raise RuntimeError("Continuous hunting is already running")

        self._continuous_stop = False
        self._continuous_config = {
            'interval_minutes': interval_minutes,
            'lookback_minutes': lookback_minutes,
            'mode': mode,
            'started_at': datetime.now().isoformat(),
            'cycles': 0,
            'last_hunt_id': None,
        }
        self._continuous_task = asyncio.ensure_future(
            self._continuous_loop(interval_minutes, lookback_minutes, mode)
        )
        logger.info(
            f"Continuous hunting started: interval={interval_minutes}m, "
            f"lookback={lookback_minutes}m"
        )

    def stop_continuous(self):
        if not self._continuous_task or self._continuous_task.done():
            raise RuntimeError("Continuous hunting is not running")
        self._continuous_stop = True
        logger.info("Continuous hunting stop requested")

    def get_continuous_status(self):
        running = (self._continuous_task is not None
                   and not self._continuous_task.done())
        return {
            'running': running,
            'stopping': running and self._continuous_stop,
            **self._continuous_config,
        }

    async def _continuous_loop(self, interval, lookback, mode):
        try:
            while not self._continuous_stop:
                hunt_id = f"hunt_cont_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                time_range = f"-{lookback}m"
                desc = f"Continuous hunt (every {interval}m, lookback {lookback}m)"

                logger.info(f"Continuous cycle: starting {hunt_id}")
                try:
                    await self.execute_hunt(hunt_id, time_range, mode, desc)
                    # Wait for this hunt to finish before starting the next
                    while hunt_id in self._monitored_hunts:
                        if self._continuous_stop:
                            break
                        await asyncio.sleep(1)
                except Exception as e:
                    logger.error(f"Continuous hunt cycle failed: {e}")

                self._continuous_config['cycles'] += 1
                self._continuous_config['last_hunt_id'] = hunt_id
                self._continuous_config['last_cycle'] = datetime.now().isoformat()

                if self._continuous_stop:
                    break

                for _ in range(interval * 60):
                    if self._continuous_stop:
                        break
                    await asyncio.sleep(1)
        finally:
            logger.info(
                f"Continuous hunting stopped after "
                f"{self._continuous_config['cycles']} cycles"
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pid_alive(pid: int) -> bool:
    """Check whether a process with the given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False
