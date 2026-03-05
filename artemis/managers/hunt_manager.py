"""Job manager for device profiling.

Key design decisions:

1. Profiling subprocesses use ``daemon=False`` so they keep running even if
   the web server restarts (uvicorn reload, code change, etc.).
2. Progress is communicated through SQLite (``hunt_progress`` table)
   instead of ``multiprocessing.Queue``, so no data is lost on restart.
3. The server polls the progress table and broadcasts to WebSocket
   clients.  On startup it detects jobs that were already running
   and resumes monitoring them.
"""

import os
import asyncio
import logging
import signal
import time as _time
from datetime import datetime
from typing import Optional

from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig

logger = logging.getLogger("artemis.hunt")

# Base directory for resolving config files (.token, etc.)
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read_splunk_credentials():
    """Read Splunk credentials from env vars, falling back to .token file.

    Returns (host, token, username, password).
    """
    host = os.getenv('SPLUNK_HOST', '10.25.11.86')
    token = os.getenv('SPLUNK_TOKEN')
    username = os.getenv('SPLUNK_USERNAME')
    password = os.getenv('SPLUNK_PASSWORD')

    # Fall back to .token file in the project root
    if not token:
        token_path = os.path.join(_BASE_DIR, '.token')
        if os.path.isfile(token_path):
            try:
                with open(token_path, 'r') as f:
                    token = f.read().strip()
                if token:
                    logger.info("Loaded Splunk token from .token file")
            except Exception as e:
                logger.warning(f"Failed to read .token file: {e}")

    return host, token, username, password


def _build_splunk_config():
    """Build a DataSourceConfig with Splunk credentials."""
    host, token, username, password = _read_splunk_credentials()
    return DataSourceConfig(
        splunk_host=host, splunk_port=8089,
        splunk_token=token or '',
        splunk_username=username or '',
        splunk_password=password or '',
    )


# ---------------------------------------------------------------------------
# Profile worker — runs in its own process
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
        except Exception as e:
            log.warning(f"Profile {profile_id}: failed to write progress "
                        f"(stage={stage}, progress={progress}): {e}")

    try:
        send('init', 'Initializing profiler...', 5)

        # Build Splunk connector
        cfg = _build_splunk_config()
        pipeline = DataPipeline(cfg)
        splunk = pipeline.splunk

        send('collect', 'Loading network map from disk...', 15)

        # Load the network mapper plugin (reads existing map from disk)
        nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
        nm.initialize()

        internal_count = sum(1 for n in nm.nodes.values() if n.is_internal)
        if not nm.nodes:
            send('error',
                 'No network map found. Build a network map first, '
                 'then profile devices.', 0,
                 {'error_detail': 'NetworkMapperPlugin loaded 0 nodes from '
                  'network_maps/current_map.json.'})
            return
        if internal_count == 0:
            send('error',
                 f'Network map has {len(nm.nodes)} nodes but none are '
                 f'internal. Nothing to profile.', 0,
                 {'error_detail': f'{len(nm.nodes)} total nodes loaded but '
                  '0 are marked as internal.'})
            return

        send('collect',
             f'Network map: {len(nm.nodes)} nodes ({internal_count} internal). '
             f'Running 10 Splunk queries...', 25)

        # Forward profile_devices progress to the UI
        def on_profile_progress(stage, message, pct):
            send(stage, message, pct)

        # Run the actual profiling (blocking — all queries + classification)
        result = nm.profile_devices(splunk, time_range=time_range,
                                    progress_callback=on_profile_progress)

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
# Background profiling worker — profiles devices one at a time
# ---------------------------------------------------------------------------

def _bg_profile_worker_process(profile_id, time_range, num_workers,
                                db_path):
    """Profile all unprofiled devices in the background.

    Phase 1 — Query: runs the global Splunk queries once (same as
              batch profiling).  This is the slow part.
    Phase 2 — Enrich: indexes results by IP, then fans out enrichment
              + classification across ``num_workers`` threads.
              Each thread processes pure Python — no Splunk calls —
              so this phase finishes in seconds.

    Progress is written to SQLite so the UI can track it.
    """
    import os, logging, traceback, json, time
    from datetime import datetime
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from artemis.managers.db_manager import DatabaseManager
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
    from artemis.plugins.network_mapper import NetworkMapperPlugin
    import threading

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.bg_profile_worker')

    db = DatabaseManager(db_path)
    pid = os.getpid()

    def send(stage, message, progress, extra=None):
        try:
            db.write_progress(profile_id, pid, stage, message, progress, extra)
        except Exception as e:
            log.warning(f"BG Profile {profile_id}: progress write failed: {e}")

    try:
        send('init', 'Starting background profiler...', 0)

        # Build Splunk connector
        cfg = _build_splunk_config()
        pipeline = DataPipeline(cfg)
        splunk = pipeline.splunk

        send('init', 'Loading network map...', 2)

        # Load the network mapper plugin
        nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
        nm.initialize()

        stats = nm.get_profiling_stats()
        total = stats['total']
        already_profiled = stats['profiled']

        if total == 0:
            send('error', 'No devices found. Build a network map first.', 0)
            return

        unprofiled_ips = nm.get_unprofiled_ips()
        if not unprofiled_ips:
            send('complete', f'All {total} devices already profiled.', 100,
                 {'total': total, 'profiled': total, 'newly_profiled': 0})
            return

        num_unprofiled = len(unprofiled_ips)
        log.info(f"BG Profile: {num_unprofiled} devices to profile")

        # ================================================================
        # PHASE 1: Run global Splunk queries (same as batch profiling)
        # ================================================================
        send('querying',
             f'Running global Splunk queries for {num_unprofiled} '
             f'unprofiled devices...',
             5,
             {'total': total, 'profiled': already_profiled,
              'newly_profiled': 0, 'phase': 'querying'})

        windows = nm._generate_profile_windows(time_range, window_hours=24)
        total_windows = len(windows)
        log.info(f"BG Profile: {total_windows} query window(s)")

        # Accumulator for cross-window merging
        accumulated = {
            'server_agg': {}, 'client_agg': {},
            'ntlm': [], 'kerberos': [], 'dhcp': [], 'snmp': [],
            'smb': [], 'software': [], 'ssh': [], 'x509': [],
            'http_ua': [],
            'ja3_ssl': [], 'ja3s_server': [], 'dns_profile': [],
            'rdp': [], 'dhcp_extended': [], 'files': [],
            'x509_extended': [],
            'known_services': [], 'smtp_banner': [], 'ftp_banner': [],
            'dhcp_gateway': [], 'snmp_oid': [],
        }

        for win_idx, (earliest, latest) in enumerate(windows, 1):
            pct = 5 + int(40 * win_idx / total_windows)
            win_label = (f"Window {win_idx}/{total_windows}: {earliest} -> {latest}"
                         if total_windows > 1
                         else "Running 23 Splunk queries in parallel...")
            send('querying', win_label, pct,
                 {'total': total, 'profiled': already_profiled,
                  'newly_profiled': 0, 'phase': 'querying'})

            log.info(f"BG Profile query window {win_idx}/{total_windows}: "
                     f"{earliest} -> {latest}")
            window_results = nm._run_profile_queries(splunk, earliest, latest)
            nm._merge_profile_results(accumulated, window_results)
            log.info(f"Window {win_idx} done — "
                     f"server IPs: {len(accumulated['server_agg'])}, "
                     f"client IPs: {len(accumulated['client_agg'])}")

        # ================================================================
        # PHASE 2: Index results and fan out enrichment
        # ================================================================
        send('profiling',
             f'Queries complete. Indexing results for {num_unprofiled} '
             f'devices...',
             50,
             {'total': total, 'profiled': already_profiled,
              'newly_profiled': 0, 'phase': 'enriching'})

        log.info("BG Profile: indexing results by IP...")
        indexed = nm._index_results_by_ip(accumulated)
        log.info("BG Profile: index built, starting enrichment workers")

        # Shared state for progress tracking
        lock = threading.Lock()
        profiled_count = 0
        failed_count = 0

        # Queue of IPs to process
        ip_queue = list(unprofiled_ips)
        queue_lock = threading.Lock()
        queue_idx = [0]

        def get_next_ip():
            with queue_lock:
                idx = queue_idx[0]
                if idx >= len(ip_queue):
                    return None
                queue_idx[0] = idx + 1
                return ip_queue[idx]

        def worker():
            nonlocal profiled_count, failed_count
            while True:
                ip = get_next_ip()
                if ip is None:
                    break
                try:
                    nm.enrich_device_from_cache(ip, indexed)
                    with lock:
                        profiled_count += 1
                        done = already_profiled + profiled_count
                        # Progress 50-99% for enrichment phase
                        pct = 50 + min(
                            int(49 * profiled_count / num_unprofiled), 49)
                        # Only send progress every 50 devices to avoid
                        # flooding SQLite
                        if profiled_count % 50 == 0 or \
                                profiled_count == num_unprofiled:
                            send('profiling',
                                 f'Enriched {done}/{total} devices '
                                 f'({profiled_count} new, '
                                 f'{num_unprofiled - profiled_count} '
                                 f'remaining)',
                                 pct,
                                 {'total': total, 'profiled': done,
                                  'newly_profiled': profiled_count,
                                  'failed': failed_count,
                                  'phase': 'enriching'})
                except Exception as e:
                    log.warning(f"Failed to enrich {ip}: {e}")
                    with lock:
                        failed_count += 1

        # Launch workers (pure Python — no Splunk, very fast)
        with ThreadPoolExecutor(max_workers=num_workers,
                                thread_name_prefix='bgp') as pool:
            futures = [pool.submit(worker) for _ in range(num_workers)]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    log.error(f"Worker thread error: {e}")

        # Merge enrichment into latest map from disk (continuous
        # ingest may have updated it while we were profiling).
        nm.merge_enrichment_and_save()

        final_stats = nm.get_profiling_stats()
        send('complete',
             f'Profiling complete: '
             f'{final_stats["profiled"]}/{total} devices profiled '
             f'({profiled_count} new, {failed_count} failed)',
             100,
             {'total': total, 'profiled': final_stats['profiled'],
              'newly_profiled': profiled_count,
              'failed': failed_count})

        log.info(f"BG Profile complete: {profiled_count} newly profiled, "
                 f"{failed_count} failed")

    except Exception as e:
        log.error(f'BG Profile {profile_id} failed: {e}')
        log.error(traceback.format_exc())
        send('error', f'Profiling failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc()})


# ---------------------------------------------------------------------------
# Helper — rebuild network map from stored events (no Splunk needed)
# ---------------------------------------------------------------------------

def _rebuild_map_from_db(db, nm, max_cycle, send, log):
    """Stream events from hunt_events and feed them to the network mapper.

    Processes one cycle at a time so memory stays bounded even with
    hundreds of millions of rows.
    """
    import json as _json
    import time as _time
    total_mapped = 0
    _last_progress = _time.monotonic()

    send('running',
         f'Rebuilding network map from {max_cycle} stored cycles...',
         10, {'pipeline': 'data',
              'stage_detail': 'db_replay',
              'cycle': 0, 'total_cycles': max_cycle,
              'total_events': 0, 'total_nodes': 0})

    for c in range(1, max_cycle + 1):
        conn = db._connect()
        try:
            cursor = conn.execute(
                "SELECT data_type, event_json FROM hunt_events "
                "WHERE cycle = ? AND data_type IN "
                "('network_connections', 'dns_queries', 'ntlm_logs')",
                (c,),
            )
            conns, dns_q, ntlm_l = [], [], []
            batch_size = 50_000
            count = 0
            for data_type, event_json in cursor:
                evt = _json.loads(event_json)
                if data_type == 'network_connections':
                    conns.append(evt)
                elif data_type == 'dns_queries':
                    dns_q.append(evt)
                elif data_type == 'ntlm_logs':
                    ntlm_l.append(evt)
                count += 1

                # Flush in batches to keep memory bounded
                if count >= batch_size:
                    if conns or dns_q or ntlm_l:
                        nm.execute(
                            network_connections=conns,
                            dns_queries=dns_q,
                            ntlm_logs=ntlm_l,
                        )
                    total_mapped += count
                    conns, dns_q, ntlm_l = [], [], []
                    count = 0

                    # Send progress every 2 seconds during large replays
                    if _time.monotonic() - _last_progress >= 2:
                        _last_progress = _time.monotonic()
                        pct = 10 + int(35 * c / max(max_cycle, 1))
                        send('running',
                             f'Replaying stored data: cycle {c}/{max_cycle} '
                             f'({total_mapped:,} events, {len(nm.nodes)} nodes)...',
                             pct, {'pipeline': 'data',
                                   'stage_detail': 'db_replay',
                                   'cycle': c, 'total_cycles': max_cycle,
                                   'total_events': total_mapped,
                                   'total_nodes': len(nm.nodes)})

            # Flush remaining
            if conns or dns_q or ntlm_l:
                nm.execute(
                    network_connections=conns,
                    dns_queries=dns_q,
                    ntlm_logs=ntlm_l,
                )
            total_mapped += count
        finally:
            conn.close()

        # Report per-cycle or every 3 cycles for speed
        if c % 3 == 0 or c == max_cycle or c == 1:
            nm.save_map()
            pct = 10 + int(35 * c / max(max_cycle, 1))
            send('running',
                 f'Replaying stored data: cycle {c}/{max_cycle} '
                 f'({total_mapped:,} events, {len(nm.nodes)} nodes)...',
                 pct, {'pipeline': 'data',
                       'stage_detail': 'db_replay',
                       'cycle': c, 'total_cycles': max_cycle,
                       'total_events': total_mapped,
                       'total_nodes': len(nm.nodes)})
            log.info(f'Map rebuild: {c}/{max_cycle} cycles, '
                     f'{total_mapped:,} events, {len(nm.nodes)} nodes')

    nm.save_map()


# ---------------------------------------------------------------------------
# Data Pipeline Process — fast collection + map building, no LLM
# ---------------------------------------------------------------------------

def _data_pipeline_process(job_id, interval_minutes, lookback_minutes,
                           db_path, backfill_from=None):
    """Continuously collect network data, build the map, and store events.

    This process does NOT run agents or LLM analysis — it only:
    1. Pulls events from Splunk
    2. Feeds them into the network mapper
    3. Stores raw events in the persistent event store (hunt_events table)
    4. Queues each cycle for the analysis pipeline

    Runs in a non-daemon subprocess that survives server restarts.
    """
    import os, logging, traceback, json, time, signal as _signal
    from datetime import datetime
    from artemis.managers.db_manager import DatabaseManager
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
    from artemis.plugins.network_mapper import NetworkMapperPlugin

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.data_pipeline')

    db = DatabaseManager(db_path)
    pid = os.getpid()
    _stop = False

    def _handle_term(*_a):
        nonlocal _stop
        _stop = True
        log.info('Received SIGTERM — stopping after current cycle')

    _signal.signal(_signal.SIGTERM, _handle_term)

    def send(stage, message, progress, extra=None):
        try:
            db.write_progress(job_id, pid, stage, message, progress, extra)
        except Exception:
            pass

    send('running', 'Starting data pipeline...', 0)

    try:
        # Build Splunk connector
        host, token, username, password = _read_splunk_credentials()
        cfg = DataSourceConfig(
            splunk_host=host, splunk_port=8089,
            splunk_token=token or '',
            splunk_username=username or '',
            splunk_password=password or '',
        )
        pipeline = DataPipeline(cfg)
        if not pipeline.splunk:
            send('error', 'Cannot connect to Splunk', 0)
            return

        # Load network mapper
        nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
        nm.initialize()

        # When starting a backfill, force a clean map — don't carry over
        # stale nodes from a previous run's map file.
        # Auto-save a backup snapshot first so the user doesn't lose work.
        if backfill_from:
            if nm.nodes:
                import shutil
                from pathlib import Path
                maps_dir = Path('network_maps')
                current = maps_dir / 'current_map.json'
                if current.exists():
                    backup_name = f"pre_backfill_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    backup_file = maps_dir / backup_name
                    shutil.copy2(current, backup_file)
                    log.info(f'Backed up existing map to {backup_name} before backfill')
            nm.nodes.clear()
            nm.sensors.clear()
            nm.mac_history.clear()
            nm._dirty_nodes.clear()
            nm._stats_cache = None
            nm.save_map()
            log.info('Backfill requested — cleared stale map data')

        # Get the latest cycle number from DB to continue sequentially
        cycle = db.get_latest_event_cycle()
        time_range = f'-{lookback_minutes}m'
        _backfill_pending = bool(backfill_from)

        # ── Skip Splunk re-download when events already exist ──
        # If we're asked to backfill but events are already stored,
        # just ensure they're queued for analysis and rebuild the map.
        if _backfill_pending and cycle > 0:
            total_stored = db.get_total_event_count()
            if total_stored > 0:
                log.info(
                    f'Backfill requested but {total_stored:,} events '
                    f'already stored across {cycle} cycles — '
                    f'skipping Splunk re-download')
                send('running',
                     f'Found {total_stored:,} existing events in '
                     f'{cycle} cycles — rebuilding map...',
                     10, {'pipeline': 'data',
                          'stage_detail': 'reuse_existing',
                          'total_events': total_stored,
                          'total_cycles': cycle})

                # Re-queue all cycles for fresh analysis.  Use
                # requeue_analysis (not queue_analysis) so that
                # previously-completed cycles are reset to 'pending'
                # — on restart we want a fresh analysis pass.
                queued = 0
                for c in range(1, cycle + 1):
                    evt_counts = db.get_event_counts_for_cycle(c)
                    if evt_counts:
                        db.requeue_analysis(c, evt_counts)
                        queued += 1

                log.info(f'Ensured {queued} cycles are queued for analysis')
                send('running',
                     f'Queued {queued} cycles for analysis — '
                     f'rebuilding network map from stored events...',
                     20, {'pipeline': 'data',
                          'stage_detail': 'requeue_existing',
                          'queued': queued})

                # Rebuild network map from stored events (stream to
                # avoid loading all events at once)
                _rebuild_map_from_db(db, nm, cycle, send, log)

                _backfill_pending = False  # skip the Splunk pull
                log.info(
                    f'Map rebuilt with {len(nm.nodes)} nodes — '
                    f'switching to live collection')
                send('running',
                     f'Map rebuilt ({len(nm.nodes)} nodes) — '
                     f'collecting live data...',
                     50, {'pipeline': 'data',
                          'total_nodes': len(nm.nodes),
                          'stage_detail': 'live_collection'})

        while not _stop:
            cycle += 1
            cycle_start = datetime.now()

            if _backfill_pending:
                _backfill_pending = False
                bf_start = backfill_from
                bf_end = datetime.now().isoformat()
                log.info(f'Cycle {cycle}: backfill from {bf_start} to now')

                # Check Splunk data availability before starting
                send('running',
                     f'Cycle {cycle}: checking Splunk data availability '
                     f'for {bf_start}...',
                     20, {'cycle': cycle, 'pipeline': 'data',
                          'total_nodes': len(nm.nodes),
                          'stage_detail': 'retention_check',
                          'backfill_from': bf_start})

                try:
                    avail = pipeline.splunk.check_data_availability(
                        earliest_time=bf_start,
                        latest_time=bf_end,
                    )
                    if avail['has_data']:
                        log.info(
                            f'Splunk retention check passed: '
                            f'{avail["message"]}')
                        send('running',
                             f'Cycle {cycle}: {avail["message"]} — '
                             f'starting backfill...',
                             22, {'cycle': cycle, 'pipeline': 'data',
                                  'total_nodes': len(nm.nodes),
                                  'stage_detail': 'retention_ok',
                                  'backfill_from': bf_start,
                                  'splunk_earliest': avail.get('earliest_event', ''),
                                  'splunk_latest': avail.get('latest_event', '')})
                    else:
                        log.warning(
                            f'Splunk retention check: {avail["message"]}')
                        send('running',
                             f'WARNING: {avail["message"]} — '
                             f'backfill may return empty results',
                             22, {'cycle': cycle, 'pipeline': 'data',
                                  'total_nodes': len(nm.nodes),
                                  'stage_detail': 'retention_warning',
                                  'backfill_from': bf_start,
                                  'retention_warning': avail['message']})
                except Exception as _rc_err:
                    log.warning(f'Retention check failed: {_rc_err}')

                send('running',
                     f'Cycle {cycle}: backfilling from {bf_start}...',
                     25, {'cycle': cycle, 'pipeline': 'data',
                          'total_nodes': len(nm.nodes),
                          'interval': interval_minutes,
                          'lookback': lookback_minutes,
                          'stage_detail': 'splunk_fetch',
                          'backfill_from': bf_start})
            else:
                log.info(f'Cycle {cycle}: collecting last {lookback_minutes}m')
                send('running',
                     f'Cycle {cycle}: collecting data (last {lookback_minutes}m)...',
                     50, {'cycle': cycle, 'pipeline': 'data',
                          'total_nodes': len(nm.nodes),
                          'interval': interval_minutes,
                          'lookback': lookback_minutes})
                bf_start = None
                bf_end = None

            try:
                # Progress callback
                def _splunk_progress(info):
                    ptype = info.get('type', '')
                    if ptype == 'window_done':
                        w = info.get('window', '?')
                        tw = info.get('total_windows', '?')
                        rt = info.get('running_total', 0)
                        we = info.get('window_earliest', '')
                        wl = info.get('window_latest', '')
                        send('running',
                             f'Cycle {cycle}: fetched window {w}/{tw} '
                             f'({rt:,} events)...',
                             25 + int(30 * w / max(tw, 1)),
                             {'cycle': cycle, 'pipeline': 'data',
                              'total_nodes': len(nm.nodes),
                              'stage_detail': 'splunk_fetch',
                              'window': w, 'total_windows': tw,
                              'running_total': rt,
                              'window_earliest': we,
                              'window_latest': wl,
                              'backfill_from': bf_start or ''})
                    elif ptype == 'query_done':
                        log.info(f'Cycle {cycle}: query {info.get("query_name")} '
                                 f'returned {info.get("query_events", 0):,} events')

                # Collect from Splunk
                if bf_start:
                    _bf_windows_mapped = [0]
                    _bf_total_events = [0]
                    _bf_cycle = [cycle]           # mutable current cycle
                    _bf_cycle_events = [0]        # events in current batch
                    _bf_batches_queued = [0]      # analysis batches queued

                    # Queue analysis every 50k events so agents hunt
                    # during long historical backfills instead of waiting
                    # for the entire backfill to finish.
                    _BF_ANALYSIS_THRESHOLD = 50_000

                    def _map_window(window_data):
                        conns = window_data.get('network_connections', [])
                        dns_q = window_data.get('dns_queries', [])
                        ntlm_l = window_data.get('ntlm_logs', [])
                        if conns or dns_q or ntlm_l:
                            nm.execute(
                                network_connections=conns,
                                dns_queries=dns_q,
                                ntlm_logs=ntlm_l,
                            )
                            _bf_windows_mapped[0] += 1
                            window_events = len(conns) + len(dns_q) + len(ntlm_l)
                            _bf_total_events[0] += window_events

                            cur = _bf_cycle[0]

                            # Store events in persistent store
                            if conns:
                                db.store_events(cur, 'network_connections', conns)
                            if dns_q:
                                db.store_events(cur, 'dns_queries', dns_q)
                            if ntlm_l:
                                db.store_events(cur, 'ntlm_logs', ntlm_l)

                            # Store other data types
                            for key in ('authentication_logs', 'process_logs',
                                        'powershell_logs', 'file_operations',
                                        'scheduled_tasks', 'registry_changes'):
                                events = window_data.get(key, [])
                                if events:
                                    db.store_events(cur, key, events)
                                    window_events += len(events)

                            _bf_cycle_events[0] += window_events

                            # When 50k events accumulate, queue for agent
                            # analysis so hunting starts while backfill
                            # continues.
                            if _bf_cycle_events[0] >= _BF_ANALYSIS_THRESHOLD:
                                nm.save_map()
                                evt_counts = db.get_event_counts_for_cycle(cur)
                                db.queue_analysis(cur, evt_counts)
                                _bf_batches_queued[0] += 1
                                log.info(
                                    f'Cycle {cur}: queued '
                                    f'{_bf_cycle_events[0]:,} events for '
                                    f'analysis (batch {_bf_batches_queued[0]})')
                                send('running',
                                     f'Cycle {cur}: queued '
                                     f'{_bf_cycle_events[0]:,} events for '
                                     f'agent analysis...',
                                     30, {'cycle': cur, 'pipeline': 'data',
                                          'stage_detail': 'backfill_analysis_queued',
                                          'total_nodes': len(nm.nodes),
                                          'batch_events': _bf_cycle_events[0],
                                          'total_events': _bf_total_events[0],
                                          'batches_queued': _bf_batches_queued[0],
                                          'backfill_from': bf_start})
                                # Start a new cycle for the next batch
                                _bf_cycle[0] += 1
                                _bf_cycle_events[0] = 0

                            elif _bf_windows_mapped[0] % 3 == 0:
                                nm.save_map()
                                send('running',
                                     f'Cycle {cur}: backfill — mapped '
                                     f'{_bf_windows_mapped[0]} windows '
                                     f'({_bf_total_events[0]:,} events, '
                                     f'{len(nm.nodes)} nodes)...',
                                     30, {'cycle': cur, 'pipeline': 'data',
                                          'stage_detail': 'backfill_mapping',
                                          'total_nodes': len(nm.nodes),
                                          'total_events': _bf_total_events[0],
                                          'backfill_from': bf_start})

                    hunting_data = pipeline.collect_hunting_data(
                        earliest_time=bf_start,
                        latest_time=bf_end,
                        storage_mode='sqlite',
                        progress_callback=_splunk_progress,
                        per_window_callback=_map_window,
                    )
                    if _bf_windows_mapped[0] > 0:
                        nm.save_map()

                    # Update cycle to the latest used during backfill
                    cycle = _bf_cycle[0]

                    # Queue any remaining events from the last partial batch
                    has_data = _bf_cycle_events[0] > 0
                    conn_count = dns_count = ntlm_count = 0  # already stored

                    if _bf_batches_queued[0] > 0:
                        remaining = (f', {_bf_cycle_events[0]:,} remaining'
                                     if has_data else '')
                        log.info(
                            f'Backfill complete: {_bf_total_events[0]:,} '
                            f'total events across '
                            f'{_bf_batches_queued[0]} batches queued'
                            f'{remaining}')

                    if hasattr(hunting_data, 'close'):
                        try:
                            hunting_data.close()
                        except Exception:
                            pass
                else:
                    hunting_data = pipeline.collect_hunting_data(
                        time_range=time_range)

                    conns = hunting_data.get('network_connections', [])
                    dns = hunting_data.get('dns_queries', [])
                    ntlm = hunting_data.get('ntlm_logs', [])
                    conn_count, dns_count, ntlm_count = len(conns), len(dns), len(ntlm)
                    has_data = bool(conns or dns or ntlm)

                    if has_data:
                        # Feed network mapper
                        result = nm.execute(
                            network_connections=conns,
                            dns_queries=dns,
                            ntlm_logs=ntlm,
                        )
                        nm.save_map()

                        # Store events in persistent store
                        for key, events in hunting_data.items():
                            if isinstance(events, list) and events:
                                db.store_events(cycle, key, events)

                if has_data:
                    # Queue this cycle for agent/LLM analysis
                    event_counts = db.get_event_counts_for_cycle(cycle)
                    db.queue_analysis(cycle, event_counts)

                    total_nodes = len(nm.nodes)
                    msg = (f'Cycle {cycle} collected: {conn_count} conns, '
                           f'{dns_count} DNS, {ntlm_count} NTLM → '
                           f'{total_nodes} nodes (queued for analysis)')
                    log.info(msg)
                    send('running', msg, 50,
                         {'cycle': cycle, 'pipeline': 'data',
                          'new_conns': conn_count,
                          'new_dns': dns_count, 'new_ntlm': ntlm_count,
                          'total_nodes': total_nodes})

                    # NOTE: profiling is handled by the separate profile
                    # pipeline process running in parallel — no inline
                    # profiling here to avoid blocking data collection.

                    # Cleanup old events (keep 72 hours)
                    try:
                        deleted = db.cleanup_old_events(max_age_hours=72)
                        if deleted > 0:
                            log.info(f'Cleaned up {deleted} old events')
                    except Exception:
                        pass

                else:
                    msg = f'Cycle {cycle}: no new data in last {lookback_minutes}m'
                    log.info(msg)
                    send('running', msg, 50,
                         {'cycle': cycle, 'pipeline': 'data',
                          'new_conns': 0, 'new_dns': 0, 'new_ntlm': 0,
                          'total_nodes': len(nm.nodes)})

            except Exception as e:
                log.error(f'Cycle {cycle} error: {e}')
                log.error(traceback.format_exc())
                send('running', f'Cycle {cycle} error: {e}', 50,
                     {'cycle': cycle, 'pipeline': 'data',
                      'total_nodes': len(nm.nodes),
                      'error': str(e)})

            # Sleep in 5-second increments
            wait_seconds = interval_minutes * 60
            elapsed = (datetime.now() - cycle_start).total_seconds()
            remaining = max(0, wait_seconds - elapsed)
            while remaining > 0 and not _stop:
                time.sleep(min(5, remaining))
                remaining -= 5

        send('complete', f'Data pipeline stopped after {cycle} cycles', 100,
             {'cycles_completed': cycle, 'pipeline': 'data'})
        log.info(f'Data pipeline stopped after {cycle} cycles')

    except Exception as e:
        log.error(f'Data pipeline failed: {e}')
        log.error(traceback.format_exc())
        send('error', f'Data pipeline failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc(), 'pipeline': 'data'})


# ---------------------------------------------------------------------------
# Analysis Pipeline Process — agents + LLM, consumes queued cycles
# ---------------------------------------------------------------------------

def _analysis_pipeline_process(job_id, db_path):
    """Consume queued cycles and run agent/LLM analysis on stored events.

    Runs in a non-daemon subprocess.  Polls the analysis_queue table
    for pending cycles, loads events from hunt_events, runs the
    coordinator (agents + LLM), and saves findings/synthesis.

    This process is decoupled from data collection — it can fall behind
    if analysis is slow, and will catch up by processing cycles in order.
    """
    import os, logging, traceback, json, time, signal as _signal
    import concurrent.futures as _cf
    from datetime import datetime
    from artemis.managers.db_manager import DatabaseManager
    from artemis.plugins.network_mapper import NetworkMapperPlugin
    from artemis.meta_learner.coordinator import MetaLearnerCoordinator
    from artemis.models.network_state import NetworkState

    _HUNT_TIMEOUT_S = int(os.environ.get('HUNT_TIMEOUT', '3600'))  # 1 hour default

    # Ensure numexpr can use more cores in this subprocess too
    os.environ.setdefault("NUMEXPR_MAX_THREADS", "96")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.analysis_pipeline')

    # Ensure agent activity logging writes to the correct DB
    from artemis.ws import set_db_path
    set_db_path(db_path)

    db = DatabaseManager(db_path)
    pid = os.getpid()
    _stop = False

    def _handle_term(*_a):
        nonlocal _stop
        _stop = True
        log.info('Received SIGTERM — stopping after current analysis')

    _signal.signal(_signal.SIGTERM, _handle_term)

    def send(stage, message, progress, extra=None):
        try:
            db.write_progress(job_id, pid, stage, message, progress, extra)
        except Exception:
            pass

    send('running', 'Starting analysis pipeline...', 0,
         {'pipeline': 'analysis', 'status': 'initializing'})

    _MAX_INIT_RETRIES = 5

    try:
        # ----------------------------------------------------------
        # Initialization with retry — transient failures (LLM health
        # check, file locks, Ollama cold-start) should not permanently
        # kill the pipeline.
        # ----------------------------------------------------------
        coordinator = None
        nm = None
        _crew_orchestrator = None
        _llm_cfg = {}

        for _init_attempt in range(1, _MAX_INIT_RETRIES + 1):
            try:
                # Load network mapper (read-only for context)
                nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
                nm.initialize()

                # Initialize coordinator with LLM
                _llm_cfg = {}
                _llm_cfg_path = os.path.join('config', 'llm_settings.json')
                if os.path.exists(_llm_cfg_path):
                    try:
                        import json as _json
                        with open(_llm_cfg_path) as _f:
                            _llm_cfg = _json.load(_f)
                        log.info(f'Loaded LLM config: backend={_llm_cfg.get("backend", "auto")}')
                    except Exception as _e:
                        log.warning(f'Could not read LLM config: {_e}')

                _llm_backend = _llm_cfg.get('backend') or os.environ.get('LLM_BACKEND', 'auto')
                _ollama_url = (
                    _llm_cfg.get('ollama_url')
                    or os.environ.get('OLLAMA_URL')
                    or os.environ.get('OLLAMA_API_BASE')
                    or 'http://localhost:11434'
                )
                os.environ.setdefault('OLLAMA_URL', _ollama_url)
                os.environ.setdefault('OLLAMA_API_BASE', _ollama_url)

                if _llm_cfg.get('ollama_model'):
                    os.environ['OLLAMA_MODEL'] = _llm_cfg['ollama_model']
                if _llm_cfg.get('anthropic_api_key'):
                    os.environ['ANTHROPIC_API_KEY'] = _llm_cfg['anthropic_api_key']

                coordinator = MetaLearnerCoordinator(
                    deployment_mode='adaptive',
                    enable_parallel_execution=True,
                    max_workers=4,
                    llm_backend=_llm_backend,
                )
                log.info(f'Initialized {len(coordinator.agents)} hunting agents')

                # Try CrewAI orchestrator
                _crew_orchestrator = None
                if _llm_cfg.get('orchestration') == 'crewai':
                    try:
                        from artemis.llm.crew import CrewOrchestrator, crewai_available
                        if crewai_available():
                            _ollama_model = _llm_cfg.get('ollama_model') or os.environ.get('OLLAMA_MODEL', 'llama3.1')
                            _crew_orchestrator = CrewOrchestrator(
                                detectors=coordinator.agents,
                                rag_store=getattr(coordinator, 'rag_store', None),
                                llm_model=f"ollama/{_ollama_model}",
                                process=_llm_cfg.get('crewai_process', 'sequential'),
                                num_ctx=int(os.environ.get('OLLAMA_NUM_CTX', '262144')),
                            )
                            log.info('CrewAI orchestrator initialised')
                    except Exception as _ce:
                        log.warning(f'CrewAI init failed: {_ce}')

                # Init succeeded — update status immediately
                send('running',
                     f'Analysis pipeline ready ({len(coordinator.agents)} agents, '
                     f'{_llm_backend}) — checking for pending cycles...',
                     5, {'pipeline': 'analysis',
                         'n_agents': len(coordinator.agents),
                         'llm_backend': getattr(coordinator.llm_client, 'backend', 'none'),
                         'status': 'idle'})
                break

            except Exception as _init_err:
                log.error(
                    f'Analysis pipeline init attempt {_init_attempt}/'
                    f'{_MAX_INIT_RETRIES} failed: {_init_err}'
                )
                log.error(traceback.format_exc())
                if _init_attempt >= _MAX_INIT_RETRIES:
                    raise  # Let the outer handler catch it
                _backoff = min(30, 5 * _init_attempt)
                send('running',
                     f'Init failed (attempt {_init_attempt}/{_MAX_INIT_RETRIES}),'
                     f' retrying in {_backoff}s: {_init_err}', 0,
                     {'pipeline': 'analysis', 'error': str(_init_err)})
                for _ in range(int(_backoff)):
                    if _stop:
                        return
                    time.sleep(1)

        analyses_completed = 0
        _consecutive_failures = 0
        _MAX_CONSECUTIVE_FAILURES = 3

        while not _stop:
            # LLM health check — if we've had consecutive failures,
            # back off to avoid burning CPU on a frozen Ollama instance
            if _consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                _backoff_s = min(300, 60 * _consecutive_failures)
                log.warning(
                    f'{_consecutive_failures} consecutive hunt failures — '
                    f'backing off {_backoff_s}s before retrying')
                send('running',
                     f'LLM issues: {_consecutive_failures} failures, '
                     f'backing off {_backoff_s}s...',
                     45, {'pipeline': 'analysis',
                          'status': 'backoff',
                          'consecutive_failures': _consecutive_failures})
                for _ in range(int(_backoff_s)):
                    if _stop:
                        break
                    time.sleep(1)
                # Quick Ollama health check before resuming
                try:
                    _health_ok = coordinator.llm_client._check_ollama()
                    if not _health_ok:
                        log.warning('Ollama still not healthy — waiting...')
                        continue
                    log.info('Ollama health check passed — resuming')
                    _consecutive_failures = 0  # Reset on health pass
                except Exception:
                    continue

            # Poll for pending analysis
            pending = db.get_pending_analysis()

            if not pending:
                # Nothing to analyze — sleep briefly and check again
                _idle_findings = db.get_findings_summary().get('total', 0)
                send('running',
                     f'Waiting for data (analyzed {analyses_completed} cycles)...',
                     50, {'pipeline': 'analysis',
                          'analyses_completed': analyses_completed,
                          'findings': _idle_findings,
                          'n_agents': len(coordinator.agents),
                          'llm_backend': getattr(coordinator.llm_client, 'backend', 'none'),
                          'status': 'idle'})
                for _ in range(6):  # 30 seconds in 5s increments
                    if _stop:
                        break
                    time.sleep(5)
                continue

            analysis_cycle = pending['cycle']
            event_counts = pending.get('event_counts', {})
            total_events = sum(event_counts.values())

            log.info(f'Analyzing cycle {analysis_cycle} '
                     f'({total_events:,} events)')
            db.mark_analysis_started(analysis_cycle)

            _backend = getattr(coordinator.llm_client, 'backend', 'none')
            _n_agents = len(coordinator.agents)
            _orch_label = 'CrewAI' if _crew_orchestrator else _backend

            send('running',
                 f'Analyzing cycle {analysis_cycle}: {total_events:,} events '
                 f'with {_n_agents} agents ({_orch_label})...',
                 60, {'pipeline': 'analysis',
                      'cycle': analysis_cycle,
                      'total_events': total_events,
                      'n_agents': _n_agents,
                      'llm_backend': _backend,
                      'stage_detail': 'llm_analysis',
                      'orchestration': 'crewai' if _crew_orchestrator else 'standard'})

            findings_count = 0
            try:
                # Load events from persistent store (can be slow for
                # large cycles with hundreds of thousands of events)
                send('running',
                     f'Loading {total_events:,} events for cycle '
                     f'{analysis_cycle}...',
                     55, {'pipeline': 'analysis',
                          'cycle': analysis_cycle,
                          'total_events': total_events,
                          'n_agents': _n_agents,
                          'llm_backend': _backend,
                          'stage_detail': 'loading_events'})
                agent_data = db.get_events_for_cycle(analysis_cycle)

                # Add counts metadata
                agent_data['_counts'] = event_counts

                # Reload map for latest context
                nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
                nm.initialize()

                # Build network state with map context + annotations
                annotations = db.get_annotations()
                context = NetworkState.from_data_with_map(
                    agent_data, nm.nodes)

                # Inject analyst annotations into context
                if annotations:
                    ann_by_ip = {}
                    for ann in annotations:
                        nid = ann.get('node_id')
                        if nid:
                            # Extract IP from node_id (format: sensor:vlan:ip)
                            parts = nid.split(':')
                            ip = parts[-1] if parts else nid
                            ann_by_ip.setdefault(ip, []).append(
                                ann['content'])
                    if ann_by_ip:
                        context.network_map.analyst_annotations = ann_by_ip
                        context.recent_agent_findings['analyst_annotations'] = ann_by_ip

                # Helper to persist agent outputs to DB immediately
                def _save_agent_outputs(agent_outputs_list):
                    _count = 0
                    for ao in agent_outputs_list:
                        ao_dict = ao if isinstance(ao, dict) else ao.to_dict()
                        for f in ao_dict.get('findings', []):
                            _count += 1
                            db.save_finding(
                                finding_id=f.get('fingerprint',
                                                 f.get('activity_type', '') + str(analysis_cycle)),
                                agent_name=ao_dict.get('agent_name', 'unknown'),
                                activity_type=f.get('activity_type', ''),
                                severity=ao_dict.get('severity', 'medium'),
                                confidence=ao_dict.get('confidence', 0.0),
                                description=f.get('description', ''),
                                indicators=f.get('indicators', []),
                                affected_assets=f.get('affected_assets', []),
                                mitre_tactics=ao_dict.get('mitre_tactics', []),
                                mitre_techniques=f.get('mitre_techniques', []),
                                evidence_count=len(f.get('evidence', [])),
                                evidence=f.get('evidence', []),
                                recommended_actions=ao_dict.get('recommended_actions', []),
                                source_cycle=analysis_cycle,
                            )
                    return _count

                # Phase 1: Run ML detectors and save findings immediately
                # so they appear in the GUI while the LLM synthesis runs.
                if _crew_orchestrator:
                    log.info('Phase 1: Running ML detectors...')
                    ml_outputs = _crew_orchestrator._run_detectors(
                        agent_data, context)
                    findings_count = _save_agent_outputs(ml_outputs)
                    log.info(f'Phase 1 complete: {findings_count} findings '
                             f'saved to DB (visible in GUI now)')

                    send('running',
                         f'Cycle {analysis_cycle}: {findings_count} ML findings '
                         f'saved — running LLM synthesis...',
                         70, {'pipeline': 'analysis',
                              'cycle': analysis_cycle,
                              'findings': findings_count,
                              'stage_detail': 'llm_synthesis'})

                # Phase 2: Run full hunt (LLM synthesis).
                #
                # Use ThreadPoolExecutor so we can poll with heartbeats
                # and enforce a timeout.  The executor thread can't be
                # forcibly killed, but the timeout lets us mark the cycle
                # complete and advance rather than blocking forever.
                def _run_hunt():
                    if _crew_orchestrator:
                        return _crew_orchestrator.hunt(
                            data=agent_data, network_state=context,
                            pre_computed_outputs=ml_outputs)
                    return coordinator.hunt(
                        data=agent_data, network_state=context)

                with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                    _fut = _pool.submit(_run_hunt)
                    _hunt_start = time.time()
                    # Poll with short timeouts so we can send heartbeats
                    while True:
                        try:
                            assessment = _fut.result(timeout=30)
                            log.info(f'Cycle {analysis_cycle}: hunt() returned '
                                     f'assessment with keys: {list(assessment.keys()) if assessment else "None"}')
                            break  # Hunt completed
                        except _cf.TimeoutError:
                            elapsed = time.time() - _hunt_start
                            if elapsed > _HUNT_TIMEOUT_S:
                                _fut.cancel()
                                log.error(
                                    f'Cycle {analysis_cycle}: hunt timed out '
                                    f'after {_HUNT_TIMEOUT_S}s — skipping')
                                raise TimeoutError(
                                    f'Hunt exceeded {_HUNT_TIMEOUT_S}s timeout')
                            # Send heartbeat so the UI knows the LLM is working
                            send('running',
                                 f'LLM analysis in progress ({int(elapsed)}s elapsed)...',
                                 65,
                                 {'pipeline': 'analysis',
                                  'cycle': analysis_cycle,
                                  'findings': findings_count,
                                  'n_agents': _n_agents,
                                  'llm_backend': _backend,
                                  'stage_detail': 'llm_synthesis',
                                  'elapsed_seconds': int(elapsed),
                                  'orchestration': 'crewai' if _crew_orchestrator else 'standard'})

                # Save findings (for non-CrewAI path, or any new findings
                # the LLM-driven tools discovered beyond the initial ML run)
                if not _crew_orchestrator:
                    for ao in assessment.get('agent_outputs', []):
                        ao_dict = ao if isinstance(ao, dict) else ao.to_dict()
                        for f in ao_dict.get('findings', []):
                            findings_count += 1
                            db.save_finding(
                                finding_id=f.get('fingerprint',
                                                 f.get('activity_type', '') + str(analysis_cycle)),
                                agent_name=ao_dict.get('agent_name', 'unknown'),
                                activity_type=f.get('activity_type', ''),
                                severity=ao_dict.get('severity', 'medium'),
                                confidence=ao_dict.get('confidence', 0.0),
                                description=f.get('description', ''),
                                indicators=f.get('indicators', []),
                                affected_assets=f.get('affected_assets', []),
                                mitre_tactics=ao_dict.get('mitre_tactics', []),
                                mitre_techniques=f.get('mitre_techniques', []),
                                evidence_count=len(f.get('evidence', [])),
                                evidence=f.get('evidence', []),
                                recommended_actions=ao_dict.get('recommended_actions', []),
                                source_cycle=analysis_cycle,
                            )

                # Persist LLM synthesis
                llm_synth = assessment.get('llm_synthesis')
                log.info(f'Cycle {analysis_cycle}: llm_synthesis present={llm_synth is not None}, '
                         f'type={type(llm_synth).__name__}')
                if llm_synth:
                    try:
                        db.save_synthesis(analysis_cycle, llm_synth)
                        log.info(f'Cycle {analysis_cycle}: saved LLM synthesis '
                                 f'(severity={llm_synth.get("overall_severity", "?")})')
                    except Exception as se:
                        log.error(f'Failed to save LLM synthesis: {se}',
                                  exc_info=True)

                db.mark_analysis_complete(analysis_cycle)
                analyses_completed += 1
                _consecutive_failures = 0  # Reset on success

                # Free disk space — delete raw events for this completed
                # cycle since findings are now persisted in agent_findings.
                try:
                    _freed = db.cleanup_analyzed_events()
                    if _freed:
                        log.info(f'Cleaned up {_freed:,} analyzed event rows')
                except Exception as _ce:
                    log.warning(f'Event cleanup failed (non-fatal): {_ce}')

                # Use the cumulative DB total so the pipeline card stays
                # in sync with the findings tab (not just this cycle's count).
                total_findings = db.get_findings_summary().get('total', findings_count)

                msg = (f'Cycle {analysis_cycle} analyzed: '
                       f'{findings_count} findings from {total_events:,} events')
                log.info(msg)
                send('running', msg, 50,
                     {'pipeline': 'analysis',
                      'cycle': analysis_cycle,
                      'findings': total_findings,
                      'n_agents': _n_agents,
                      'llm_backend': _backend,
                      'analyses_completed': analyses_completed})

            except TimeoutError as te:
                _consecutive_failures += 1
                log.error(f'Analysis cycle {analysis_cycle} timed out: {te}')
                # Skip this cycle (ML findings are already saved from Phase 1)
                # but don't endlessly retry — mark complete so the pipeline
                # advances to newer cycles with fresher data.
                db.mark_analysis_complete(analysis_cycle)
                send('running',
                     f'Cycle {analysis_cycle} timed out (LLM synthesis skipped, '
                     f'ML findings preserved) — advancing to next cycle',
                     50,
                     {'pipeline': 'analysis', 'cycle': analysis_cycle,
                      'error': str(te),
                      'consecutive_failures': _consecutive_failures})

            except Exception as ae:
                _consecutive_failures += 1
                log.error(f'Analysis cycle {analysis_cycle} error: {ae}')
                log.error(traceback.format_exc())
                db.mark_analysis_complete(analysis_cycle)  # Don't retry
                send('running',
                     f'Cycle {analysis_cycle} analysis error: {ae}', 50,
                     {'pipeline': 'analysis', 'cycle': analysis_cycle,
                      'error': str(ae),
                      'consecutive_failures': _consecutive_failures})

        send('complete',
             f'Analysis pipeline stopped ({analyses_completed} cycles analyzed)',
             100, {'analyses_completed': analyses_completed,
                   'pipeline': 'analysis'})
        log.info(f'Analysis pipeline stopped after {analyses_completed} analyses')

    except Exception as e:
        log.error(f'Analysis pipeline failed: {e}')
        log.error(traceback.format_exc())
        send('error', f'Analysis pipeline failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc(), 'pipeline': 'analysis'})


# ---------------------------------------------------------------------------
# Profile pipeline (separate subprocess)
# ---------------------------------------------------------------------------

def _profile_pipeline_process(job_id, db_path):
    """Continuously profile unprofiled devices in a separate subprocess.

    Runs in a non-daemon subprocess alongside the data and analysis
    pipelines.  Polls for unprofiled devices, runs deep profiling
    (23 parallel Splunk queries per 24-hour window going back to each
    device's first_seen timestamp), then sleeps until the next check.

    Uses merge_enrichment_and_save() to avoid clobbering connection
    data being written concurrently by the data pipeline.
    """
    import os, logging, traceback, time, signal as _signal
    from datetime import datetime
    from artemis.managers.db_manager import DatabaseManager
    from artemis.plugins.network_mapper import NetworkMapperPlugin
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.profile_pipeline')

    db = DatabaseManager(db_path)
    pid = os.getpid()
    _stop = False

    def _handle_term(*_a):
        nonlocal _stop
        _stop = True
        log.info('Profile pipeline received SIGTERM, shutting down...')

    _signal.signal(_signal.SIGTERM, _handle_term)

    def send(stage, message, progress, data=None):
        db.write_progress(job_id, pid, stage, message, progress, data)

    send('running', 'Profile pipeline starting...', 0,
         {'pipeline': 'profile'})

    try:
        cfg = _build_splunk_config()
        pipeline = DataPipeline(cfg)
        nm = NetworkMapperPlugin({'output_dir': 'network_maps'})
        nm.initialize()

        log.info(f'Profile pipeline started (pid {pid})')

        # Wait for the data pipeline to finish its initial map rebuild
        # before profiling — otherwise node first_seen timestamps may
        # be wrong and we'd compute a too-short time range (e.g. -1h).
        _waited = 0
        _MAX_WAIT = 600  # 10 minutes max
        while not _stop and _waited < _MAX_WAIT:
            # Check if any data pipeline progress indicates it's still
            # replaying from DB or hasn't started live collection yet
            all_progress = db.get_all_running_progress()
            _rebuilding = False
            for p in all_progress:
                pdata = p.get('data', {})
                if pdata.get('pipeline') != 'data':
                    continue
                sd = pdata.get('stage_detail', '')
                if sd in ('db_replay', 'reuse_existing', 'requeue_existing',
                          'retention_check', 'retention_ok',
                          'retention_warning'):
                    _rebuilding = True
                    break
            if not _rebuilding:
                break
            if _waited == 0:
                log.info('Waiting for data pipeline map rebuild to finish '
                         'before profiling...')
                send('running',
                     'Waiting for data pipeline map rebuild...',
                     5, {'pipeline': 'profile', 'stage_detail': 'waiting_for_data'})
            _waited += 5
            time.sleep(5)

        if _waited > 0 and not _stop:
            log.info(f'Data pipeline rebuild finished after {_waited}s wait '
                     f'— starting profiling')
            # Reload map with corrected timestamps
            nm.initialize()

        _total_classified = 0

        while not _stop:
            # Reload map from disk to pick up new nodes from data pipeline
            nm.initialize()

            stats = nm.get_profiling_stats()
            unprofiled = stats.get('unprofiled', 0)
            profiled = stats.get('profiled', 0)

            if unprofiled == 0:
                send('running', 'All devices profiled — waiting for new nodes',
                     50, {'pipeline': 'profile', 'unprofiled': 0,
                          'classified': profiled or _total_classified,
                          'total_nodes': len(nm.nodes)})
                # Sleep 60s, checking for stop every 5s
                for _ in range(12):
                    if _stop:
                        break
                    time.sleep(5)
                continue

            # Collect IPs and MACs of unprofiled devices so queries
            # are scoped to only the devices that need profiling.
            unprofiled_nodes = [
                n for n in nm.nodes.values()
                if not n.device_type and n.is_internal
            ]
            target_ips = {n.ip for n in unprofiled_nodes if n.ip}
            target_macs = {
                n.mac_address for n in unprofiled_nodes
                if n.mac_address
            }

            # Use the full available time range so we gather as much
            # evidence as possible for each device.  Compute from the
            # earliest first_seen across ALL nodes (not just unprofiled)
            # to cover the complete data window.  Also check the DB
            # event collection timestamps as a fallback — when events
            # are replayed from the DB, node first_seen is set from
            # event timestamps which may be much older than wall-clock.
            all_nodes = list(nm.nodes.values())
            earliest = None
            if all_nodes:
                earliest = min(n.first_seen for n in all_nodes)

            # Also check DB collection timestamps as a secondary signal
            try:
                db_range = db.get_event_time_range()
                if db_range.get('earliest'):
                    db_earliest = datetime.fromisoformat(db_range['earliest'])
                    if earliest is None or db_earliest < earliest:
                        earliest = db_earliest
            except Exception:
                pass

            if earliest is not None:
                age_secs = (datetime.now() - earliest).total_seconds()
                age_hours = max(1, int(age_secs / 3600) + 1)
                if age_hours >= 24:
                    age_days = (age_hours + 23) // 24
                    profile_time_range = f'-{age_days}d'
                else:
                    profile_time_range = f'-{age_hours}h'
            else:
                profile_time_range = '-24h'

            log.info(f'Profiling {unprofiled} devices one-at-a-time '
                     f'({len(target_ips)} IPs, '
                     f'time_range={profile_time_range})')

            # ── Profile one device at a time ──────────────────────────
            # Running all devices in a single Splunk query builds a
            # huge WHERE ... IN (...) clause that is slow and can time
            # out.  Iterating per-device keeps each query fast and lets
            # us report per-device progress + save incrementally.
            _ip_list = sorted(target_ips)
            _total_this_round = len(_ip_list)
            _classified_this_round = 0
            _profile_times = []  # track per-device durations for avg

            for _dev_idx, _dev_ip in enumerate(_ip_list):
                if _stop:
                    break

                _pct = int((_dev_idx / max(_total_this_round, 1)) * 100)

                # Compute average time and ETA
                _avg_time = (sum(_profile_times) / len(_profile_times)
                             if _profile_times else 0.0)
                _remaining = _total_this_round - _dev_idx
                _eta_seconds = int(_avg_time * _remaining)

                send('running',
                     f'Profiling device {_dev_idx + 1}/{_total_this_round}: '
                     f'{_dev_ip} ({profile_time_range})',
                     20 + _pct * 60 // 100,
                     {'pipeline': 'profile',
                      'unprofiled': _remaining,
                      'total_nodes': len(nm.nodes),
                      'time_range': profile_time_range,
                      'current_ip': _dev_ip,
                      'device_index': _dev_idx + 1,
                      'device_total': _total_this_round,
                      'classified': _total_classified,
                      'avg_device_time': round(_avg_time, 1),
                      'eta_seconds': _eta_seconds,
                      'stage_detail': 'profiling'})

                # Find matching MAC for this IP (if known)
                _dev_mac = None
                for n in unprofiled_nodes:
                    if n.ip == _dev_ip and n.mac_address:
                        _dev_mac = n.mac_address
                        break
                _dev_macs = {_dev_mac} if _dev_mac else set()

                _dev_start = time.time()
                try:
                    result = nm.profile_devices(
                        pipeline.splunk,
                        time_range=profile_time_range,
                        target_ips={_dev_ip},
                        target_macs=_dev_macs,
                    )
                    _dev_elapsed = time.time() - _dev_start
                    _profile_times.append(_dev_elapsed)

                    classified = result.get('classified', 0)
                    _classified_this_round += classified
                    _total_classified += classified

                    if classified:
                        log.info(f'  [{_dev_idx + 1}/{_total_this_round}] '
                                 f'{_dev_ip}: classified ({_dev_elapsed:.1f}s)')
                    else:
                        log.info(f'  [{_dev_idx + 1}/{_total_this_round}] '
                                 f'{_dev_ip}: profiled, not classified '
                                 f'({_dev_elapsed:.1f}s)')

                    # Save after each device so progress is durable
                    # and visible in the UI immediately.
                    nm.merge_enrichment_and_save()

                except Exception as pe:
                    _dev_elapsed = time.time() - _dev_start
                    _profile_times.append(_dev_elapsed)
                    log.warning(f'  [{_dev_idx + 1}/{_total_this_round}] '
                                f'{_dev_ip}: error ({_dev_elapsed:.1f}s) — {pe}')
                    # Continue to next device on failure
                    continue

            log.info(f'Profiling round complete: {_classified_this_round} '
                     f'classified out of {_total_this_round} '
                     f'({_total_classified} total)')
            send('running',
                 f'Profiled {_total_this_round} devices '
                 f'({_classified_this_round} classified) — '
                 f'waiting for new nodes',
                 90, {'pipeline': 'profile', 'unprofiled': 0,
                      'total_nodes': len(nm.nodes),
                      'classified': _total_classified,
                      'time_range': profile_time_range})

            # Wait before next check (30s in 5s increments)
            for _ in range(6):
                if _stop:
                    break
                time.sleep(5)

        send('complete', 'Profile pipeline stopped', 100,
             {'pipeline': 'profile'})
        log.info('Profile pipeline exiting')

    except Exception as e:
        log.error(f'Profile pipeline failed: {e}')
        log.error(traceback.format_exc())
        send('error', f'Profile pipeline failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc(), 'pipeline': 'profile'})


# ---------------------------------------------------------------------------
# HuntManager — lives in the web server process
# ---------------------------------------------------------------------------

class HuntManager:
    """Manages profiling job execution and state.

    Profiling jobs run in non-daemon subprocesses and write progress to
    SQLite.  The manager polls the DB and broadcasts updates to WebSocket
    clients.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self.active_hunts: dict = {}          # job_id -> state dict
        self._monitored_hunts: dict = {}      # job_id -> pid
        self._poll_task: Optional[asyncio.Task] = None
        self._splunk = None
        # Continuous ingestion state — triple pipeline
        self._continuous_id: Optional[str] = None
        self._continuous_pid: Optional[int] = None
        self._data_pipeline_id: Optional[str] = None
        self._data_pipeline_pid: Optional[int] = None
        self._analysis_pipeline_id: Optional[str] = None
        self._analysis_pipeline_pid: Optional[int] = None
        self._profile_pipeline_id: Optional[str] = None
        self._profile_pipeline_pid: Optional[int] = None

    # WebSocket broadcast callback — set by the app at startup
    _broadcast_fn = None

    def get_splunk_connector(self):
        """Get a Splunk connector for API use (e.g. device profiling)."""
        if self._splunk is None:
            cfg = _build_splunk_config()
            pipeline = DataPipeline(cfg)
            self._splunk = pipeline.splunk
        return self._splunk

    # ------------------------------------------------------------------
    # Continuous ingestion
    # ------------------------------------------------------------------

    async def start_continuous(self, interval_minutes: int = 15,
                               lookback_minutes: int = 20,
                               backfill_from: str = None) -> dict:
        """Start continuous ingestion with decoupled data + analysis pipelines."""
        import multiprocessing

        # Check if either pipeline is already running
        if self._data_pipeline_pid and _pid_alive(self._data_pipeline_pid):
            return {
                'status': 'already_running',
                'data_pipeline_id': self._data_pipeline_id,
                'data_pipeline_pid': self._data_pipeline_pid,
                'analysis_pipeline_id': self._analysis_pipeline_id,
                'analysis_pipeline_pid': self._analysis_pipeline_pid,
            }

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        data_job_id = f'datapipe_{ts}'
        analysis_job_id = f'analysis_{ts}'
        # Keep a composite ID for backward compat with frontend
        composite_id = f'continuous_{ts}'
        db_path = self.db.db_path

        # Launch data pipeline process
        data_proc = multiprocessing.Process(
            target=_data_pipeline_process,
            args=(data_job_id, interval_minutes, lookback_minutes,
                  db_path, backfill_from),
            daemon=False,
        )
        data_proc.start()

        # Launch analysis pipeline process
        analysis_proc = multiprocessing.Process(
            target=_analysis_pipeline_process,
            args=(analysis_job_id, db_path),
            daemon=False,
        )
        analysis_proc.start()

        # Launch profile pipeline process
        profile_job_id = f'profpipe_{ts}'
        profile_proc = multiprocessing.Process(
            target=_profile_pipeline_process,
            args=(profile_job_id, db_path),
            daemon=False,
        )
        profile_proc.start()

        # Track all three pipelines
        self._data_pipeline_id = data_job_id
        self._data_pipeline_pid = data_proc.pid
        self._analysis_pipeline_id = analysis_job_id
        self._analysis_pipeline_pid = analysis_proc.pid
        self._profile_pipeline_id = profile_job_id
        self._profile_pipeline_pid = profile_proc.pid

        # Composite tracking for backward compat
        self._continuous_id = composite_id
        self._continuous_pid = data_proc.pid  # primary PID for status checks

        self._monitored_hunts[data_job_id] = data_proc.pid
        self._monitored_hunts[analysis_job_id] = analysis_proc.pid
        self._monitored_hunts[profile_job_id] = profile_proc.pid

        self.active_hunts[data_job_id] = {
            'status': 'running',
            'type': 'data_pipeline',
            'progress': 0,
            'start_time': datetime.now(),
            'interval_minutes': interval_minutes,
            'lookback_minutes': lookback_minutes,
        }
        self.active_hunts[analysis_job_id] = {
            'status': 'running',
            'type': 'analysis_pipeline',
            'progress': 0,
            'start_time': datetime.now(),
        }
        self.active_hunts[profile_job_id] = {
            'status': 'running',
            'type': 'profile_pipeline',
            'progress': 0,
            'start_time': datetime.now(),
        }

        logger.info(
            f'Started pipelines: data={data_job_id} '
            f'(pid {data_proc.pid}), analysis={analysis_job_id} '
            f'(pid {analysis_proc.pid}), profile={profile_job_id} '
            f'(pid {profile_proc.pid}), '
            f'interval={interval_minutes}m, lookback={lookback_minutes}m'
        )
        self._ensure_poll_task()
        return {
            'status': 'started',
            'data_pipeline': {
                'job_id': data_job_id,
                'pid': data_proc.pid,
            },
            'analysis_pipeline': {
                'job_id': analysis_job_id,
                'pid': analysis_proc.pid,
            },
            'profile_pipeline': {
                'job_id': profile_job_id,
                'pid': profile_proc.pid,
            },
            'interval_minutes': interval_minutes,
            'lookback_minutes': lookback_minutes,
        }

    async def stop_continuous(self) -> dict:
        """Stop both data and analysis pipeline processes."""
        pids_to_kill = []

        # Collect all pipeline PIDs and clean up tracking
        for attr_id, attr_pid in [
            ('_data_pipeline_id', '_data_pipeline_pid'),
            ('_analysis_pipeline_id', '_analysis_pipeline_pid'),
            ('_profile_pipeline_id', '_profile_pipeline_pid'),
        ]:
            job_id = getattr(self, attr_id)
            pid = getattr(self, attr_pid)
            if job_id:
                self._monitored_hunts.pop(job_id, None)
                self.db.clear_progress(job_id)
                if job_id in self.active_hunts:
                    self.active_hunts[job_id]['status'] = 'stopped'
                if pid and _pid_alive(pid):
                    pids_to_kill.append(pid)
                setattr(self, attr_id, None)
                setattr(self, attr_pid, None)

        if not pids_to_kill and not self._continuous_id:
            return {'status': 'not_running'}

        composite_id = self._continuous_id
        self._continuous_id = None
        self._continuous_pid = None

        # Broadcast stop
        if self._broadcast_fn:
            await self._broadcast_fn({
                'type': 'continuous_progress',
                'stage': 'complete',
                'message': 'Pipelines stopped by user',
                'progress': 100,
                'hunt_id': composite_id or '',
            })

        # SIGTERM all pipeline processes
        import signal as _sig
        for pid in pids_to_kill:
            try:
                os.kill(pid, _sig.SIGTERM)
            except OSError:
                pass

        # Wait up to 10 seconds for graceful shutdown
        for _ in range(20):
            await asyncio.sleep(0.5)
            if all(not _pid_alive(p) for p in pids_to_kill):
                break

        # Force-kill if still alive
        for pid in pids_to_kill:
            if _pid_alive(pid):
                logger.warning(f'Process {pid} did not respond to SIGTERM, sending SIGKILL')
                try:
                    os.kill(pid, _sig.SIGKILL)
                except OSError:
                    pass

        return {'status': 'stopped'}

    def get_continuous_status(self) -> dict:
        """Return status of all pipelines."""
        data_alive = (self._data_pipeline_pid and
                      _pid_alive(self._data_pipeline_pid))
        analysis_alive = (self._analysis_pipeline_pid and
                          _pid_alive(self._analysis_pipeline_pid))
        profile_alive = (self._profile_pipeline_pid and
                         _pid_alive(self._profile_pipeline_pid))

        if not data_alive and not analysis_alive and not profile_alive:
            if self._data_pipeline_id or self._analysis_pipeline_id:
                # Clean up dead references
                last_data = self._data_pipeline_id
                last_analysis = self._analysis_pipeline_id
                self._data_pipeline_id = None
                self._data_pipeline_pid = None
                self._analysis_pipeline_id = None
                self._analysis_pipeline_pid = None
                self._profile_pipeline_id = None
                self._profile_pipeline_pid = None
                self._continuous_id = None
                self._continuous_pid = None
                return {'running': False,
                        'last_data_pipeline': last_data,
                        'last_analysis_pipeline': last_analysis}
            return {'running': False}

        def _get_pipeline_info(job_id, pid, pipeline_type):
            state = self.active_hunts.get(job_id, {})
            last_progress = state.get('last_progress') or {}
            extra = last_progress.get('data', {}) or {}
            if isinstance(extra, str):
                try:
                    import json
                    extra = json.loads(extra)
                except Exception:
                    extra = {}
            return {
                'running': _pid_alive(pid) if pid else False,
                'job_id': job_id,
                'pid': pid,
                'message': last_progress.get('message', ''),
                'cycle': extra.get('cycle', 0),
                'total_nodes': extra.get('total_nodes', 0),
                'stage_detail': extra.get('stage_detail', ''),
                'findings': extra.get('findings', 0),
                'analyses_completed': extra.get('analyses_completed', 0),
                # Detailed fields for per-pipeline cards
                'last_progress': extra,
            }

        data_info = _get_pipeline_info(
            self._data_pipeline_id, self._data_pipeline_pid, 'data')
        analysis_info = _get_pipeline_info(
            self._analysis_pipeline_id, self._analysis_pipeline_pid, 'analysis')
        profile_info = _get_pipeline_info(
            self._profile_pipeline_id, self._profile_pipeline_pid, 'profile')

        # Get analysis queue status for the frontend
        try:
            queue_status = self.db.get_analysis_queue_status()
        except Exception:
            queue_status = {}

        # Backward compat fields
        data_state = self.active_hunts.get(self._data_pipeline_id, {})
        return {
            'running': True,
            'job_id': self._continuous_id,
            'data_pipeline': data_info,
            'analysis_pipeline': analysis_info,
            'profile_pipeline': profile_info,
            'analysis_queue': queue_status,
            'interval_minutes': data_state.get('interval_minutes', 15),
            'lookback_minutes': data_state.get('lookback_minutes', 20),
            # Backward compat
            'pid': self._data_pipeline_pid,
            'message': data_info.get('message', ''),
            'cycle': data_info.get('cycle', 0),
            'total_nodes': data_info.get('total_nodes', 0),
        }

    # ------------------------------------------------------------------
    # Cancel a running job
    # ------------------------------------------------------------------

    async def cancel_hunt(self, hunt_id: str) -> dict:
        """Cancel a running profile by killing its subprocess.

        Returns a status dict with 'cancelled' or 'error' status.
        """
        pid = self._monitored_hunts.get(hunt_id)
        if not pid:
            return {'status': 'error', 'message': f'{hunt_id} is not running'}

        if not _pid_alive(pid):
            # Already dead — clean up state
            self._monitored_hunts.pop(hunt_id, None)
            if hunt_id in self.active_hunts:
                self.active_hunts[hunt_id]['status'] = 'cancelled'
            self.db.clear_progress(hunt_id)
            return {'status': 'cancelled', 'hunt_id': hunt_id, 'was': 'dead'}

        # Send SIGTERM for graceful shutdown, then SIGKILL if needed
        logger.info(f"Cancelling {hunt_id} (pid {pid}) — sending SIGTERM")
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            logger.warning(f"SIGTERM failed for pid {pid}: {e}")

        # Give it a moment to die
        import asyncio
        for _ in range(10):  # 2 seconds total
            await asyncio.sleep(0.2)
            if not _pid_alive(pid):
                break
        else:
            # Still alive — force kill
            logger.warning(f"{hunt_id} (pid {pid}) didn't respond to SIGTERM, sending SIGKILL")
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError as e:
                logger.warning(f"SIGKILL failed for pid {pid}: {e}")

        # Clean up tracking state
        self._monitored_hunts.pop(hunt_id, None)
        if hunt_id in self.active_hunts:
            self.active_hunts[hunt_id]['status'] = 'cancelled'
        self.db.clear_progress(hunt_id)

        # Clear profile tracking if this was the active profile
        if hunt_id == self._profile_id:
            self._profile_pid = None

        # Broadcast the cancellation to WS clients
        if self._broadcast_fn:
            is_bg_profile = hunt_id.startswith('bgprofile_')
            msg_type = 'bg_profile_progress' if is_bg_profile else 'profile_progress'
            await self._broadcast_fn({
                'type': msg_type,
                'hunt_id': hunt_id,
                'stage': 'cancelled',
                'message': 'Profiling was cancelled.',
                'progress': 0,
            })

        logger.info(f"Cancelled {hunt_id} (pid {pid})")
        return {'status': 'cancelled', 'hunt_id': hunt_id}

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
    # Background profiling (continuous per-device)
    # ------------------------------------------------------------------

    _bg_profile_id: Optional[str] = None
    _bg_profile_pid: Optional[int] = None

    async def start_background_profile(self, time_range: str = "-24h",
                                        num_workers: int = 1) -> str:
        """Launch background per-device profiling in a subprocess."""
        import multiprocessing

        # Don't allow if batch profiling is already running
        if self._profile_id and self._profile_pid and _pid_alive(self._profile_pid):
            raise RuntimeError("Batch profiling is already running")

        # Don't allow if bg profiling is already running
        if (self._bg_profile_id and self._bg_profile_pid
                and _pid_alive(self._bg_profile_pid)):
            raise RuntimeError(
                f"Profiling already running ({self._bg_profile_id})"
            )

        # Cap workers to reasonable range
        num_workers = max(1, min(num_workers, 32))

        profile_id = f"bgprofile_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        proc = multiprocessing.Process(
            target=_bg_profile_worker_process,
            args=(profile_id, time_range, num_workers, self.db.db_path),
            daemon=False,
        )
        proc.start()

        self._bg_profile_id = profile_id
        self._bg_profile_pid = proc.pid
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
            f'{num_workers} workers, time_range={time_range})'
        )
        self._ensure_poll_task()
        return profile_id

    def get_bg_profile_status(self) -> dict:
        """Return the current background profiling state for the UI."""
        pid = self._bg_profile_id
        if not pid:
            return {'running': False}

        state = self.active_hunts.get(pid, {})
        status = state.get('status', 'unknown')
        if status not in ('running',) and not (
            self._bg_profile_pid and _pid_alive(self._bg_profile_pid)
        ):
            return {'running': False, 'last_profile_id': pid}

        row = state.get('last_progress') or {}
        extra = row.get('data', {}) or {}
        return {
            'running': True,
            'profile_id': pid,
            'progress': state.get('progress', 0),
            'stage': row.get('stage', 'init'),
            'message': row.get('message', 'Running...'),
            'total': extra.get('total', 0),
            'profiled': extra.get('profiled', 0),
            'newly_profiled': extra.get('newly_profiled', 0),
            'failed': extra.get('failed', 0),
        }

    async def stop_background_profile(self) -> dict:
        """Stop the running background profile process."""
        pid = self._bg_profile_pid
        profile_id = self._bg_profile_id

        if not pid or not profile_id:
            return {'status': 'error', 'error': 'No profiling running'}

        if not _pid_alive(pid):
            self._bg_profile_pid = None
            return {'status': 'error', 'error': 'Process already exited'}

        try:
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to bg profile pid {pid}")
            # Give it a moment to clean up
            for _ in range(10):
                await asyncio.sleep(0.5)
                if not _pid_alive(pid):
                    break
            else:
                # Force kill if still alive
                os.kill(pid, signal.SIGKILL)
                logger.warning(f"Force killed bg profile pid {pid}")
        except ProcessLookupError:
            pass

        self._bg_profile_pid = None

        # Update state
        if profile_id in self.active_hunts:
            self.active_hunts[profile_id]['status'] = 'cancelled'
        self.db.clear_progress(profile_id)
        self._monitored_hunts.pop(profile_id, None)

        # Broadcast cancellation
        if self._broadcast_fn:
            await self._broadcast_fn({
                'type': 'bg_profile_progress',
                'stage': 'cancelled',
                'message': 'Profiling stopped by user',
                'progress': 0,
                'hunt_id': profile_id,
            })

        return {'status': 'stopped', 'profile_id': profile_id}

    # ------------------------------------------------------------------
    # Kill all child processes (server shutdown helper)
    # ------------------------------------------------------------------

    def kill_all_processes(self) -> dict:
        """Kill every tracked child process (SIGTERM then SIGKILL).

        Returns a summary dict with counts.  This is synchronous so it
        can be called right before the server exits.
        """
        killed = []
        already_dead = []

        # Collect every PID we know about
        all_pids: dict[int, str] = {}  # pid -> label

        for hunt_id, pid in list(self._monitored_hunts.items()):
            all_pids[pid] = hunt_id

        for attr, label in [
            ('_data_pipeline_pid', 'data_pipeline'),
            ('_analysis_pipeline_pid', 'analysis_pipeline'),
            ('_profile_pipeline_pid', 'profile_pipeline'),
            ('_continuous_pid', 'continuous'),
            ('_profile_pid', 'profile'),
            ('_bg_profile_pid', 'bg_profile'),
        ]:
            pid = getattr(self, attr, None)
            if pid and pid not in all_pids:
                all_pids[pid] = label

        # SIGTERM everything first
        for pid in all_pids:
            if _pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass

        # Wait briefly for graceful shutdown
        deadline = _time.monotonic() + 5.0
        while _time.monotonic() < deadline:
            if all(not _pid_alive(p) for p in all_pids):
                break
            _time.sleep(0.25)

        # SIGKILL anything still alive, tally results
        for pid, label in all_pids.items():
            if _pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                killed.append({'pid': pid, 'label': label, 'method': 'SIGKILL'})
            else:
                killed.append({'pid': pid, 'label': label, 'method': 'SIGTERM'})

        # Clear all internal tracking
        self._monitored_hunts.clear()
        self.active_hunts.clear()
        self._continuous_id = None
        self._continuous_pid = None
        self._data_pipeline_id = None
        self._data_pipeline_pid = None
        self._analysis_pipeline_id = None
        self._analysis_pipeline_pid = None
        self._profile_pipeline_id = None
        self._profile_pipeline_pid = None
        self._profile_id = None
        self._profile_pid = None
        self._bg_profile_id = None
        self._bg_profile_pid = None

        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()

        logger.info(f"kill_all_processes: terminated {len(killed)} child process(es)")
        return {
            'killed': len(killed),
            'processes': killed,
        }

    # ------------------------------------------------------------------
    # Progress polling loop
    # ------------------------------------------------------------------

    def _ensure_poll_task(self):
        """Start the progress-polling background task if it isn't running."""
        if self._poll_task is None or self._poll_task.done():
            self._poll_task = asyncio.ensure_future(self._poll_progress())

    async def _poll_progress(self):
        """Poll progress table and broadcast updates to WebSocket clients."""
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
                        is_bg_profile = hunt_id.startswith('bgprofile_')
                        is_data_pipe = hunt_id.startswith('datapipe_')
                        is_analysis_pipe = hunt_id.startswith('analysis_')
                        is_profile_pipe = hunt_id.startswith('profpipe_')
                        is_continuous = (hunt_id.startswith('continuous_')
                                         or is_data_pipe or is_analysis_pipe
                                         or is_profile_pipe)
                        msg_type = ('continuous_progress' if is_continuous
                                    else 'bg_profile_progress' if is_bg_profile
                                    else 'profile_progress')
                        msg = {
                            'type': msg_type,
                            'stage': row['stage'],
                            'message': row['message'],
                            'progress': row['progress'],
                            'hunt_id': hunt_id,
                        }
                        if row.get('data'):
                            msg['result'] = row['data']
                        # Add pipeline identifier BEFORE broadcasting
                        if is_data_pipe:
                            msg['pipeline'] = 'data'
                        elif is_analysis_pipe:
                            msg['pipeline'] = 'analysis'
                        elif is_profile_pipe:
                            msg['pipeline'] = 'profile'
                        await self._broadcast_fn(msg)

                    # For continuous pipelines, reload the map from disk
                    # periodically so the API serves up-to-date graph data.
                    # Triggers on cycle/node-count/classified changes,
                    # throttled to at most once per 30 seconds per pipeline.
                    if is_continuous and row['stage'] == 'running':
                        data = row.get('data') or {}
                        if not isinstance(data, dict):
                            data = {}
                        # Build a fingerprint of relevant state
                        cur_fp = (
                            data.get('cycle', 0),
                            data.get('total_nodes', 0),
                            data.get('classified', 0),
                            data.get('unprofiled', 0),
                        )

                        prev_key = f'_last_reload_{hunt_id}'
                        prev_fp, prev_ts = getattr(
                            self, prev_key, ((0, 0, 0, 0), 0))

                        now_ts = _time.time()
                        state_changed = cur_fp != prev_fp and any(cur_fp)
                        if state_changed and (now_ts - prev_ts) > 30:
                            setattr(self, prev_key, (cur_fp, now_ts))
                            try:
                                plugin_manager.reload_from_disk(
                                    ['network_mapper']
                                )
                            except Exception:
                                pass

                    # Terminal states
                    if row['stage'] in ('complete', 'error'):
                        status = 'completed' if row['stage'] == 'complete' else 'failed'
                        if hunt_id in self.active_hunts:
                            self.active_hunts[hunt_id]['status'] = status
                        self.db.clear_progress(hunt_id)
                        plugin_manager.reload_from_disk(
                            ['network_mapper', 'sigma_engine']
                        )
                        # Clear tracking for finished jobs
                        if hunt_id == self._profile_id:
                            self._profile_pid = None
                        if hunt_id == self._bg_profile_id:
                            self._bg_profile_pid = None
                        if hunt_id == self._data_pipeline_id:
                            self._data_pipeline_pid = None
                        if hunt_id == self._analysis_pipeline_id:
                            self._analysis_pipeline_pid = None
                        if hunt_id == self._continuous_id:
                            self._continuous_id = None
                            self._continuous_pid = None
                        finished.append(hunt_id)
                    elif not _pid_alive(pid):
                        # Process died without writing terminal state
                        logger.warning(
                            f'Job {hunt_id} subprocess (pid {pid}) '
                            f'exited without completing'
                        )
                        if hunt_id in self.active_hunts:
                            self.active_hunts[hunt_id]['status'] = 'failed'
                        self.db.clear_progress(hunt_id)

                        # Auto-restart the analysis pipeline if it
                        # crashed and there is still work to process.
                        if hunt_id == self._analysis_pipeline_id:
                            self._analysis_pipeline_pid = None
                            pending = self.db.get_pending_analysis()
                            if pending or (
                                self._data_pipeline_pid
                                and _pid_alive(self._data_pipeline_pid)
                            ):
                                logger.warning(
                                    'Analysis pipeline crashed — restarting'
                                )
                                import multiprocessing as _mp
                                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                                new_job = f'analysis_{ts}'
                                proc = _mp.Process(
                                    target=_analysis_pipeline_process,
                                    args=(new_job, self.db.db_path),
                                    daemon=False,
                                )
                                proc.start()
                                self._analysis_pipeline_id = new_job
                                self._analysis_pipeline_pid = proc.pid
                                self._monitored_hunts[new_job] = proc.pid
                                self.active_hunts[new_job] = {
                                    'status': 'running',
                                    'type': 'analysis_pipeline',
                                    'progress': 0,
                                    'start_time': datetime.now(),
                                }
                                logger.info(
                                    f'Restarted analysis pipeline: '
                                    f'{new_job} (pid {proc.pid})'
                                )
                                # Don't remove old hunt_id from monitored
                                # — it's dead and will be cleaned below.

                        finished.append(hunt_id)

                for hid in finished:
                    self._monitored_hunts.pop(hid, None)

                await asyncio.sleep(0.5)

                if not self._monitored_hunts:
                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f'Progress polling error: {e}')

    # ------------------------------------------------------------------
    # Reconnect to jobs that survived a server restart
    # ------------------------------------------------------------------

    def reconnect_running_jobs(self):
        """Called at startup.  Finds profiling jobs that are still running
        from before a server restart and resumes monitoring them."""
        rows = self.db.get_all_running_progress()
        reconnected = 0

        for row in rows:
            hunt_id = row['hunt_id']
            pid = row['pid']

            if _pid_alive(pid):
                logger.info(
                    f'Reconnecting to running profile {hunt_id} (pid {pid})'
                )
                self._monitored_hunts[hunt_id] = pid
                self.active_hunts[hunt_id] = {
                    'status': 'running',
                    'progress': row.get('progress', 0),
                    'start_time': row.get('updated_at', datetime.now()),
                    'collection_stats': {},
                    'last_progress': row,
                }
                # Restore job tracking
                if hunt_id.startswith('profile_'):
                    self._profile_id = hunt_id
                    self._profile_pid = pid
                elif hunt_id.startswith('bgprofile_'):
                    self._bg_profile_id = hunt_id
                    self._bg_profile_pid = pid
                elif hunt_id.startswith('datapipe_'):
                    self._data_pipeline_id = hunt_id
                    self._data_pipeline_pid = pid
                    ts = hunt_id.replace('datapipe_', '')
                    self._continuous_id = f'continuous_{ts}'
                    self._continuous_pid = pid
                elif hunt_id.startswith('analysis_'):
                    self._analysis_pipeline_id = hunt_id
                    self._analysis_pipeline_pid = pid
                elif hunt_id.startswith('profpipe_'):
                    self._profile_pipeline_id = hunt_id
                    self._profile_pipeline_pid = pid
                elif hunt_id.startswith('continuous_'):
                    self._continuous_id = hunt_id
                    self._continuous_pid = pid
                reconnected += 1
            else:
                logger.warning(
                    f'Job {hunt_id} subprocess (pid {pid}) is no longer '
                    f'alive — marking as stopped'
                )
                # Mark as complete instead of deleting so the frontend
                # can still display the last known stats (classified count, etc.)
                self.db.write_progress(
                    hunt_id, pid, 'complete',
                    'Pipeline stopped (process exited)',
                    row.get('progress', 0),
                    row.get('data'),
                )

        if reconnected:
            logger.info(f'Reconnected to {reconnected} running job(s)')
            self._ensure_poll_task()


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


def _kill_pid(pid: int, timeout: float = 5.0) -> bool:
    """Send SIGTERM then SIGKILL to a PID. Returns True if process was killed."""
    if not _pid_alive(pid):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    # Wait for graceful shutdown
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        _time.sleep(0.2)
    # Force kill
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return True
