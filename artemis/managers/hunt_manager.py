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

        # Get the latest cycle number from DB to continue sequentially
        cycle = db.get_latest_event_cycle()
        time_range = f'-{lookback_minutes}m'
        _backfill_pending = bool(backfill_from)

        while not _stop:
            cycle += 1
            cycle_start = datetime.now()

            if _backfill_pending:
                _backfill_pending = False
                bf_start = backfill_from
                bf_end = datetime.now().isoformat()
                log.info(f'Cycle {cycle}: backfill from {bf_start} to now')
                send('running',
                     f'Cycle {cycle}: backfilling from {bf_start}...',
                     25, {'cycle': cycle, 'pipeline': 'data',
                          'interval': interval_minutes,
                          'lookback': lookback_minutes,
                          'backfill_from': bf_start})
            else:
                log.info(f'Cycle {cycle}: collecting last {lookback_minutes}m')
                send('running',
                     f'Cycle {cycle}: collecting data (last {lookback_minutes}m)...',
                     50, {'cycle': cycle, 'pipeline': 'data',
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
                        send('running',
                             f'Cycle {cycle}: fetched window {w}/{tw} '
                             f'({rt:,} events)...',
                             25 + int(30 * w / max(tw, 1)),
                             {'cycle': cycle, 'pipeline': 'data',
                              'stage_detail': 'splunk_fetch',
                              'window': w, 'total_windows': tw,
                              'running_total': rt})
                    elif ptype == 'query_done':
                        log.info(f'Cycle {cycle}: query {info.get("query_name")} '
                                 f'returned {info.get("query_events", 0):,} events')

                # Collect from Splunk
                if bf_start:
                    _bf_windows_mapped = [0]
                    _bf_total_events = [0]

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
                            _bf_total_events[0] += len(conns) + len(dns_q) + len(ntlm_l)

                            # Store events in persistent store
                            if conns:
                                db.store_events(cycle, 'network_connections', conns)
                            if dns_q:
                                db.store_events(cycle, 'dns_queries', dns_q)
                            if ntlm_l:
                                db.store_events(cycle, 'ntlm_logs', ntlm_l)

                            # Store other data types
                            for key in ('authentication_logs', 'process_logs',
                                        'powershell_logs', 'file_operations',
                                        'scheduled_tasks', 'registry_changes'):
                                events = window_data.get(key, [])
                                if events:
                                    db.store_events(cycle, key, events)

                            if _bf_windows_mapped[0] % 3 == 0:
                                nm.save_map()
                                send('running',
                                     f'Cycle {cycle}: backfill — mapped '
                                     f'{_bf_windows_mapped[0]} windows '
                                     f'({_bf_total_events[0]:,} events, '
                                     f'{len(nm.nodes)} nodes)...',
                                     30, {'cycle': cycle, 'pipeline': 'data',
                                          'stage_detail': 'backfill_mapping',
                                          'total_nodes': len(nm.nodes),
                                          'total_events': _bf_total_events[0]})

                    hunting_data = pipeline.collect_hunting_data(
                        earliest_time=bf_start,
                        latest_time=bf_end,
                        storage_mode='sqlite',
                        progress_callback=_splunk_progress,
                        per_window_callback=_map_window,
                    )
                    if _bf_windows_mapped[0] > 0:
                        nm.save_map()

                    conn_count = hunting_data.count('network_connections') if hasattr(hunting_data, 'count') else 0
                    dns_count = hunting_data.count('dns_queries') if hasattr(hunting_data, 'count') else 0
                    ntlm_count = hunting_data.count('ntlm_logs') if hasattr(hunting_data, 'count') else 0
                    has_data = (conn_count + dns_count + ntlm_count) > 0

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

                    # Auto-profile unprofiled devices
                    try:
                        stats = nm.get_profiling_stats()
                        unprofiled = stats.get('unprofiled', 0)
                        if unprofiled > 0:
                            log.info(f'Cycle {cycle}: auto-profiling '
                                     f'{unprofiled} devices')
                            profile_result = nm.profile_devices(
                                pipeline.splunk,
                                time_range=f'-{lookback_minutes}m',
                            )
                            nm.save_map()
                    except Exception as pe:
                        log.warning(f'Cycle {cycle}: auto-profile error: {pe}')

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
                         {'cycle': cycle, 'pipeline': 'data'})

            except Exception as e:
                log.error(f'Cycle {cycle} error: {e}')
                log.error(traceback.format_exc())
                send('running', f'Cycle {cycle} error: {e}', 50,
                     {'cycle': cycle, 'pipeline': 'data',
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
    from datetime import datetime
    from artemis.managers.db_manager import DatabaseManager
    from artemis.plugins.network_mapper import NetworkMapperPlugin
    from artemis.meta_learner.coordinator import MetaLearnerCoordinator
    from artemis.models.network_state import NetworkState

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.analysis_pipeline')

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

    send('running', 'Starting analysis pipeline...', 0)

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
                        num_ctx=int(os.environ.get('OLLAMA_NUM_CTX', '131072')),
                    )
                    log.info('CrewAI orchestrator initialised')
            except Exception as _ce:
                log.warning(f'CrewAI init failed: {_ce}')

        analyses_completed = 0

        while not _stop:
            # Poll for pending analysis
            pending = db.get_pending_analysis()

            if not pending:
                # Nothing to analyze — sleep briefly and check again
                send('running',
                     f'Waiting for data (analyzed {analyses_completed} cycles)...',
                     50, {'pipeline': 'analysis',
                          'analyses_completed': analyses_completed,
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
                      'stage_detail': 'llm_analysis',
                      'orchestration': 'crewai' if _crew_orchestrator else 'standard'})

            findings_count = 0
            try:
                # Load events from persistent store
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

                # Run analysis
                if _crew_orchestrator:
                    assessment = _crew_orchestrator.hunt(
                        data=agent_data, network_state=context)
                else:
                    assessment = coordinator.hunt(
                        data=agent_data, network_state=context)

                # Save findings
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
                            recommended_actions=ao_dict.get('recommended_actions', []),
                            source_cycle=analysis_cycle,
                        )

                # Persist LLM synthesis
                llm_synth = assessment.get('llm_synthesis')
                if llm_synth:
                    try:
                        db.save_synthesis(analysis_cycle, llm_synth)
                        log.info(f'Cycle {analysis_cycle}: saved LLM synthesis '
                                 f'(severity={llm_synth.get("overall_severity", "?")})')
                    except Exception as se:
                        log.error(f'Failed to save LLM synthesis: {se}')

                db.mark_analysis_complete(analysis_cycle)
                analyses_completed += 1

                msg = (f'Cycle {analysis_cycle} analyzed: '
                       f'{findings_count} findings from {total_events:,} events')
                log.info(msg)
                send('running', msg, 50,
                     {'pipeline': 'analysis',
                      'cycle': analysis_cycle,
                      'findings': findings_count,
                      'analyses_completed': analyses_completed})

            except Exception as ae:
                log.error(f'Analysis cycle {analysis_cycle} error: {ae}')
                log.error(traceback.format_exc())
                db.mark_analysis_complete(analysis_cycle)  # Don't retry
                send('running',
                     f'Cycle {analysis_cycle} analysis error: {ae}', 50,
                     {'pipeline': 'analysis', 'cycle': analysis_cycle,
                      'error': str(ae)})

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
        # Continuous ingestion state — dual pipeline
        self._continuous_id: Optional[str] = None
        self._continuous_pid: Optional[int] = None
        self._data_pipeline_id: Optional[str] = None
        self._data_pipeline_pid: Optional[int] = None
        self._analysis_pipeline_id: Optional[str] = None
        self._analysis_pipeline_pid: Optional[int] = None

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

        # Track both pipelines
        self._data_pipeline_id = data_job_id
        self._data_pipeline_pid = data_proc.pid
        self._analysis_pipeline_id = analysis_job_id
        self._analysis_pipeline_pid = analysis_proc.pid

        # Composite tracking for backward compat
        self._continuous_id = composite_id
        self._continuous_pid = data_proc.pid  # primary PID for status checks

        self._monitored_hunts[data_job_id] = data_proc.pid
        self._monitored_hunts[analysis_job_id] = analysis_proc.pid

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

        logger.info(
            f'Started decoupled pipelines: data={data_job_id} '
            f'(pid {data_proc.pid}), analysis={analysis_job_id} '
            f'(pid {analysis_proc.pid}), '
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
        """Return status of both pipelines."""
        data_alive = (self._data_pipeline_pid and
                      _pid_alive(self._data_pipeline_pid))
        analysis_alive = (self._analysis_pipeline_pid and
                          _pid_alive(self._analysis_pipeline_pid))

        if not data_alive and not analysis_alive:
            if self._data_pipeline_id or self._analysis_pipeline_id:
                # Clean up dead references
                last_data = self._data_pipeline_id
                last_analysis = self._analysis_pipeline_id
                self._data_pipeline_id = None
                self._data_pipeline_pid = None
                self._analysis_pipeline_id = None
                self._analysis_pipeline_pid = None
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
            }

        data_info = _get_pipeline_info(
            self._data_pipeline_id, self._data_pipeline_pid, 'data')
        analysis_info = _get_pipeline_info(
            self._analysis_pipeline_id, self._analysis_pipeline_pid, 'analysis')

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
                        is_continuous = (hunt_id.startswith('continuous_')
                                         or is_data_pipe or is_analysis_pipe)
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
                        await self._broadcast_fn(msg)

                    # For continuous ingestion, reload the map from disk
                    # periodically so the API serves up-to-date graph data.
                    if is_continuous and row['stage'] == 'running':
                        data = row.get('data') or {}
                        cur_cycle = data.get('cycle', 0) if isinstance(data, dict) else 0
                        last_key = f'_last_reload_cycle_{hunt_id}'
                        prev_cycle = getattr(self, last_key, 0)
                        if cur_cycle and cur_cycle != prev_cycle:
                            setattr(self, last_key, cur_cycle)
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
                elif hunt_id.startswith('continuous_'):
                    self._continuous_id = hunt_id
                    self._continuous_pid = pid
                reconnected += 1
            else:
                logger.warning(
                    f'Job {hunt_id} subprocess (pid {pid}) is no longer '
                    f'alive — marking as failed'
                )
                self.db.clear_progress(hunt_id)

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
