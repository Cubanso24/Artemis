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
            send('error', 'No internal devices found. Build a network map first.', 0)
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

        # Final save
        nm.save_map()

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
# Continuous ingestion worker — runs in its own process, loops forever
# ---------------------------------------------------------------------------

def _continuous_ingest_process(job_id, interval_minutes, lookback_minutes,
                               db_path, backfill_from=None):
    """Continuously collect network data and update the map.

    Runs in a non-daemon subprocess that survives server restarts.
    Every *interval_minutes* it queries Splunk for the last
    *lookback_minutes* of data and feeds it into the network mapper's
    ``execute()`` method, which builds/updates the live network map.

    If *backfill_from* is set (ISO 8601 date string), the first cycle
    pulls all data from that date to now using absolute time ranges
    (the data pipeline auto-splits into 1-hour windows and uses
    SQLite storage to avoid memory exhaustion).

    The process writes its state to the ``hunt_progress`` table so the
    server can track it and broadcast updates via WebSocket.
    """
    import os, logging, traceback, json, time, signal as _signal
    from datetime import datetime
    from artemis.managers.db_manager import DatabaseManager
    from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
    from artemis.plugins.network_mapper import NetworkMapperPlugin
    from artemis.meta_learner.coordinator import MetaLearnerCoordinator
    from artemis.models.network_state import NetworkState

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    log = logging.getLogger('artemis.continuous_ingest')

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

    send('running', 'Starting continuous ingestion...', 0)

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

        # Initialize hunting agent coordinator.
        # Read LLM settings: GUI config file > environment variables > auto.
        _llm_cfg = {}
        _llm_cfg_path = os.path.join('config', 'llm_settings.json')
        if os.path.exists(_llm_cfg_path):
            try:
                import json as _json
                with open(_llm_cfg_path) as _f:
                    _llm_cfg = _json.load(_f)
                log.info(f'Loaded LLM config from {_llm_cfg_path}: '
                         f'backend={_llm_cfg.get("backend", "auto")}')
            except Exception as _e:
                log.warning(f'Could not read LLM config: {_e}')

        _llm_backend = _llm_cfg.get('backend') or os.environ.get('LLM_BACKEND', 'auto')
        # Push config values into env so LLMClient picks them up
        if _llm_cfg.get('ollama_url'):
            os.environ['OLLAMA_URL'] = _llm_cfg['ollama_url']
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

        # Try to initialise CrewAI orchestrator (optional overlay)
        _crew_orchestrator = None
        _use_crewai = _llm_cfg.get('orchestration') == 'crewai'
        if _use_crewai:
            try:
                from artemis.llm.crew import CrewOrchestrator, crewai_available
                if crewai_available():
                    _ollama_model = _llm_cfg.get('ollama_model') or os.environ.get('OLLAMA_MODEL', 'llama3.1')
                    _crew_orchestrator = CrewOrchestrator(
                        detectors=coordinator.agents,
                        rag_store=getattr(coordinator, 'rag_store', None),
                        llm_model=f"ollama/{_ollama_model}",
                        process=_llm_cfg.get('crewai_process', 'sequential'),
                    )
                    log.info('CrewAI orchestrator initialised — will use CrewAI for hunt cycles')
                else:
                    log.warning('CrewAI requested but crewai package not installed — falling back to standard coordinator')
            except Exception as _ce:
                log.warning(f'CrewAI init failed: {_ce} — falling back to standard coordinator')

        cycle = 0
        time_range = f'-{lookback_minutes}m'
        _backfill_pending = bool(backfill_from)

        while not _stop:
            cycle += 1
            cycle_start = datetime.now()

            # First cycle with backfill: pull all data from the start
            # date to now using absolute time ranges + sqlite storage.
            if _backfill_pending:
                _backfill_pending = False
                bf_start = backfill_from
                bf_end = datetime.now().isoformat()
                log.info(f'Cycle {cycle}: backfill from {bf_start} to now')
                send('running',
                     f'Cycle {cycle}: backfilling from {bf_start} '
                     f'(auto-windowed, may take a while)...',
                     25, {'cycle': cycle, 'interval': interval_minutes,
                          'lookback': lookback_minutes,
                          'backfill_from': bf_start})
            else:
                log.info(f'Cycle {cycle}: collecting last {lookback_minutes}m of data')
                send('running',
                     f'Cycle {cycle}: collecting data (last {lookback_minutes}m)...',
                     50, {'cycle': cycle, 'interval': interval_minutes,
                          'lookback': lookback_minutes})
                bf_start = None
                bf_end = None

            findings_this_cycle = 0
            try:
                # Progress callback relays Splunk fetch progress to the UI
                def _splunk_progress(info):
                    ptype = info.get('type', '')
                    if ptype == 'window_done':
                        w = info.get('window', '?')
                        tw = info.get('total_windows', '?')
                        rt = info.get('running_total', 0)
                        send('running',
                             f'Cycle {cycle}: fetched window {w}/{tw} '
                             f'({rt:,} events so far)...',
                             25 + int(30 * w / max(tw, 1)),
                             {'cycle': cycle, 'stage_detail': 'splunk_fetch',
                              'window': w, 'total_windows': tw,
                              'running_total': rt})
                    elif ptype == 'query_done':
                        qn = info.get('query_name', '')
                        qc = info.get('query_events', 0)
                        log.info(f'Cycle {cycle}: query {qn} returned {qc:,} events')

                if bf_start:
                    # Build network map incrementally as each 1-hour
                    # window completes, so the map appears in the UI
                    # while backfill is still running.
                    _bf_windows_mapped = [0]

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
                            # Save map periodically so UI can see progress
                            if _bf_windows_mapped[0] % 3 == 0:
                                nm.save_map()
                                send('running',
                                     f'Cycle {cycle}: backfill — mapped '
                                     f'{_bf_windows_mapped[0]} windows so far '
                                     f'({len(nm.nodes)} nodes)...',
                                     30, {'cycle': cycle,
                                          'stage_detail': 'backfill_mapping',
                                          'total_nodes': len(nm.nodes)})

                    hunting_data = pipeline.collect_hunting_data(
                        earliest_time=bf_start,
                        latest_time=bf_end,
                        storage_mode='sqlite',
                        progress_callback=_splunk_progress,
                        per_window_callback=_map_window,
                    )
                    # Final save after all windows
                    if _bf_windows_mapped[0] > 0:
                        nm.save_map()
                        log.info(f'Backfill: incrementally mapped '
                                 f'{_bf_windows_mapped[0]} windows → '
                                 f'{len(nm.nodes)} nodes')
                else:
                    hunting_data = pipeline.collect_hunting_data(
                        time_range=time_range)

                # ---------------------------------------------------------
                # Decide whether to stream or materialise events.
                # SqliteEventStore (backfill) can hold tens of millions
                # of events — materialising them all into Python lists
                # at once would exhaust RAM.  Instead, stream them into
                # the network mapper and pass only event *counts* and a
                # manageable sample to the coordinator / agents.
                # ---------------------------------------------------------
                _is_sqlite = hasattr(hunting_data, 'iter_events')

                if _is_sqlite:
                    conn_count = hunting_data.count('network_connections')
                    dns_count = hunting_data.count('dns_queries')
                    ntlm_count = hunting_data.count('ntlm_logs')
                    has_data = (conn_count + dns_count + ntlm_count) > 0
                else:
                    conns = hunting_data.get('network_connections', [])
                    dns = hunting_data.get('dns_queries', [])
                    ntlm = hunting_data.get('ntlm_logs', [])
                    conn_count, dns_count, ntlm_count = len(conns), len(dns), len(ntlm)
                    has_data = bool(conns or dns or ntlm)

                if has_data:
                    # -- Feed network mapper (streaming if SQLite) --
                    if _is_sqlite:
                        total_events = conn_count + dns_count + ntlm_count
                        log.info(f'Cycle {cycle}: streaming {conn_count} conns, '
                                 f'{dns_count} DNS, {ntlm_count} NTLM into network mapper')
                        send('running',
                             f'Cycle {cycle}: building network map from '
                             f'{total_events:,} events...',
                             55, {'cycle': cycle, 'stage_detail': 'network_mapper',
                                  'total_events': total_events})
                        result = nm.execute(
                            network_connections=hunting_data.iter_events('network_connections'),
                            dns_queries=hunting_data.iter_events('dns_queries'),
                            ntlm_logs=hunting_data.iter_events('ntlm_logs'),
                        )
                    else:
                        result = nm.execute(
                            network_connections=conns,
                            dns_queries=dns,
                            ntlm_logs=ntlm,
                        )
                    nm.save_map()

                    # Build a lightweight data dict for the coordinator
                    # and agents.  With millions of events the agents
                    # cannot usefully inspect every row — they operate on
                    # patterns.  We provide counts and a sample so the
                    # LLM hypothesis generation and rule-based agents can
                    # still function.
                    _SAMPLE = 50_000
                    if _is_sqlite:
                        agent_data = {
                            'network_connections': list(
                                hunting_data.iter_events('network_connections', limit=_SAMPLE)
                            ) if conn_count else [],
                            'dns_queries': list(
                                hunting_data.iter_events('dns_queries', limit=_SAMPLE)
                            ) if dns_count else [],
                            'ntlm_logs': list(
                                hunting_data.iter_events('ntlm_logs', limit=_SAMPLE)
                            ) if ntlm_count else [],
                            'ids_alerts': list(
                                hunting_data.iter_events('ids_alerts', limit=_SAMPLE)
                            ) if hunting_data.count('ids_alerts') else [],
                            # Preserve counts so summaries are accurate
                            '_counts': hunting_data.counts_by_type(),
                        }
                    else:
                        agent_data = hunting_data

                    # ---- Run hunting agents with network map context ----
                    try:
                        _backend = getattr(coordinator.llm_client, 'backend', 'none')
                        _n_agents = len(coordinator.agents)
                        _orch_label = 'CrewAI' if _crew_orchestrator else _backend
                        log.info(f'Cycle {cycle}: running {_n_agents} '
                                 f'hunting agents (orchestration: {_orch_label})')
                        send('running',
                             f'Cycle {cycle}: analyzing with {_n_agents} agents '
                             f'({_orch_label})...',
                             65, {'cycle': cycle, 'total_nodes': result['total_nodes'],
                                  'internal_nodes': result['internal_nodes'],
                                  'stage_detail': 'llm_analysis',
                                  'orchestration': 'crewai' if _crew_orchestrator else 'standard'})
                        context = NetworkState.from_data_with_map(
                            agent_data, nm.nodes)

                        if _crew_orchestrator:
                            assessment = _crew_orchestrator.hunt(
                                data=agent_data, network_state=context)
                        else:
                            assessment = coordinator.hunt(
                                data=agent_data, network_state=context)

                        agent_outputs = assessment.get('agent_outputs', [])
                        for ao in agent_outputs:
                            ao_dict = ao if isinstance(ao, dict) else ao.to_dict()
                            for f in ao_dict.get('findings', []):
                                findings_this_cycle += 1
                                db.save_finding(
                                    finding_id=f.get('fingerprint', f.get('activity_type', '') + str(cycle)),
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
                                    source_cycle=cycle,
                                )
                        # Persist LLM synthesis if present
                        llm_synth = assessment.get('llm_synthesis')
                        if llm_synth:
                            try:
                                db.save_synthesis(cycle, llm_synth)
                                log.info(f'Cycle {cycle}: saved LLM synthesis '
                                         f'(severity={llm_synth.get("overall_severity", "?")})')
                            except Exception as se:
                                log.error(f'Failed to save LLM synthesis: {se}')

                        if findings_this_cycle:
                            log.info(f'Cycle {cycle}: agents produced {findings_this_cycle} findings')
                    except Exception as ae:
                        log.error(f'Agent analysis error: {ae}')
                        log.error(traceback.format_exc())
                        send('running',
                             f'Cycle {cycle}: agent error: {ae}', 50,
                             {'cycle': cycle, 'agent_error': str(ae)})

                    msg = (f'Cycle {cycle} done: {conn_count} conns, '
                           f'{dns_count} DNS, {ntlm_count} NTLM → '
                           f'{result["total_nodes"]} nodes'
                           f'{f", {findings_this_cycle} findings" if findings_this_cycle else ""}')
                    log.info(msg)
                    send('running', msg, 50,
                         {'cycle': cycle, 'new_conns': conn_count,
                          'new_dns': dns_count, 'new_ntlm': ntlm_count,
                          'total_nodes': result['total_nodes'],
                          'internal_nodes': result['internal_nodes'],
                          'findings': findings_this_cycle})

                    # Free the SQLite store after the cycle to reclaim
                    # disk space (the next cycle will create a new one).
                    if _is_sqlite:
                        try:
                            hunting_data.close()
                        except Exception:
                            pass

                    # --- Auto-profile unprofiled devices ---
                    try:
                        stats = nm.get_profiling_stats()
                        unprofiled = stats.get('unprofiled', 0)
                        if unprofiled > 0:
                            log.info(f'Cycle {cycle}: auto-profiling '
                                     f'{unprofiled} unprofiled devices')
                            send('running',
                                 f'Cycle {cycle}: profiling {unprofiled} '
                                 f'new devices...',
                                 80, {'cycle': cycle,
                                      'stage_detail': 'auto_profile'})
                            profile_result = nm.profile_devices(
                                pipeline.splunk,
                                time_range=f'-{lookback_minutes}m',
                            )
                            nm.save_map()
                            classified = profile_result.get('classified', 0)
                            log.info(f'Cycle {cycle}: auto-profiled '
                                     f'{classified} devices')
                            send('running',
                                 f'Cycle {cycle}: profiled {classified} '
                                 f'devices',
                                 85, {'cycle': cycle,
                                      'stage_detail': 'auto_profile_done',
                                      'classified': classified})
                    except Exception as pe:
                        log.warning(f'Cycle {cycle}: auto-profile error: {pe}')

                else:
                    msg = f'Cycle {cycle}: no new data in last {lookback_minutes}m'
                    log.info(msg)
                    send('running', msg, 50, {'cycle': cycle})

            except Exception as e:
                log.error(f'Cycle {cycle} error: {e}')
                log.error(traceback.format_exc())
                send('running', f'Cycle {cycle} error: {e}', 50,
                     {'cycle': cycle, 'error': str(e)})

            # Sleep in 5-second increments so SIGTERM is checked promptly
            wait_seconds = interval_minutes * 60
            elapsed = (datetime.now() - cycle_start).total_seconds()
            remaining = max(0, wait_seconds - elapsed)
            while remaining > 0 and not _stop:
                time.sleep(min(5, remaining))
                remaining -= 5

        send('complete', f'Stopped after {cycle} cycles', 100,
             {'cycles_completed': cycle})
        log.info(f'Continuous ingestion stopped after {cycle} cycles')

    except Exception as e:
        log.error(f'Continuous ingestion failed: {e}')
        log.error(traceback.format_exc())
        send('error', f'Ingestion failed: {str(e)}', 0,
             {'error_detail': traceback.format_exc()})


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
        # Continuous ingestion state
        self._continuous_id: Optional[str] = None
        self._continuous_pid: Optional[int] = None

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
        """Start continuous network map ingestion in a background process."""
        import multiprocessing

        if self._continuous_pid and _pid_alive(self._continuous_pid):
            return {
                'status': 'already_running',
                'job_id': self._continuous_id,
                'pid': self._continuous_pid,
            }

        job_id = f'continuous_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        db_path = self.db.db_path

        proc = multiprocessing.Process(
            target=_continuous_ingest_process,
            args=(job_id, interval_minutes, lookback_minutes, db_path,
                  backfill_from),
            daemon=False,
        )
        proc.start()

        self._continuous_id = job_id
        self._continuous_pid = proc.pid
        self._monitored_hunts[job_id] = proc.pid
        self.active_hunts[job_id] = {
            'status': 'running',
            'type': 'continuous',
            'progress': 0,
            'start_time': datetime.now(),
            'interval_minutes': interval_minutes,
            'lookback_minutes': lookback_minutes,
        }

        logger.info(
            f'Started continuous ingestion {job_id} (pid {proc.pid}), '
            f'interval={interval_minutes}m, lookback={lookback_minutes}m'
        )
        self._ensure_poll_task()
        return {
            'status': 'started',
            'job_id': job_id,
            'pid': proc.pid,
            'interval_minutes': interval_minutes,
            'lookback_minutes': lookback_minutes,
        }

    async def stop_continuous(self) -> dict:
        """Stop the continuous ingestion process."""
        if not self._continuous_pid:
            return {'status': 'not_running'}

        if not _pid_alive(self._continuous_pid):
            job_id = self._continuous_id
            self.db.clear_progress(job_id)
            self._continuous_id = None
            self._continuous_pid = None
            self._monitored_hunts.pop(job_id, None)
            return {'status': 'already_stopped', 'job_id': job_id}

        job_id = self._continuous_id
        pid = self._continuous_pid
        logger.info(
            f'Stopping continuous ingestion {job_id} (pid {pid})'
        )

        # Immediately remove from poll loop tracking so
        # _poll_progress stops broadcasting stale WS updates
        # that would flip the frontend back to "running".
        self._monitored_hunts.pop(job_id, None)
        self.db.clear_progress(job_id)
        if job_id in self.active_hunts:
            self.active_hunts[job_id]['status'] = 'stopped'
        self._continuous_id = None
        self._continuous_pid = None

        # Broadcast an explicit 'complete' so the frontend
        # flips to stopped even if an earlier 'running' msg
        # was already in flight.
        if self._broadcast_fn:
            await self._broadcast_fn({
                'type': 'continuous_progress',
                'stage': 'complete',
                'message': 'Ingestion stopped by user',
                'progress': 100,
                'hunt_id': job_id,
            })

        # Send SIGTERM — the process catches it and stops gracefully
        try:
            import signal as _sig
            os.kill(pid, _sig.SIGTERM)
        except OSError:
            pass

        # Wait up to 10 seconds for graceful shutdown
        for _ in range(20):
            await asyncio.sleep(0.5)
            if not _pid_alive(pid):
                break

        # If still alive, force-kill with SIGKILL
        if _pid_alive(pid):
            logger.warning(
                f'Process {pid} did not respond to SIGTERM, sending SIGKILL'
            )
            try:
                import signal as _sig
                os.kill(pid, _sig.SIGKILL)
            except OSError:
                pass
            # Wait briefly for SIGKILL to take effect
            for _ in range(10):
                await asyncio.sleep(0.3)
                if not _pid_alive(pid):
                    break

        return {'status': 'stopped', 'job_id': job_id}

    def get_continuous_status(self) -> dict:
        """Return current continuous ingestion status."""
        if not self._continuous_id:
            return {'running': False}

        alive = self._continuous_pid and _pid_alive(self._continuous_pid)
        if not alive:
            job_id = self._continuous_id
            self._continuous_id = None
            self._continuous_pid = None
            return {'running': False, 'last_job_id': job_id}

        state = self.active_hunts.get(self._continuous_id, {})
        last_progress = state.get('last_progress', {})
        extra = {}
        if last_progress.get('extra'):
            try:
                import json
                extra = json.loads(last_progress['extra']) if isinstance(
                    last_progress['extra'], str) else last_progress['extra']
            except Exception:
                pass

        return {
            'running': True,
            'job_id': self._continuous_id,
            'pid': self._continuous_pid,
            'message': last_progress.get('message', ''),
            'cycle': extra.get('cycle', 0),
            'interval_minutes': extra.get('interval', state.get('interval_minutes', 15)),
            'lookback_minutes': extra.get('lookback', state.get('lookback_minutes', 20)),
            'total_nodes': extra.get('total_nodes', 0),
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
                        is_continuous = hunt_id.startswith('continuous_')
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
