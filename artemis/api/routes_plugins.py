"""Plugin, network-graph, profiling, and Sigma rule routes."""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse, StreamingResponse

from artemis.api.schemas import (
    PluginConfig, ProfileRequest, BackgroundProfileRequest,
    ContinuousHuntRequest,
    LanGroupCreate, LanGroupUpdate,
    DeviceFlagRequest, ThreatIntelConfigRequest, ThreatIntelLookupRequest,
    ThreatIntelBatchRequest, LLMSettingsRequest,
    MapLayoutSave, AnnotationCreate, AnnotationUpdate,
)
from artemis.managers import db_manager, hunt_manager, plugin_manager
from artemis.integrations.threat_intel import threat_intel_manager

logger = logging.getLogger("artemis.api.plugins")

router = APIRouter()


# --- Plugin management ----------------------------------------------------

@router.get("/api/plugins")
async def list_plugins():
    """List available plugins."""
    return plugin_manager.list_plugins()


@router.post("/api/plugins/{plugin_name}/enable")
def enable_plugin(plugin_name: str, config: PluginConfig):
    """Enable a plugin. Uses def (not async) so blocking init runs in threadpool."""
    try:
        plugin_manager.enable_plugin(plugin_name, config.config)
        return {'status': 'enabled', 'plugin': plugin_name}
    except Exception as e:
        logger.error(f"Failed to enable plugin {plugin_name}: {e}")
        return JSONResponse(status_code=400, content={'error': str(e)})


@router.post("/api/plugins/{plugin_name}/disable")
def disable_plugin(plugin_name: str):
    """Disable a plugin."""
    plugin_manager.disable_plugin(plugin_name)
    return {'status': 'disabled', 'plugin': plugin_name}


# --- Network maps ---------------------------------------------------------

@router.get("/api/network-maps")
async def list_network_maps():
    """List saved network map snapshots."""
    maps_dir = Path("network_maps")
    maps_dir.mkdir(exist_ok=True)

    maps = []
    for f in sorted(maps_dir.iterdir(),
                    key=lambda x: x.stat().st_mtime, reverse=True):
        if f.suffix == '.json':
            try:
                with open(f) as fh:
                    first_line = fh.readline().strip()
                    if first_line:
                        header = json.loads(first_line)
                        maps.append({
                            'filename': f.name,
                            'timestamp': header.get('timestamp', ''),
                            'total_nodes': header.get('total_nodes', 0),
                            'sensors': header.get('sensors', []),
                            'size_bytes': f.stat().st_size,
                            'is_current': f.name == 'current_map.json',
                        })
            except Exception as e:
                logger.warning(f"Failed to parse network map header from {f.name}: {e}")
                maps.append({
                    'filename': f.name,
                    'timestamp': '',
                    'total_nodes': 0,
                    'sensors': [],
                    'size_bytes': f.stat().st_size,
                    'is_current': f.name == 'current_map.json',
                })
    return maps


@router.post("/api/network-maps/snapshot")
async def save_network_map_snapshot(name: Optional[str] = None):
    """Save a named snapshot of the current network map."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}

    plugin.save_map()

    maps_dir = Path("network_maps")
    current = maps_dir / "current_map.json"
    if not current.exists():
        return {'error': 'No current map to snapshot'}

    if not name:
        name = f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    safe_name = "".join(c for c in name if c.isalnum() or c in ('_', '-'))
    snapshot_file = maps_dir / f"{safe_name}.json"

    shutil.copy2(current, snapshot_file)
    logger.info(f"Saved network map snapshot: {snapshot_file.name}")
    return {'status': 'saved', 'filename': snapshot_file.name}


@router.post("/api/network-maps/{filename}/load")
async def load_network_map(filename: str):
    """Load a saved network map, replacing the current one."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}

    maps_dir = Path("network_maps")
    map_file = maps_dir / filename

    if not map_file.exists():
        return {'error': 'Map file not found'}

    current = maps_dir / "current_map.json"
    if filename != "current_map.json":
        shutil.copy2(map_file, current)

    plugin.nodes.clear()
    plugin.sensors.clear()
    plugin._load_existing_map()

    logger.info(f"Loaded network map: {filename} ({len(plugin.nodes)} nodes)")
    return {
        'status': 'loaded',
        'filename': filename,
        'total_nodes': len(plugin.nodes),
        'sensors': sorted(plugin.sensors),
    }


@router.delete("/api/network-maps/{filename}")
async def delete_network_map(filename: str):
    """Delete a saved network map snapshot."""
    if filename == "current_map.json":
        return {'error': 'Cannot delete the current active map'}

    maps_dir = Path("network_maps")
    map_file = maps_dir / filename

    if not map_file.exists():
        return {'error': 'Map file not found'}

    map_file.unlink()
    summary = maps_dir / filename.replace('.json', '_summary.txt')
    if summary.exists():
        summary.unlink()

    logger.info(f"Deleted network map: {filename}")
    return {'status': 'deleted', 'filename': filename}


@router.post("/api/network-maps/reset")
async def reset_network_map():
    """Clear the network map only.  Stops pipelines and wipes the
    in-memory map + map files on disk, but preserves all stored events,
    findings, syntheses, and cases.  The next pipeline run will rebuild
    the map from new data (or backfill)."""

    # 0. Stop any running pipelines so they don't keep writing data
    try:
        await hunt_manager.stop_continuous()
    except Exception as e:
        logger.warning(f"Error stopping pipelines during reset: {e}")

    plugin = plugin_manager.get_plugin('network_mapper')
    prev_nodes = 0

    # 1. Clear in-memory state (API process)
    if plugin:
        prev_nodes = len(plugin.nodes)
        plugin.nodes.clear()
        plugin.sensors.clear()
        plugin._dirty_nodes.clear()
        plugin.mac_history.clear()
        plugin._stats_cache = None
        plugin.save_map()  # writes empty map to disk

        # Remove auxiliary files so nothing stale gets reloaded
        map_dir = plugin.output_dir
        for pattern in ('*_summary.txt', 'mac_history.json',
                        'current_map.json.lock'):
            for f in map_dir.glob(pattern):
                try:
                    f.unlink()
                except OSError:
                    pass

    logger.info(f"Network map reset: cleared {prev_nodes} nodes")
    return {
        'status': 'reset',
        'total_nodes': 0,
        'previous_nodes': prev_nodes,
    }


@router.post("/api/factory-reset")
async def factory_reset():
    """Full factory reset: clears EVERYTHING — network map, stored events,
    findings, syntheses, cases, and analysis queue.  Use this only when
    you truly want to start from scratch."""

    # Stop pipelines first
    try:
        await hunt_manager.stop_continuous()
    except Exception as e:
        logger.warning(f"Error stopping pipelines during factory reset: {e}")

    # Clear map
    plugin = plugin_manager.get_plugin('network_mapper')
    if plugin:
        plugin.nodes.clear()
        plugin.sensors.clear()
        plugin._dirty_nodes.clear()
        plugin.mac_history.clear()
        plugin._stats_cache = None
        plugin.save_map()

        map_dir = plugin.output_dir
        for pattern in ('*_summary.txt', 'mac_history.json',
                        'current_map.json.lock'):
            for f in map_dir.glob(pattern):
                try:
                    f.unlink()
                except OSError:
                    pass

    # Clear all database tables
    db_stats = db_manager.full_reset()

    logger.info(
        f"Factory reset: map cleared, {db_stats['events_deleted']} events, "
        f"{db_stats['findings_deleted']} findings, "
        f"{db_stats['queue_deleted']} queued cycles deleted"
    )
    return {
        'status': 'factory_reset',
        'total_nodes': 0,
        **db_stats,
    }


# --- Network graph --------------------------------------------------------

@router.get("/api/network-graph")
async def get_network_graph(
    sensor_id: Optional[str] = None,
    max_nodes: int = 5000,
):
    """Get network topology graph from network mapper plugin."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(
            status_code=404,
            content={'error': 'Network mapper plugin not enabled'},
        )
    try:
        graph_data = plugin.get_network_graph(
            sensor_id=sensor_id, max_nodes=max_nodes,
        )
        # Attach device flags, LAN groups, layout, and annotations
        graph_data['device_flags'] = db_manager.get_device_flags()
        graph_data['lan_groups'] = db_manager.get_lan_groups()
        graph_data['saved_layout'] = db_manager.get_layout()
        graph_data['annotations'] = db_manager.get_annotations()
        return graph_data
    except Exception as e:
        return JSONResponse(status_code=500, content={'error': str(e)})


@router.get("/api/network-summary")
async def get_network_summary(sensor_id: Optional[str] = None):
    """Get network summary statistics, optionally filtered by sensor."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(
            status_code=404,
            content={'error': 'Network mapper plugin not enabled'},
        )
    try:
        return plugin.get_summary(sensor_id=sensor_id)
    except Exception as e:
        return JSONResponse(status_code=500, content={'error': str(e)})


@router.post("/api/network-graph/profile")
async def profile_devices(request: ProfileRequest):
    """Start device profiling in a background subprocess.

    Progress is broadcast over WebSocket so the UI can track it,
    and the process survives page reloads.
    """
    try:
        profile_id = await hunt_manager.start_profile(request.time_range)
        return {'profile_id': profile_id, 'status': 'started'}
    except RuntimeError as e:
        return JSONResponse(status_code=409, content={'error': str(e)})
    except Exception as e:
        logger.error(f"Device profiling failed: {e}")
        return JSONResponse(status_code=500, content={'error': str(e)})


@router.get("/api/network-graph/profile/status")
async def profile_status():
    """Get the current profiling status (for page-reload reconnection)."""
    return hunt_manager.get_profile_status()


@router.post("/api/network-graph/profile/cancel")
async def cancel_profile():
    """Cancel a running device profiling job."""
    profile_id = hunt_manager._profile_id
    if not profile_id:
        return JSONResponse(status_code=404,
                            content={'error': 'No profiling job is running'})
    result = await hunt_manager.cancel_hunt(profile_id)
    if result.get('status') == 'error':
        return JSONResponse(status_code=404, content=result)
    logger.info(f"Profile {profile_id} cancelled via API")
    return result


# --- Background profiling -------------------------------------------------

@router.post("/api/network-graph/profile/background/start")
async def start_background_profile(request: BackgroundProfileRequest):
    """Start background per-device profiling with multiple workers."""
    try:
        profile_id = await hunt_manager.start_background_profile(
            time_range=request.time_range,
            num_workers=request.num_workers,
        )
        return {'profile_id': profile_id, 'status': 'started',
                'num_workers': request.num_workers}
    except RuntimeError as e:
        return JSONResponse(status_code=409, content={'error': str(e)})
    except Exception as e:
        logger.error(f"Background profiling failed to start: {e}")
        return JSONResponse(status_code=500, content={'error': str(e)})


@router.get("/api/network-graph/profile/background/status")
async def background_profile_status():
    """Get background profiling status."""
    return hunt_manager.get_bg_profile_status()


@router.post("/api/network-graph/profile/background/stop")
async def stop_background_profile():
    """Stop background profiling."""
    return await hunt_manager.stop_background_profile()


# --- Continuous ingestion --------------------------------------------------

@router.post("/api/network-graph/continuous/start")
async def start_continuous_ingestion(req: ContinuousHuntRequest = ContinuousHuntRequest()):
    """Start continuous network map ingestion.

    Runs a background loop that queries Splunk every *interval_minutes*
    for the last *lookback_minutes* of network connections, DNS queries,
    and NTLM events, then feeds them into the network mapper to grow
    the map in real-time.

    If *backfill_from* is set (ISO 8601 date, e.g. ``"2025-01-15"``),
    the **first cycle** pulls all data from that date to now (using
    automatic 1-hour windowing), then subsequent cycles use the normal
    *lookback_minutes* window.
    """
    return await hunt_manager.start_continuous(
        req.interval_minutes, req.lookback_minutes,
        backfill_from=req.backfill_from,
    )


@router.post("/api/network-graph/continuous/stop")
async def stop_continuous_ingestion():
    """Stop continuous network map ingestion."""
    return await hunt_manager.stop_continuous()


@router.get("/api/network-graph/continuous/status")
async def continuous_ingestion_status():
    """Get current continuous ingestion status."""
    return hunt_manager.get_continuous_status()


# --- Network graph query API -----------------------------------------------

@router.get("/api/network-graph/query")
async def query_network_graph(
    device_type: Optional[str] = None,
    role: Optional[str] = None,
    has_external: Optional[bool] = None,
    port: Optional[int] = None,
    os_contains: Optional[str] = None,
    ip_prefix: Optional[str] = None,
    hostname_contains: Optional[str] = None,
    limit: int = 200,
):
    """Query the network map with filters.

    Returns matching nodes with their full profile — designed for
    agentic consumers that need to search the map by criteria.
    """
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(status_code=404,
                            content={'error': 'Network mapper not enabled'})

    results = []
    for nid, node in plugin.nodes.items():
        # Apply filters
        if device_type and (getattr(node, 'device_type', '') or '') != device_type:
            continue
        if role and role not in (getattr(node, 'roles', set()) or set()):
            continue
        if has_external is not None:
            ext_out = getattr(node, 'connections_to', {}) or {}
            has_ext = any(not _is_rfc1918(ip) for ip in ext_out)
            if has_external != has_ext:
                continue
        if port is not None:
            ports = {p for p, _ in (getattr(node, 'services', set()) or set())}
            if port not in ports:
                continue
        if os_contains:
            os_info = (getattr(node, 'os_info', '') or '').lower()
            if os_contains.lower() not in os_info:
                continue
        if ip_prefix:
            if not (getattr(node, 'ip', '') or '').startswith(ip_prefix):
                continue
        if hostname_contains:
            names = getattr(node, 'hostnames', set()) or set()
            if not any(hostname_contains.lower() in h.lower() for h in names):
                continue

        results.append(node.to_dict())
        if len(results) >= limit:
            break

    return {'count': len(results), 'nodes': results}


def _is_rfc1918(ip: str) -> bool:
    """Quick check for private IPv4 addresses."""
    return (ip.startswith('10.') or ip.startswith('192.168.') or
            (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31))


# --- Agent findings --------------------------------------------------------

@router.get("/api/findings")
async def get_findings(
    limit: int = 100,
    agent_name: Optional[str] = None,
    min_severity: Optional[str] = None,
    include_dismissed: bool = False,
):
    """Get agent threat-hunting findings."""
    return db_manager.get_findings(
        limit=limit,
        agent_name=agent_name,
        min_severity=min_severity,
        include_dismissed=include_dismissed,
    )


@router.get("/api/findings/summary")
async def get_findings_summary():
    """Get a summary of findings by severity and agent."""
    return db_manager.get_findings_summary()


@router.post("/api/findings/{finding_id}/dismiss")
async def dismiss_finding(finding_id: str):
    """Dismiss a finding (mark it as reviewed/not-actionable)."""
    db_manager.dismiss_finding(finding_id)
    return {'status': 'dismissed', 'finding_id': finding_id}


@router.post("/api/findings/reset")
async def reset_findings():
    """Delete all findings and LLM syntheses so fresh hunts start clean."""
    count = db_manager.clear_findings()
    return {'status': 'cleared', 'deleted': count}


@router.get("/api/timeline")
async def get_timeline():
    """Get chronological timeline of LLM syntheses with actual event dates."""
    import json as _json

    events = []

    # Build a cycle -> earliest actual event timestamp lookup from findings
    # so we display when events actually occurred, not when they were detected.
    cycle_timestamps = {}
    cycle_details = {}  # aggregated MITRE, indicators, assets per cycle
    try:
        findings = db_manager.get_findings(limit=500, include_dismissed=False)
        for f in findings:
            cycle = f.get('source_cycle', 0)
            if cycle not in cycle_details:
                cycle_details[cycle] = {
                    'mitre_tactics': set(),
                    'mitre_techniques': set(),
                    'indicators': [],
                    'affected_assets': [],
                    'evidence_count': 0,
                }
            cd = cycle_details[cycle]
            for t in (f.get('mitre_tactics') or []):
                cd['mitre_tactics'].add(t)
            for t in (f.get('mitre_techniques') or []):
                cd['mitre_techniques'].add(t)
            cd['indicators'].extend((f.get('indicators') or [])[:5])
            cd['affected_assets'].extend((f.get('affected_assets') or [])[:5])
            cd['evidence_count'] += f.get('evidence_count', 0)

            # Extract actual event timestamps from evidence data
            for ev in (f.get('evidence') or []):
                ev_data = ev.get('data', {}) if isinstance(ev, dict) else {}
                ts = ev_data.get('timestamp') or ev_data.get('_time')
                if ts:
                    if cycle not in cycle_timestamps or ts < cycle_timestamps[cycle]:
                        cycle_timestamps[cycle] = ts
    except Exception:
        pass

    # LLM syntheses as timeline events — use actual event dates
    try:
        syntheses = db_manager.get_syntheses(limit=50)
        for s in syntheses:
            full = s.get('full_synthesis') or {}
            if isinstance(full, str):
                try:
                    full = _json.loads(full)
                except Exception:
                    full = {}
            cycle = s.get('cycle', 0)
            cd = cycle_details.get(cycle, {})

            # Prefer the earliest actual event timestamp; fall back to created_at
            event_ts = cycle_timestamps.get(cycle) or s.get('created_at', '')

            # Deduplicate aggregated lists
            indicators = list(dict.fromkeys(
                (i if isinstance(i, str) else (i.get('value') or i.get('indicator', '')))
                for i in (cd.get('indicators') or [])
            ))[:10]
            assets = list(dict.fromkeys(
                (a if isinstance(a, str) else (a.get('hostname') or a.get('ip', '')))
                for a in (cd.get('affected_assets') or [])
            ))[:10]

            events.append({
                'id': f"synthesis-{s.get('id', 0)}",
                'type': 'synthesis',
                'timestamp': event_ts,
                'title': f"Threat Synthesis — Batch {cycle}",
                'description': (full.get('reasoning') or
                                full.get('threat_narrative') or
                                s.get('reasoning', '')),
                'severity': s.get('overall_severity', 'low'),
                'confidence': s.get('overall_confidence', 0),
                'agent': 'LLM Synthesis',
                'indicators': indicators,
                'affected_assets': assets,
                'mitre_tactics': sorted(cd.get('mitre_tactics', set())),
                'mitre_techniques': sorted(cd.get('mitre_techniques', set())),
                'evidence_count': cd.get('evidence_count', 0),
                'source_cycle': cycle,
                'false_positives': full.get('likely_false_positives') or
                                   full.get('false_positive_flags') or [],
            })
    except Exception:
        pass

    # Sort by timestamp descending (newest first)
    events.sort(key=lambda e: e.get('timestamp', ''), reverse=True)

    return events


# --- MAC-to-IP tracking ---------------------------------------------------

@router.get("/api/network-graph/mac-tracking")
async def get_mac_tracking():
    """Get MAC-to-IP device tracking summary."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(
            status_code=404,
            content={'error': 'Network mapper plugin not enabled'},
        )
    return plugin.get_mac_tracking()


@router.get("/api/network-graph/mac-history/{mac:path}")
async def get_mac_history(mac: str):
    """Get detailed MAC history for a specific MAC address."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(
            status_code=404,
            content={'error': 'Network mapper plugin not enabled'},
        )
    result = plugin.get_mac_history_detail(mac)
    if not result:
        return JSONResponse(
            status_code=404,
            content={'error': 'MAC address not found in history'},
        )
    return result


@router.get("/api/network-graph/device-identity/{ip}")
async def get_device_identity(ip: str):
    """Given an IP, find all MACs and their other IPs over time."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return JSONResponse(
            status_code=404,
            content={'error': 'Network mapper plugin not enabled'},
        )
    result = plugin.get_device_identity(ip)
    if not result:
        return JSONResponse(
            status_code=404,
            content={'error': 'No MAC history found for this IP'},
        )
    return result


# --- LAN groups -----------------------------------------------------------

@router.get("/api/lan-groups")
async def list_lan_groups():
    """List all LAN groups with their member node IDs."""
    return db_manager.get_lan_groups()


@router.post("/api/lan-groups")
async def create_lan_group(req: LanGroupCreate):
    """Create a new LAN group."""
    return db_manager.create_lan_group(
        name=req.name,
        description=req.description,
        color=req.color,
        member_ids=req.members,
    )


@router.put("/api/lan-groups/{group_id}")
async def update_lan_group(group_id: int, req: LanGroupUpdate):
    """Update a LAN group's name, description, color, or members."""
    db_manager.update_lan_group(
        group_id=group_id,
        name=req.name,
        description=req.description,
        color=req.color,
        member_ids=req.members,
    )
    return {'status': 'updated', 'id': group_id}


@router.delete("/api/lan-groups/{group_id}")
async def delete_lan_group(group_id: int):
    """Delete a LAN group."""
    db_manager.delete_lan_group(group_id)
    return {'status': 'deleted', 'id': group_id}


# --- Device flags ---------------------------------------------------------

@router.get("/api/device-flags")
async def list_device_flags():
    """List all flagged devices."""
    return db_manager.get_device_flags()


@router.post("/api/device-flags")
async def set_device_flag(req: DeviceFlagRequest):
    """Flag a device as malicious or suspicious."""
    if req.flag_type not in ('malicious', 'suspicious'):
        return JSONResponse(
            status_code=400,
            content={'error': 'flag_type must be "malicious" or "suspicious"'},
        )
    return db_manager.set_device_flag(
        node_id=req.node_id,
        flag_type=req.flag_type,
        reason=req.reason,
    )


@router.delete("/api/device-flags/{node_id:path}")
async def remove_device_flag(node_id: str):
    """Remove a flag from a device."""
    db_manager.remove_device_flag(node_id)
    return {'status': 'removed', 'node_id': node_id}


# --- Sigma rules ----------------------------------------------------------

@router.get("/api/sigma/rules")
async def get_sigma_rules():
    """List loaded Sigma rules."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if not plugin:
        return {'error': 'Sigma engine plugin not enabled'}
    return plugin.get_rules()


@router.get("/api/sigma/results")
async def get_sigma_results():
    """Get latest Sigma scan results."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if plugin:
        return plugin.get_last_results()
    results_file = Path('sigma_results') / 'latest.json'
    if results_file.exists():
        try:
            with open(results_file) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read Sigma results file {results_file}: {e}")
    return {'error': 'Sigma engine plugin not enabled'}


@router.post("/api/sigma/reload")
async def reload_sigma_rules():
    """Reload Sigma rules from disk."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if not plugin:
        return {'error': 'Sigma engine plugin not enabled'}
    plugin.reload_rules()
    return {'status': 'reloaded', 'rules_count': len(plugin.rules)}


# --- Threat Intelligence --------------------------------------------------

@router.get("/api/threat-intel/status")
async def threat_intel_status():
    """Get threat intel source configuration status."""
    return threat_intel_manager.get_config_status()


@router.post("/api/threat-intel/configure")
async def configure_threat_intel(req: ThreatIntelConfigRequest):
    """Configure threat intel API keys."""
    settings = {}
    if req.abuseipdb_key is not None:
        settings["abuseipdb_key"] = req.abuseipdb_key
    if req.virustotal_key is not None:
        settings["virustotal_key"] = req.virustotal_key
    if req.otx_key is not None:
        settings["otx_key"] = req.otx_key
    if req.greynoise_key is not None:
        settings["greynoise_key"] = req.greynoise_key
    threat_intel_manager.configure(settings)
    return {"status": "configured", "sources": threat_intel_manager.get_config_status()}


# --- LLM Backend Settings -------------------------------------------------

_LLM_CONFIG_PATH = Path("config/llm_settings.json")


def _read_llm_settings() -> dict:
    """Read persisted LLM backend settings."""
    if _LLM_CONFIG_PATH.exists():
        try:
            return json.loads(_LLM_CONFIG_PATH.read_text())
        except Exception:
            pass
    return {}


@router.get("/api/llm/settings")
async def get_llm_settings():
    """Return current LLM backend settings (keys are masked)."""
    cfg = _read_llm_settings()
    return {
        "backend": cfg.get("backend", "auto"),
        "ollama_url": cfg.get("ollama_url", "http://localhost:11434"),
        "ollama_model": cfg.get("ollama_model", "llama3.1"),
        "has_anthropic_key": bool(cfg.get("anthropic_api_key")),
        "orchestration": cfg.get("orchestration", "standard"),
        "crewai_process": cfg.get("crewai_process", "sequential"),
    }


@router.post("/api/llm/settings")
async def save_llm_settings(req: LLMSettingsRequest):
    """Persist LLM backend settings to disk."""
    cfg = _read_llm_settings()
    cfg["backend"] = req.backend
    if req.ollama_url is not None:
        cfg["ollama_url"] = req.ollama_url
    if req.ollama_model is not None:
        cfg["ollama_model"] = req.ollama_model
    if req.anthropic_api_key is not None:
        cfg["anthropic_api_key"] = req.anthropic_api_key

    if req.orchestration is not None:
        cfg["orchestration"] = req.orchestration
    if req.crewai_process is not None:
        cfg["crewai_process"] = req.crewai_process

    _LLM_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LLM_CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    return {"status": "saved", "backend": cfg["backend"],
            "orchestration": cfg.get("orchestration", "standard")}


@router.post("/api/threat-intel/lookup")
def threat_intel_lookup(req: ThreatIntelLookupRequest):
    """Enrich a single indicator (IP or domain). Sync so rate-limiting blocks properly."""
    if req.indicator_type == "ip":
        return threat_intel_manager.enrich_ip(req.indicator, req.sources)
    elif req.indicator_type == "domain":
        return threat_intel_manager.enrich_domain(req.indicator, req.sources)
    return JSONResponse(status_code=400,
                        content={"error": "indicator_type must be 'ip' or 'domain'"})


@router.post("/api/threat-intel/batch")
def threat_intel_batch(req: ThreatIntelBatchRequest):
    """Enrich a batch of indicators."""
    results = threat_intel_manager.enrich_batch(
        req.indicators, req.indicator_type)
    return {"results": results, "count": len(results)}


@router.get("/api/threat-intel/worker-status")
async def enrichment_worker_status():
    """Get background enrichment worker status."""
    return threat_intel_manager.get_worker_status()


@router.get("/api/threat-intel/enrichments")
async def get_enrichments():
    """Get all stored enrichment results."""
    return db_manager.get_all_enrichments()


@router.get("/api/threat-intel/enrichment-summary")
async def get_enrichment_summary():
    """Get aggregated enrichment stats by verdict."""
    all_enrichments = db_manager.get_all_enrichments()
    verdicts = {}
    sources_seen = set()
    for e in all_enrichments:
        v = e.get("verdict", "unknown")
        verdicts[v] = verdicts.get(v, 0) + 1
        for src in (e.get("sources") or {}):
            sources_seen.add(src)
    return {
        "total": len(all_enrichments),
        "by_verdict": verdicts,
        "sources_used": sorted(sources_seen),
        "config": threat_intel_manager.get_config_status(),
    }


@router.get("/api/threat-intel/enrichment/{ip}")
async def get_ip_enrichment(ip: str):
    """Get enrichment for a specific IP."""
    result = db_manager.get_enrichment(ip)
    if not result:
        return JSONResponse(status_code=404,
                            content={"error": "No enrichment data for this IP"})
    return result


# --- LLM Synthesis reports ------------------------------------------------

@router.get("/api/llm-synthesis")
async def get_syntheses(limit: int = 20):
    """Get recent LLM threat synthesis reports."""
    return db_manager.get_syntheses(limit=limit)


@router.get("/api/llm-synthesis/latest")
async def get_latest_synthesis():
    """Get the most recent LLM synthesis report."""
    result = db_manager.get_latest_synthesis()
    if not result:
        # Fallback: check JSON backup files written by hunt_manager
        import pathlib, json as _json
        _synth_dir = pathlib.Path(db_manager.db_path).parent / 'synthesis_backup'
        if _synth_dir.exists():
            _files = sorted(_synth_dir.glob('cycle_*.json'), reverse=True)
            if _files:
                try:
                    _data = _json.loads(_files[0].read_text())
                    return {
                        'id': 0,
                        'cycle': int(_files[0].stem.split('_')[1]),
                        'overall_severity': _data.get('overall_severity', 'low'),
                        'overall_confidence': _data.get('overall_confidence', 0.0),
                        'reasoning': _data.get('reasoning',
                                               _data.get('threat_narrative', '')),
                        'kill_chain': _data.get('kill_chain_assessment', {}),
                        'correlations': _data.get('correlations',
                                                  _data.get('correlated_findings', [])),
                        'false_positive_flags': _data.get('false_positive_flags',
                                                          _data.get('likely_false_positives', [])),
                        'recommended_actions': _data.get('recommended_actions', []),
                        'full_synthesis': _data,
                        'created_at': _files[0].stat().st_mtime,
                        'source': 'json_backup',
                    }
                except Exception:
                    pass
        return JSONResponse(status_code=404,
                            content={"error": "No synthesis reports yet"})
    return result


# --- Map layout (interactive positioning) ---------------------------------

@router.get("/api/network-graph/layout")
async def get_map_layout():
    """Get all saved node positions."""
    return db_manager.get_layout()


@router.put("/api/network-graph/layout")
async def save_map_layout(req: MapLayoutSave):
    """Save node positions (drag-and-drop)."""
    count = db_manager.save_layout(req.positions)
    return {'status': 'saved', 'count': count}


@router.delete("/api/network-graph/layout")
async def reset_map_layout():
    """Clear all saved positions (reset to auto-layout)."""
    count = db_manager.clear_layout()
    return {'status': 'reset', 'cleared': count}


# --- Map annotations ------------------------------------------------------

@router.get("/api/network-graph/annotations")
async def get_annotations(node_id: Optional[str] = None):
    """Get map annotations, optionally filtered by node_id."""
    return db_manager.get_annotations(node_id=node_id)


@router.post("/api/network-graph/annotations")
async def create_annotation(req: AnnotationCreate):
    """Create a map annotation."""
    return db_manager.create_annotation(
        node_id=req.node_id,
        annotation_type=req.annotation_type,
        content=req.content,
        metadata=req.metadata,
    )


@router.put("/api/network-graph/annotations/{ann_id}")
async def update_annotation(ann_id: int, req: AnnotationUpdate):
    """Update an annotation."""
    db_manager.update_annotation(ann_id, content=req.content,
                                 metadata=req.metadata)
    return {'status': 'updated', 'id': ann_id}


@router.delete("/api/network-graph/annotations/{ann_id}")
async def delete_annotation(ann_id: int):
    """Delete an annotation."""
    db_manager.delete_annotation(ann_id)
    return {'status': 'deleted', 'id': ann_id}


# --- Analysis queue status ------------------------------------------------

@router.get("/api/analysis-queue/status")
async def analysis_queue_status():
    """Get the analysis queue status (pending, in_progress, complete counts)."""
    return db_manager.get_analysis_queue_status()


@router.get("/api/llm-synthesis/report/pdf")
async def generate_pdf_report():
    """Generate a PDF threat report from the latest LLM synthesis + findings."""
    synthesis = db_manager.get_latest_synthesis()
    findings = db_manager.get_findings(limit=200)
    findings_summary = db_manager.get_findings_summary()

    if not synthesis and not findings:
        return JSONResponse(status_code=404,
                            content={"error": "No data for report generation"})

    try:
        from artemis.reporting.pdf_report import generate_threat_report
        pdf_bytes = generate_threat_report(synthesis, findings, findings_summary)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    f'attachment; filename="artemis_threat_report_{timestamp}.pdf"'
            },
        )
    except ImportError:
        return JSONResponse(status_code=500,
                            content={"error": "PDF generation library not installed. "
                                     "Run: pip install reportlab"})
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return JSONResponse(status_code=500,
                            content={"error": f"PDF generation failed: {str(e)}"})
