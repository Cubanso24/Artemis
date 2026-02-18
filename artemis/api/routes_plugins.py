"""Plugin, network-graph, and Sigma rule routes."""

import csv
import io
import json
import logging
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import Response

from artemis.api.schemas import (
    PluginConfig, ProfileRequest, LanGroupCreate, LanGroupUpdate,
    DeviceFlagRequest, ThreatIntelConfigRequest, ThreatIntelLookupRequest,
    ThreatIntelBatchRequest,
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
    """Clear the current network map (start fresh)."""
    plugin = plugin_manager.get_plugin('network_mapper')
    if not plugin:
        return {'error': 'Network mapper plugin not enabled'}

    plugin.nodes.clear()
    plugin.sensors.clear()
    plugin._dirty_nodes.clear()
    plugin._stats_cache = None
    plugin.save_map()

    logger.info("Network map reset to empty")
    return {'status': 'reset', 'total_nodes': 0}


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
        # Attach device flags and LAN groups so the frontend can render them
        graph_data['device_flags'] = db_manager.get_device_flags()
        graph_data['lan_groups'] = db_manager.get_lan_groups()
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


@router.post("/api/threat-intel/enrich-hunt/{hunt_id}")
def enrich_hunt(hunt_id: str):
    """Queue all IPs from a hunt for background enrichment."""
    return threat_intel_manager.enrich_hunt(hunt_id)


@router.get("/api/threat-intel/worker-status")
async def enrichment_worker_status():
    """Get background enrichment worker status."""
    return threat_intel_manager.get_worker_status()


@router.get("/api/threat-intel/enrichments")
async def get_enrichments():
    """Get all stored enrichment results."""
    return db_manager.get_all_enrichments()


@router.get("/api/threat-intel/enrichment/{ip}")
async def get_ip_enrichment(ip: str):
    """Get enrichment for a specific IP."""
    result = db_manager.get_enrichment(ip)
    if not result:
        return JSONResponse(status_code=404,
                            content={"error": "No enrichment data for this IP"})
    return result


@router.get("/api/hunts/{hunt_id}/enrichments")
async def get_hunt_enrichments(hunt_id: str):
    """Get enrichment results for all IPs in a hunt."""
    ips = db_manager.extract_ips_from_hunt(hunt_id)
    enrichments = db_manager.get_enrichments_bulk(ips)
    return {
        "hunt_id": hunt_id,
        "total_ips": len(ips),
        "enriched": len(enrichments),
        "results": enrichments,
    }


# --- Export / Reporting ---------------------------------------------------

@router.get("/api/hunts/{hunt_id}/export/{fmt}")
async def export_hunt(hunt_id: str, fmt: str):
    """Export hunt results in various formats: json, csv, html."""
    hunt = db_manager.get_hunt_details(hunt_id)
    if not hunt:
        return JSONResponse(status_code=404, content={"error": "Hunt not found"})

    if fmt == "json":
        return JSONResponse(
            content=hunt,
            headers={
                "Content-Disposition":
                    f'attachment; filename="artemis_{hunt_id}.json"'
            },
        )

    elif fmt == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Title", "Severity", "Confidence", "Agent",
            "MITRE Tactics", "MITRE Techniques",
            "Affected Assets", "Description", "Timestamp",
        ])
        for f in hunt.get("findings", []):
            writer.writerow([
                f.get("title", ""),
                f.get("severity", ""),
                f.get("confidence", ""),
                f.get("agent_name", ""),
                "; ".join(f.get("mitre_tactics", [])),
                "; ".join(f.get("mitre_techniques", [])),
                "; ".join(f.get("affected_assets", [])),
                f.get("description", ""),
                f.get("timestamp", ""),
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition":
                    f'attachment; filename="artemis_{hunt_id}.csv"'
            },
        )

    elif fmt == "html":
        from artemis.utils.report_generator import generate_html_report
        html = generate_html_report(hunt)
        return HTMLResponse(
            content=html,
            headers={
                "Content-Disposition":
                    f'attachment; filename="artemis_report_{hunt_id}.html"'
            },
        )

    return JSONResponse(status_code=400,
                        content={"error": "Format must be json, csv, or html"})


# --- Timeline data --------------------------------------------------------

@router.get("/api/hunts/{hunt_id}/timeline")
async def get_hunt_timeline(hunt_id: str):
    """Get findings formatted for timeline visualization."""
    hunt = db_manager.get_hunt_details(hunt_id)
    if not hunt:
        return JSONResponse(status_code=404, content={"error": "Hunt not found"})

    events = []
    for f in hunt.get("findings", []):
        events.append({
            "title": f.get("title", "Untitled"),
            "description": f.get("description", ""),
            "severity": f.get("severity", "low"),
            "confidence": f.get("confidence", 0),
            "agent": f.get("agent_name", ""),
            "timestamp": f.get("timestamp", ""),
            "mitre_tactics": f.get("mitre_tactics", []),
            "mitre_techniques": f.get("mitre_techniques", []),
            "affected_assets": f.get("affected_assets", []),
        })

    # Sort by timestamp
    events.sort(key=lambda e: e.get("timestamp") or "")

    return {
        "hunt_id": hunt_id,
        "hunt_start": hunt.get("start_time"),
        "hunt_end": hunt.get("end_time"),
        "events": events,
    }


@router.get("/api/timeline/all")
async def get_all_timelines(limit: int = 200):
    """Get recent findings across all hunts for a global timeline."""
    conn = sqlite3.connect(db_manager.db_path)
    try:
        rows = conn.execute("""
            SELECT f.hunt_id, f.agent_name, f.title, f.description,
                   f.severity, f.confidence, f.mitre_tactics,
                   f.mitre_techniques, f.affected_assets, f.timestamp
            FROM findings f
            ORDER BY f.timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

        events = []
        for r in rows:
            events.append({
                "hunt_id": r[0],
                "agent": r[1],
                "title": r[2],
                "description": r[3],
                "severity": r[4],
                "confidence": r[5],
                "mitre_tactics": json.loads(r[6]) if r[6] else [],
                "mitre_techniques": json.loads(r[7]) if r[7] else [],
                "affected_assets": json.loads(r[8]) if r[8] else [],
                "timestamp": r[9],
            })

        return {"events": events, "total": len(events)}
    finally:
        conn.close()
