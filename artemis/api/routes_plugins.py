"""Plugin, network-graph, and Sigma rule routes."""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from artemis.api.schemas import PluginConfig, ProfileRequest
from artemis.managers import hunt_manager, plugin_manager

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
            except Exception:
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
    max_nodes: int = 200,
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
        except Exception:
            pass
    return {'error': 'Sigma engine plugin not enabled'}


@router.post("/api/sigma/reload")
async def reload_sigma_rules():
    """Reload Sigma rules from disk."""
    plugin = plugin_manager.get_plugin('sigma_engine')
    if not plugin:
        return {'error': 'Sigma engine plugin not enabled'}
    plugin.reload_rules()
    return {'status': 'reloaded', 'rules_count': len(plugin.rules)}
