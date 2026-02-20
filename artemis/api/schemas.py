"""Pydantic request/response models for the Artemis API."""

from typing import Dict, Optional

from pydantic import BaseModel


class HuntRequest(BaseModel):
    """Request to start a new hunt."""
    time_range: str = "-1h"
    mode: str = "PARALLEL"
    description: Optional[str] = None
    storage_mode: str = "ram"   # "ram" or "sqlite"
    earliest_time: Optional[str] = None   # ISO 8601, e.g. "2025-01-15T08:00:00"
    latest_time: Optional[str] = None     # ISO 8601, e.g. "2025-01-16T20:00:00"
    target_hosts: Optional[list] = None   # Filter to specific hosts/sensors, e.g. ["sensor01", "10.0.1.5"]


class BulkHuntRequest(BaseModel):
    """Request to start a bulk hunt."""
    days_back: int = 7
    window_hours: int = 6
    mode: str = "PARALLEL"
    description: Optional[str] = None


class ContinuousHuntRequest(BaseModel):
    """Request to start continuous hunting."""
    interval_minutes: int = 15
    lookback_minutes: int = 20
    mode: str = "PARALLEL"
    target_hosts: Optional[list] = None   # Filter to specific hosts/sensors


class PluginConfig(BaseModel):
    """Configuration for a plugin."""
    name: str
    enabled: bool
    config: Dict = {}


class ProfileRequest(BaseModel):
    """Request for device profiling."""
    time_range: str = "-24h"


class BackgroundProfileRequest(BaseModel):
    """Request for background per-device profiling."""
    time_range: str = "-24h"
    num_workers: int = 1


class LanGroupCreate(BaseModel):
    """Create a LAN group."""
    name: str
    description: str = ''
    color: str = '#667eea'
    members: list = []


class LanGroupUpdate(BaseModel):
    """Update a LAN group."""
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    members: Optional[list] = None


class DeviceFlagRequest(BaseModel):
    """Flag a device as malicious or suspicious."""
    node_id: str
    flag_type: str   # 'malicious' or 'suspicious'
    reason: str = ''


class ThreatIntelConfigRequest(BaseModel):
    """Configure threat intel API keys."""
    abuseipdb_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    otx_key: Optional[str] = None
    greynoise_key: Optional[str] = None


class ThreatIntelLookupRequest(BaseModel):
    """Request to enrich an indicator."""
    indicator: str
    indicator_type: str = "ip"    # "ip" or "domain"
    sources: Optional[list] = None


class ThreatIntelBatchRequest(BaseModel):
    """Batch enrichment request."""
    indicators: list
    indicator_type: str = "ip"
