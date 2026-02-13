"""Pydantic request/response models for the Artemis API."""

from typing import Dict, Optional

from pydantic import BaseModel


class HuntRequest(BaseModel):
    """Request to start a new hunt."""
    time_range: str = "-1h"
    mode: str = "PARALLEL"
    description: Optional[str] = None


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


class PluginConfig(BaseModel):
    """Configuration for a plugin."""
    name: str
    enabled: bool
    config: Dict = {}


class ProfileRequest(BaseModel):
    """Request for device profiling."""
    time_range: str = "-24h"
