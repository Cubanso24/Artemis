"""
Network state representation for context-aware threat hunting.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any
import numpy as np


@dataclass
class TimeFeatures:
    """Temporal features of the current network state."""
    timestamp: datetime
    hour_of_day: int
    day_of_week: int
    is_business_hours: bool
    is_weekend: bool
    is_holiday: bool = False

    @classmethod
    def from_timestamp(cls, timestamp: datetime) -> 'TimeFeatures':
        """Create TimeFeatures from a timestamp."""
        hour = timestamp.hour
        day = timestamp.weekday()  # 0=Monday, 6=Sunday

        # Business hours: 8 AM to 6 PM
        is_business = 8 <= hour < 18
        is_weekend = day >= 5  # Saturday or Sunday

        return cls(
            timestamp=timestamp,
            hour_of_day=hour,
            day_of_week=day,
            is_business_hours=is_business,
            is_weekend=is_weekend
        )


@dataclass
class TrafficMetrics:
    """Network traffic metrics."""
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    connection_count: int = 0
    unique_destinations: int = 0
    dns_queries: int = 0
    failed_connections: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class AlertHistory:
    """Historical alert information."""
    total_alerts_24h: int = 0
    total_alerts_7d: int = 0
    recent_incident_types: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.0
    mean_time_to_detect: float = 0.0  # seconds
    mean_time_to_respond: float = 0.0  # seconds


@dataclass
class ThreatIntelligence:
    """Current threat intelligence context."""
    active_campaigns: List[str] = field(default_factory=list)
    industry_threats: List[str] = field(default_factory=list)
    ioc_matches: int = 0
    threat_actor_ttps: Dict[str, List[str]] = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class AssetContext:
    """Critical asset and organizational context."""
    critical_assets: List[str] = field(default_factory=list)
    high_value_targets: List[str] = field(default_factory=list)
    active_users: int = 0
    privileged_sessions: int = 0
    maintenance_windows: List[str] = field(default_factory=list)
    business_critical_systems: List[str] = field(default_factory=list)


@dataclass
class NetworkState:
    """
    Complete network state representation for meta-learner context.

    This encapsulates all environmental context the meta-learner uses
    for decision-making.
    """
    time_features: TimeFeatures
    traffic_metrics: TrafficMetrics = field(default_factory=TrafficMetrics)
    alert_history: AlertHistory = field(default_factory=AlertHistory)
    threat_intel: ThreatIntelligence = field(default_factory=ThreatIntelligence)
    asset_context: AssetContext = field(default_factory=AssetContext)
    system_load: float = 0.0  # 0.0 to 1.0
    recent_agent_findings: Dict[str, Any] = field(default_factory=dict)

    def to_state_vector(self) -> np.ndarray:
        """
        Convert network state to numerical vector for ML models.

        Returns:
            State vector suitable for meta-learner input
        """
        vector = [
            # Time features
            self.time_features.hour_of_day / 24.0,
            self.time_features.day_of_week / 7.0,
            float(self.time_features.is_business_hours),
            float(self.time_features.is_weekend),
            float(self.time_features.is_holiday),

            # Traffic metrics (normalized)
            min(self.traffic_metrics.total_bytes_in / 1e9, 1.0),  # Normalize to GB
            min(self.traffic_metrics.total_bytes_out / 1e9, 1.0),
            min(self.traffic_metrics.connection_count / 10000.0, 1.0),
            min(self.traffic_metrics.unique_destinations / 1000.0, 1.0),
            min(self.traffic_metrics.dns_queries / 10000.0, 1.0),
            min(self.traffic_metrics.failed_connections / 1000.0, 1.0),

            # Alert history
            min(self.alert_history.total_alerts_24h / 100.0, 1.0),
            min(self.alert_history.total_alerts_7d / 1000.0, 1.0),
            self.alert_history.false_positive_rate,
            min(self.alert_history.mean_time_to_detect / 3600.0, 1.0),  # Normalize to hours

            # Threat intel
            len(self.threat_intel.active_campaigns) / 10.0,
            min(self.threat_intel.ioc_matches / 100.0, 1.0),
            self.threat_intel.risk_score,

            # Asset context
            len(self.asset_context.critical_assets) / 100.0,
            self.asset_context.active_users / 1000.0,
            self.asset_context.privileged_sessions / 100.0,

            # System state
            self.system_load
        ]

        return np.array(vector, dtype=np.float32)

    def get_context_summary(self) -> Dict[str, Any]:
        """Get human-readable context summary."""
        return {
            "timestamp": self.time_features.timestamp.isoformat(),
            "business_hours": self.time_features.is_business_hours,
            "weekend": self.time_features.is_weekend,
            "alert_volume_24h": self.alert_history.total_alerts_24h,
            "active_threat_campaigns": len(self.threat_intel.active_campaigns),
            "ioc_matches": self.threat_intel.ioc_matches,
            "threat_risk_score": self.threat_intel.risk_score,
            "critical_assets": len(self.asset_context.critical_assets),
            "system_load": self.system_load
        }
