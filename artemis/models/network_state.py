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
class NetworkMapContext:
    """Context derived from the profiled network map.

    This bridges the network mapper's deep per-device knowledge into the
    agent framework so that hunting agents can reason about *what* a
    device is, not just what traffic it produced.
    """
    total_nodes: int = 0
    internal_nodes: int = 0
    external_nodes: int = 0

    # Device-type inventory  (e.g. {"server": 12, "workstation": 48, ...})
    device_type_counts: Dict[str, int] = field(default_factory=dict)

    # Quick-lookup tables keyed by IP
    ip_to_device_type: Dict[str, str] = field(default_factory=dict)
    ip_to_roles: Dict[str, List[str]] = field(default_factory=dict)
    ip_to_services: Dict[str, List[str]] = field(default_factory=dict)
    ip_to_os: Dict[str, str] = field(default_factory=dict)
    ip_to_hostnames: Dict[str, List[str]] = field(default_factory=dict)

    # Infrastructure awareness
    gateways: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    domain_controllers: List[str] = field(default_factory=list)
    ntp_servers: List[str] = field(default_factory=list)

    # Per-device traffic baselines (ip -> {avg_conns, avg_bytes, ...})
    baselines: Dict[str, Dict[str, float]] = field(default_factory=dict)

    def device_type_for(self, ip: str) -> str:
        """Return the profiled device type for an IP, or 'unknown'."""
        return self.ip_to_device_type.get(ip, 'unknown')

    def roles_for(self, ip: str) -> List[str]:
        """Return the inferred roles for an IP."""
        return self.ip_to_roles.get(ip, [])

    def is_server(self, ip: str) -> bool:
        return self.ip_to_device_type.get(ip, '') == 'server'

    def is_workstation(self, ip: str) -> bool:
        return self.ip_to_device_type.get(ip, '') == 'workstation'

    def is_infrastructure(self, ip: str) -> bool:
        return ip in self.gateways or ip in self.dns_servers or ip in self.domain_controllers

    @classmethod
    def from_network_map(cls, nodes: Dict[str, Any]) -> 'NetworkMapContext':
        """Build context from network mapper's node dictionary.

        Args:
            nodes: Dict mapping node-id -> node dict (as returned by
                   NetworkMapperPlugin.get_network_graph() or the raw
                   ``nodes`` dict on the plugin).
        """
        ctx = cls()
        device_counts: Dict[str, int] = {}

        for node_id, node in nodes.items():
            # node can be a dict (from to_dict) or the raw NetworkNode
            if hasattr(node, 'ip'):
                # Raw NetworkNode object
                ip = node.ip
                dtype = getattr(node, 'device_type', 'unknown') or 'unknown'
                roles = list(getattr(node, 'roles', set()) or set())
                services = [f"{p}/{pr}" for p, pr in (getattr(node, 'services', set()) or set())]
                os_info = getattr(node, 'os_info', '') or ''
                hostnames = list(getattr(node, 'hostnames', set()) or set())
                is_int = getattr(node, 'is_internal', True)
                is_gw = bool(getattr(node, 'is_gateway_for', None))
                total_conns = getattr(node, 'total_connections', 0) or 0
                bytes_in = getattr(node, 'bytes_received', 0) or 0
                bytes_out = getattr(node, 'bytes_sent', 0) or 0
                ntp = getattr(node, 'ntp_server', False)
            else:
                # Dict representation
                ip = node.get('ip', node_id)
                dtype = node.get('device_type', 'unknown') or 'unknown'
                roles = node.get('roles', [])
                services = node.get('services', [])
                if services and isinstance(services[0], (list, tuple)):
                    services = [f"{p}/{pr}" for p, pr in services]
                os_info = node.get('os_info', '') or ''
                hostnames = node.get('hostnames', [])
                is_int = node.get('is_internal', True)
                is_gw = bool(node.get('is_gateway_for'))
                total_conns = node.get('total_connections', 0) or 0
                bytes_in = node.get('bytes_received', 0) or 0
                bytes_out = node.get('bytes_sent', 0) or 0
                ntp = node.get('ntp_server', False)

            ctx.total_nodes += 1
            if is_int:
                ctx.internal_nodes += 1
            else:
                ctx.external_nodes += 1

            device_counts[dtype] = device_counts.get(dtype, 0) + 1
            ctx.ip_to_device_type[ip] = dtype
            ctx.ip_to_roles[ip] = roles
            ctx.ip_to_services[ip] = services
            ctx.ip_to_os[ip] = os_info
            ctx.ip_to_hostnames[ip] = hostnames

            if is_gw:
                ctx.gateways.append(ip)
            if 'dns_server' in roles:
                ctx.dns_servers.append(ip)
            if 'domain_controller' in roles or 'dc' in roles:
                ctx.domain_controllers.append(ip)
            if ntp:
                ctx.ntp_servers.append(ip)

            # Store per-device baseline
            ctx.baselines[ip] = {
                'total_connections': total_conns,
                'bytes_in': bytes_in,
                'bytes_out': bytes_out,
            }

        ctx.device_type_counts = device_counts
        return ctx


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
    network_map: NetworkMapContext = field(default_factory=NetworkMapContext)
    system_load: float = 0.0  # 0.0 to 1.0
    recent_agent_findings: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_data_with_map(
        cls,
        hunting_data: Dict[str, Any],
        network_nodes: Dict[str, Any],
    ) -> 'NetworkState':
        """Create NetworkState enriched with network map context.

        This is the preferred factory when the network mapper has been
        populated — it gives hunting agents full visibility into the
        profiled device inventory so they can correlate traffic with
        device identity.
        """
        state = cls.from_data(hunting_data)
        state.network_map = NetworkMapContext.from_network_map(network_nodes)

        # Enrich AssetContext from the map
        for ip, dtype in state.network_map.ip_to_device_type.items():
            if dtype in ('server', 'domain_controller'):
                state.asset_context.high_value_targets.append(ip)
        state.asset_context.critical_assets = (
            state.network_map.gateways
            + state.network_map.dns_servers
            + state.network_map.domain_controllers
        )
        return state

    @classmethod
    def from_data(cls, hunting_data: Dict[str, Any]) -> 'NetworkState':
        """
        Create NetworkState from hunting data collected by DataPipeline.

        Args:
            hunting_data: Dict containing network_connections, dns_queries, etc.

        Returns:
            NetworkState instance populated from the hunting data
        """
        # Time features from current time
        time_features = TimeFeatures.from_timestamp(datetime.now())

        # Traffic metrics from network connections
        traffic_metrics = TrafficMetrics()
        network_connections = hunting_data.get('network_connections', [])
        dns_queries = hunting_data.get('dns_queries', [])

        # _counts holds real totals when agent_data is a sample
        _counts = hunting_data.get('_counts', {})

        if network_connections:
            traffic_metrics.connection_count = _counts.get(
                'network_connections', len(network_connections))
            traffic_metrics.total_bytes_in = sum(
                conn.get('orig_bytes', 0) for conn in network_connections
            )
            traffic_metrics.total_bytes_out = sum(
                conn.get('resp_bytes', 0) for conn in network_connections
            )

            # Count unique destinations
            destinations = set(conn.get('id.resp_h', '') for conn in network_connections)
            traffic_metrics.unique_destinations = len(destinations)

            # Count failed connections
            traffic_metrics.failed_connections = sum(
                1 for conn in network_connections
                if conn.get('conn_state', '') in ['S0', 'REJ', 'RSTO', 'RSTR']
            )

            # Protocol distribution
            protocols = {}
            for conn in network_connections:
                proto = conn.get('proto', 'unknown')
                protocols[proto] = protocols.get(proto, 0) + 1
            traffic_metrics.protocol_distribution = protocols

        if dns_queries:
            traffic_metrics.dns_queries = _counts.get(
                'dns_queries', len(dns_queries))

        # Alert history from IDS alerts
        alert_history = AlertHistory()
        ids_alerts = hunting_data.get('ids_alerts', [])
        if ids_alerts:
            alert_history.total_alerts_24h = len(ids_alerts)
            alert_history.recent_incident_types = list(set(
                alert.get('alert.category', 'unknown') for alert in ids_alerts[:10]
            ))

        # Threat intel - basic for now
        threat_intel = ThreatIntelligence()

        # Asset context - basic for now
        asset_context = AssetContext()

        return cls(
            time_features=time_features,
            traffic_metrics=traffic_metrics,
            alert_history=alert_history,
            threat_intel=threat_intel,
            asset_context=asset_context,
            system_load=0.5  # Default moderate load
        )

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
