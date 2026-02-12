"""
Network Mapper Plugin

Builds and maintains a network topology map from observed traffic.
Tracks hosts, connections, services, and communication patterns.
Supports multi-sensor environments with per-sensor network segmentation.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Set, Any, Optional
from collections import defaultdict
from pathlib import Path

from artemis.plugins import ArtemisPlugin


logger = logging.getLogger("artemis.plugins.network_mapper")


class NetworkNode:
    """Represents a network host observed by a specific sensor on a specific VLAN."""

    __slots__ = (
        'ip', 'sensor_id', 'vlan', 'hostnames', 'services', 'first_seen',
        'last_seen', 'total_connections', 'bytes_sent', 'bytes_received',
        'connections_to', 'connections_from', 'is_internal', 'roles',
        'device_type',
    )

    def __init__(self, ip: str, sensor_id: str = "default", vlan: str = "0"):
        self.ip = ip
        self.sensor_id = sensor_id
        self.vlan = vlan
        self.hostnames: Set[str] = set()
        self.services: Set[tuple] = set()  # (port, protocol) tuples
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.total_connections = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections_to: Dict[str, int] = defaultdict(int)  # IP -> count
        self.connections_from: Dict[str, int] = defaultdict(int)  # IP -> count
        self.is_internal = self._is_internal_ip(ip)
        self.roles: Set[str] = set()
        self.device_type: str = ''

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if IP is internal (RFC1918)."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
        except ValueError:
            pass

        return False

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'ip': self.ip,
            'sensor_id': self.sensor_id,
            'vlan': self.vlan,
            'hostnames': list(self.hostnames),
            'services': [f"{port}/{proto}" for port, proto in self.services],
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'total_connections': self.total_connections,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'is_internal': self.is_internal,
            'roles': list(self.roles),
            'device_type': self.device_type,
            'connections_to': dict(sorted(
                self.connections_to.items(),
                key=lambda x: x[1],
                reverse=True
            )[:50]),
            'connections_from': dict(sorted(
                self.connections_from.items(),
                key=lambda x: x[1],
                reverse=True
            )[:50])
        }


# Max entries kept in connections_to / connections_from per node.
# Prevents unbounded growth when a single host talks to millions of peers.
_MAX_PEER_TRACKING = 10_000


class NetworkMapperPlugin(ArtemisPlugin):
    """Plugin that builds network topology maps with multi-sensor support."""

    DESCRIPTION = "Builds and visualizes network topology from observed traffic"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.nodes: Dict[str, NetworkNode] = {}  # key: "sensor:vlan:ip"
        self.sensors: Set[str] = set()
        self.output_dir = Path(config.get('output_dir', 'network_maps'))
        self.auto_save_interval = config.get('auto_save_interval', 300)
        self.max_nodes = config.get('max_nodes', 500_000)
        self.last_save = datetime.now()

        # Incremental role inference: only re-evaluate touched nodes
        self._dirty_nodes: Set[str] = set()

        # Cached summary stats (invalidated on execute)
        self._stats_cache: Optional[Dict] = None
        self._stats_cache_time: Optional[datetime] = None
        self._stats_cache_ttl = 30  # seconds

    def initialize(self):
        """Initialize network mapper."""
        self.output_dir.mkdir(exist_ok=True)
        logger.info(f"Network Mapper initialized. Output: {self.output_dir}")
        self.enabled = True
        self._load_existing_map()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_existing_map(self):
        """Load existing network map from disk (supports NDJSON and legacy JSON)."""
        map_file = self.output_dir / "current_map.json"
        if not map_file.exists():
            return

        try:
            with open(map_file) as f:
                first_line = f.readline().strip()
                if not first_line:
                    return

                first_obj = json.loads(first_line)

                # Detect format: NDJSON has 'sensors' in header, legacy has 'nodes' list
                if 'nodes' in first_obj:
                    # Legacy single-JSON format
                    self._load_legacy_map(first_obj)
                else:
                    # NDJSON: first line is header, rest are nodes
                    if 'sensors' in first_obj:
                        self.sensors = set(first_obj.get('sensors', []))
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        node_data = json.loads(line)
                        self._load_node(node_data)

            logger.info(
                f"Loaded existing map with {len(self.nodes)} nodes "
                f"across {len(self.sensors)} sensors"
            )
        except Exception as e:
            logger.error(f"Error loading existing map: {e}")

    def _load_legacy_map(self, data: Dict):
        """Load from legacy single-JSON format (backward compat)."""
        for node_data in data.get('nodes', []):
            self._load_node(node_data)

    def _load_node(self, node_data: Dict):
        """Restore a single NetworkNode from serialized data."""
        ip = node_data.get('ip', '')
        sensor_id = node_data.get('sensor_id', 'default')
        vlan = node_data.get('vlan', '0')
        key = self._node_key(sensor_id, vlan, ip)

        node = NetworkNode(ip, sensor_id, vlan)
        node.hostnames = set(node_data.get('hostnames', []))
        node.services = set()
        for s in node_data.get('services', []):
            parts = s.split('/')
            if len(parts) == 2:
                node.services.add((parts[0], parts[1]))
        node.total_connections = node_data.get('total_connections', 0)
        node.bytes_sent = node_data.get('bytes_sent', 0)
        node.bytes_received = node_data.get('bytes_received', 0)
        node.roles = set(node_data.get('roles', []))
        node.device_type = node_data.get('device_type', '')

        # Restore connection maps (edges)
        for dst_ip, count in node_data.get('connections_to', {}).items():
            node.connections_to[dst_ip] = int(count)
        for src_ip, count in node_data.get('connections_from', {}).items():
            node.connections_from[src_ip] = int(count)
        # Backward compat: older maps used top_destinations/top_sources
        if not node.connections_to:
            for dst_ip, count in node_data.get('top_destinations', {}).items():
                node.connections_to[dst_ip] = int(count)
        if not node.connections_from:
            for src_ip, count in node_data.get('top_sources', {}).items():
                node.connections_from[src_ip] = int(count)

        self.nodes[key] = node
        self.sensors.add(sensor_id)

    # ------------------------------------------------------------------
    # Core execution
    # ------------------------------------------------------------------

    @staticmethod
    def _node_key(sensor_id: str, vlan: str, ip: str) -> str:
        return f"{sensor_id}:{vlan}:{ip}"

    def _get_or_create_node(
        self, sensor_id: str, vlan: str, ip: str,
    ) -> NetworkNode:
        """Get existing node or create a new one, respecting max_nodes."""
        key = self._node_key(sensor_id, vlan, ip)
        node = self.nodes.get(key)
        if node is not None:
            return node

        # Evict before adding if at capacity
        if len(self.nodes) >= self.max_nodes:
            self._evict_stale_nodes(count=max(1, self.max_nodes // 100))

        node = NetworkNode(ip, sensor_id, vlan)
        self.nodes[key] = node
        self.sensors.add(sensor_id)
        self._dirty_nodes.add(key)
        return node

    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Process network data and update map.

        Expected kwargs:
            network_connections: List of connection records
            dns_queries: List of DNS query records
        """
        connections = kwargs.get('network_connections', [])
        dns_queries = kwargs.get('dns_queries', [])

        logger.info(
            f"Processing {len(connections)} connections and "
            f"{len(dns_queries)} DNS queries"
        )

        # Process connections in batches to allow periodic progress logging
        batch_size = 50_000
        for i in range(0, len(connections), batch_size):
            batch = connections[i:i + batch_size]
            for conn in batch:
                self._process_connection(conn)
            if i + batch_size < len(connections):
                logger.info(
                    f"  Processed {i + batch_size}/{len(connections)} connections"
                )

        # Process DNS queries
        for i in range(0, len(dns_queries), batch_size):
            batch = dns_queries[i:i + batch_size]
            for dns in batch:
                self._process_dns(dns)
            if i + batch_size < len(dns_queries):
                logger.info(
                    f"  Processed {i + batch_size}/{len(dns_queries)} DNS queries"
                )

        logger.info(f"  Connections and DNS done. Inferring roles for {len(self._dirty_nodes)} nodes...")

        # Infer roles only for nodes touched this round
        self._infer_roles_incremental()

        logger.info(f"  Role inference complete. {len(self.nodes)} total nodes in map.")

        # Invalidate stats cache
        self._stats_cache = None

        # Auto-save if interval elapsed
        elapsed = (datetime.now() - self.last_save).total_seconds()
        if elapsed > self.auto_save_interval:
            self.save_map()

        return {
            'total_nodes': len(self.nodes),
            'sensors': list(self.sensors),
            'internal_nodes': sum(
                1 for n in self.nodes.values() if n.is_internal
            ),
            'external_nodes': sum(
                1 for n in self.nodes.values() if not n.is_internal
            ),
            'total_services': sum(
                len(n.services) for n in self.nodes.values()
            ),
            'map_file': str(self.output_dir / "current_map.json")
        }

    def _process_connection(self, conn: Dict):
        """Process a network connection."""
        src_ip = conn.get('source_ip')
        dst_ip = conn.get('destination_ip')
        dst_port = conn.get('destination_port')
        protocol = conn.get('protocol', 'tcp')
        bytes_out = conn.get('bytes_out', 0)
        bytes_in = conn.get('bytes_in', 0)
        sensor_id = conn.get('sensor_id', 'default')
        vlan = str(conn.get('vlan', '0'))

        if not src_ip or not dst_ip:
            return

        src_node = self._get_or_create_node(sensor_id, vlan, src_ip)
        dst_node = self._get_or_create_node(sensor_id, vlan, dst_ip)

        now = datetime.now()
        src_node.last_seen = now
        dst_node.last_seen = now

        src_node.total_connections += 1
        dst_node.total_connections += 1

        # Track peer connections with bounded size
        if len(src_node.connections_to) < _MAX_PEER_TRACKING:
            src_node.connections_to[dst_ip] += 1
        elif dst_ip in src_node.connections_to:
            src_node.connections_to[dst_ip] += 1

        if len(dst_node.connections_from) < _MAX_PEER_TRACKING:
            dst_node.connections_from[src_ip] += 1
        elif src_ip in dst_node.connections_from:
            dst_node.connections_from[src_ip] += 1

        src_node.bytes_sent += bytes_out
        src_node.bytes_received += bytes_in
        dst_node.bytes_sent += bytes_in
        dst_node.bytes_received += bytes_out

        if dst_port:
            dst_node.services.add((dst_port, protocol))

        # Mark both nodes as dirty for role inference
        src_key = self._node_key(sensor_id, vlan, src_ip)
        dst_key = self._node_key(sensor_id, vlan, dst_ip)
        self._dirty_nodes.add(src_key)
        self._dirty_nodes.add(dst_key)

    def _process_dns(self, dns: Dict):
        """Process a DNS query."""
        src_ip = dns.get('source_ip')
        domain = dns.get('domain')
        answer = dns.get('answer')
        sensor_id = dns.get('sensor_id', 'default')
        vlan = str(dns.get('vlan', '0'))

        if not src_ip:
            return

        src_node = self._get_or_create_node(sensor_id, vlan, src_ip)
        src_node.last_seen = datetime.now()

        if answer and domain:
            if '.' in answer and all(p.isdigit() for p in answer.split('.')):
                ans_node = self._get_or_create_node(sensor_id, vlan, answer)
                ans_node.hostnames.add(domain)

    # ------------------------------------------------------------------
    # Role inference (incremental)
    # ------------------------------------------------------------------

    def _infer_roles_incremental(self):
        """Infer roles only for nodes that changed since last call."""
        for node_key in self._dirty_nodes:
            node = self.nodes.get(node_key)
            if node is None:
                continue
            self._infer_node_role(node)
        self._dirty_nodes.clear()

    @staticmethod
    def _infer_node_role(node: NetworkNode):
        """Infer roles for a single node based on its behaviour."""
        node.roles.clear()

        if len(node.connections_from) > 10:
            node.roles.add('server')
        if len(node.connections_to) > len(node.connections_from) * 2:
            node.roles.add('client')
        if len(node.connections_to) > 50:
            node.roles.add('scanner')
        if len(node.connections_from) > 50:
            node.roles.add('popular')
        if (53, 'udp') in node.services or (53, 'tcp') in node.services:
            node.roles.add('dns_server')
        if (80, 'tcp') in node.services or (443, 'tcp') in node.services:
            node.roles.add('web_server')
        if any(
            p in node.services
            for p in [(25, 'tcp'), (587, 'tcp'), (993, 'tcp')]
        ):
            node.roles.add('mail_server')

    # ------------------------------------------------------------------
    # Device profiling
    # ------------------------------------------------------------------

    # Port-to-device-type classification rules.
    # Checked in order; first match wins. Each entry:
    #   label, required_ports (need >= min_match), bonus_ports (raise confidence)
    DEVICE_PROFILES = [
        {
            'type': 'domain_controller',
            'label': 'Domain Controller',
            'required': {88, 389},       # Kerberos + LDAP
            'bonus': {636, 445, 53, 135, 464, 3268},
            'min_match': 2,
        },
        {
            'type': 'dns_server',
            'label': 'DNS Server',
            'required': {53},
            'bonus': set(),
            'min_match': 1,
            'min_clients': 5,
        },
        {
            'type': 'web_server',
            'label': 'Web Server',
            'required': {80, 443, 8080, 8443},
            'bonus': set(),
            'min_match': 1,
            'min_clients': 3,
        },
        {
            'type': 'database_server',
            'label': 'Database Server',
            'required': {3306, 5432, 1433, 27017, 6379, 9200, 5984, 9042},
            'bonus': set(),
            'min_match': 1,
        },
        {
            'type': 'mail_server',
            'label': 'Mail Server',
            'required': {25, 587, 993, 143, 110, 465},
            'bonus': set(),
            'min_match': 1,
        },
        {
            'type': 'file_server',
            'label': 'File Server',
            'required': {445, 139, 2049, 21},
            'bonus': set(),
            'min_match': 1,
            'min_clients': 3,
        },
        {
            'type': 'dhcp_server',
            'label': 'DHCP Server',
            'required': {67},
            'bonus': set(),
            'min_match': 1,
        },
        {
            'type': 'ssh_server',
            'label': 'SSH Server',
            'required': {22},
            'bonus': set(),
            'min_match': 1,
            'min_clients': 2,
        },
        {
            'type': 'vpn_gateway',
            'label': 'VPN Gateway',
            'required': {500, 4500, 1194, 1723},
            'bonus': set(),
            'min_match': 1,
        },
        {
            'type': 'print_server',
            'label': 'Printer',
            'required': {9100, 515, 631},
            'bonus': set(),
            'min_match': 1,
        },
        {
            'type': 'syslog_server',
            'label': 'Syslog/SIEM',
            'required': {514, 1514, 6514},
            'bonus': set(),
            'min_match': 1,
            'min_clients': 3,
        },
        {
            'type': 'monitoring',
            'label': 'Monitoring',
            'required': {161, 162, 10050, 10051, 9090},
            'bonus': set(),
            'min_match': 1,
        },
    ]

    def _classify_device(self, ports_served: set, unique_clients: int,
                         unique_destinations: int, outbound_conns: int) -> str:
        """Classify a device based on its traffic profile.

        Args:
            ports_served: Set of integer port numbers the IP serves
            unique_clients: Number of unique IPs connecting TO this device
            unique_destinations: Number of unique IPs this device connects TO
            outbound_conns: Total outbound connection count

        Returns:
            Device type string (e.g. 'web_server', 'workstation')
        """
        for profile in self.DEVICE_PROFILES:
            matched = ports_served & profile['required']
            if len(matched) >= profile.get('min_match', 1):
                min_clients = profile.get('min_clients', 0)
                if unique_clients >= min_clients:
                    return profile['type']

        # Heuristic fallbacks
        if unique_destinations > 20 and outbound_conns > unique_clients * 3:
            return 'workstation'
        if unique_clients > 20 and len(ports_served) == 0:
            return 'gateway'
        if len(ports_served) <= 2 and unique_clients <= 3 and unique_destinations <= 5:
            return 'iot_device'

        return ''

    @staticmethod
    def _device_label(device_type: str) -> str:
        """Get human-readable label for a device type."""
        labels = {
            'domain_controller': 'DC',
            'dns_server': 'DNS',
            'web_server': 'Web',
            'database_server': 'DB',
            'mail_server': 'Mail',
            'file_server': 'Files',
            'dhcp_server': 'DHCP',
            'ssh_server': 'SSH',
            'vpn_gateway': 'VPN',
            'print_server': 'Printer',
            'syslog_server': 'SIEM',
            'monitoring': 'Monitor',
            'workstation': 'Workstation',
            'gateway': 'Gateway',
            'iot_device': 'IoT',
        }
        return labels.get(device_type, '')

    @staticmethod
    def _device_tier(device_type: str, is_internal: bool) -> int:
        """Get hierarchical tier for network diagram layout.

        Tier 0 (top)   : External / WAN / Internet
        Tier 1          : Gateways, firewalls, VPN, routers
        Tier 2          : Core infrastructure (DNS, DHCP, DC)
        Tier 3          : Servers (web, DB, mail, file, ssh, syslog, monitoring)
        Tier 4 (bottom) : End devices (workstations, printers, IoT)
        """
        if not is_internal:
            return 0
        tiers = {
            'gateway': 1,
            'vpn_gateway': 1,
            'domain_controller': 2,
            'dns_server': 2,
            'dhcp_server': 2,
            'web_server': 3,
            'database_server': 3,
            'mail_server': 3,
            'file_server': 3,
            'ssh_server': 3,
            'syslog_server': 3,
            'monitoring': 3,
            'print_server': 4,
            'workstation': 4,
            'iot_device': 4,
        }
        return tiers.get(device_type, 3)

    def profile_devices(self, splunk_connector, time_range: str = "-24h") -> Dict:
        """
        Profile network devices by querying Splunk zeek:conn logs.

        Runs two queries:
        1. Server profile: what ports each IP serves, how many clients
        2. Client profile: how many destinations each IP connects to

        Then classifies each device and updates the network map nodes.

        Args:
            splunk_connector: SplunkConnector instance
            time_range: Splunk time range to analyze (default -24h)

        Returns:
            Dict with profiling results summary
        """
        from concurrent.futures import ThreadPoolExecutor

        logger.info(f"Starting device profiling with time_range={time_range}")

        # Query 1: Server perspective — what ports does each IP serve?
        server_query = '''
        search index=zeek_conn OR index=suricata
        | spath
        | stats dc("id.orig_h") as unique_clients,
                values("id.resp_p") as ports,
                count as incoming_count
          by "id.resp_h"
        | rename "id.resp_h" as ip
        | where incoming_count >= 3
        '''

        # Query 2: Client perspective — how many destinations does each IP reach?
        client_query = '''
        search index=zeek_conn OR index=suricata
        | spath
        | stats dc("id.resp_h") as unique_destinations,
                count as outgoing_count
          by "id.orig_h"
        | rename "id.orig_h" as ip
        | where outgoing_count >= 3
        '''

        # Run both queries in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            server_future = executor.submit(
                splunk_connector.query, server_query,
                earliest_time=time_range, latest_time="now"
            )
            client_future = executor.submit(
                splunk_connector.query, client_query,
                earliest_time=time_range, latest_time="now"
            )

            server_results = server_future.result(timeout=600)
            client_results = client_future.result(timeout=600)

        logger.info(
            f"Device profiling: got {len(server_results)} server profiles, "
            f"{len(client_results)} client profiles"
        )

        # Index server data by IP
        server_data: Dict[str, Dict] = {}
        for row in server_results:
            ip = row.get('ip', '')
            if not ip:
                continue
            ports_raw = row.get('ports', [])
            if isinstance(ports_raw, str):
                ports_raw = [ports_raw]
            ports = set()
            for p in ports_raw:
                try:
                    ports.add(int(p))
                except (ValueError, TypeError):
                    pass
            server_data[ip] = {
                'unique_clients': int(row.get('unique_clients', 0)),
                'ports': ports,
                'incoming_count': int(row.get('incoming_count', 0)),
            }

        # Index client data by IP
        client_data: Dict[str, Dict] = {}
        for row in client_results:
            ip = row.get('ip', '')
            if not ip:
                continue
            client_data[ip] = {
                'unique_destinations': int(row.get('unique_destinations', 0)),
                'outgoing_count': int(row.get('outgoing_count', 0)),
            }

        # Classify each node in the network map
        classified = 0
        type_counts: Dict[str, int] = defaultdict(int)

        for key, node in self.nodes.items():
            if not node.is_internal:
                continue

            ip = node.ip
            srv = server_data.get(ip, {})
            cli = client_data.get(ip, {})

            ports_served = srv.get('ports', set())
            unique_clients = srv.get('unique_clients', 0)
            unique_dests = cli.get('unique_destinations', 0)
            outbound = cli.get('outgoing_count', 0)

            # Also include ports from the node's own services set
            for port_str, _proto in node.services:
                try:
                    ports_served.add(int(port_str))
                except (ValueError, TypeError):
                    pass

            device_type = self._classify_device(
                ports_served, unique_clients, unique_dests, outbound
            )

            if device_type:
                node.device_type = device_type
                classified += 1
                type_counts[device_type] += 1

        # Save updated map
        self.save_map()

        result = {
            'total_internal': sum(1 for n in self.nodes.values() if n.is_internal),
            'classified': classified,
            'device_types': dict(type_counts),
            'unclassified': sum(1 for n in self.nodes.values()
                                if n.is_internal and not n.device_type),
        }

        logger.info(
            f"Device profiling complete: {classified} devices classified "
            f"across {len(type_counts)} types"
        )
        for dtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            logger.info(f"  {self._device_label(dtype) or dtype}: {count}")

        return result

    # ------------------------------------------------------------------
    # Eviction
    # ------------------------------------------------------------------

    def _evict_stale_nodes(self, count: int = 1):
        """Remove the oldest nodes by last_seen to free capacity."""
        if not self.nodes:
            return

        # Partial sort: only need the `count` oldest
        nodes_by_age = sorted(
            self.nodes.items(), key=lambda x: x[1].last_seen
        )
        to_remove = min(count, len(nodes_by_age))
        for key, _ in nodes_by_age[:to_remove]:
            del self.nodes[key]

        logger.debug(f"Evicted {to_remove} stale nodes")

    # ------------------------------------------------------------------
    # Save / summary
    # ------------------------------------------------------------------

    def save_map(self) -> str:
        """Save current network map to disk using NDJSON (one node per line)."""
        map_file = self.output_dir / "current_map.json"

        with open(map_file, 'w') as f:
            # Header line
            header = {
                'timestamp': datetime.now().isoformat(),
                'total_nodes': len(self.nodes),
                'sensors': list(self.sensors),
            }
            f.write(json.dumps(header) + '\n')

            # One node per line — no need to hold full JSON tree in memory
            for node in self.nodes.values():
                f.write(json.dumps(node.to_dict()) + '\n')

        self.last_save = datetime.now()
        logger.info(
            f"Saved network map with {len(self.nodes)} nodes to {map_file}"
        )

        self._generate_summary()
        return str(map_file)

    def _generate_summary(self):
        """Generate human-readable network summary."""
        summary_file = self.output_dir / "network_summary.txt"

        # Partition nodes by sensor and internal/external
        by_sensor: Dict[str, List[NetworkNode]] = defaultdict(list)
        for node in self.nodes.values():
            by_sensor[node.sensor_id].append(node)

        with open(summary_file, 'w') as f:
            f.write("ARTEMIS NETWORK MAP SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(f"Total Nodes: {len(self.nodes)}\n")
            f.write(f"Sensors: {', '.join(sorted(self.sensors))}\n\n")

            for sensor_id in sorted(by_sensor):
                sensor_nodes = by_sensor[sensor_id]
                internal = [n for n in sensor_nodes if n.is_internal]
                external = [n for n in sensor_nodes if not n.is_internal]
                vlans = sorted(
                    {n.vlan for n in sensor_nodes if n.vlan != '0'}
                )

                f.write(f"\n{'─' * 80}\n")
                f.write(f"SENSOR: {sensor_id}\n")
                f.write(f"{'─' * 80}\n")
                f.write(
                    f"  Nodes: {len(sensor_nodes)} "
                    f"(internal: {len(internal)}, "
                    f"external: {len(external)})\n"
                )
                if vlans:
                    f.write(f"  VLANs observed: {', '.join(vlans)}\n")

                # Top internal hosts
                f.write("\n  TOP INTERNAL HOSTS (by connection count):\n")
                for node in sorted(
                    internal,
                    key=lambda n: n.total_connections,
                    reverse=True,
                )[:10]:
                    roles_str = (
                        ", ".join(node.roles) if node.roles else "unknown"
                    )
                    vlan_tag = f" [v{node.vlan}]" if node.vlan != '0' else ""
                    f.write(
                        f"    {node.ip:15s}{vlan_tag:8s} | "
                        f"{node.total_connections:6d} conns | "
                        f"Roles: {roles_str}\n"
                    )
                    if node.services:
                        svcs = ", ".join(
                            f"{p}/{pr}"
                            for p, pr in sorted(node.services)[:5]
                        )
                        f.write(
                            f"                              "
                            f"Services: {svcs}\n"
                        )

                # Top external destinations
                f.write("\n  TOP EXTERNAL DESTINATIONS:\n")
                for node in sorted(
                    external,
                    key=lambda n: n.total_connections,
                    reverse=True,
                )[:10]:
                    hostname = (
                        next(iter(node.hostnames))
                        if node.hostnames
                        else "unknown"
                    )
                    f.write(
                        f"    {node.ip:15s} | "
                        f"{node.total_connections:6d} conns | "
                        f"{hostname}\n"
                    )

                # Servers
                servers = [
                    n for n in internal
                    if 'server' in n.roles or n.services
                ]
                f.write(f"\n  IDENTIFIED SERVERS ({len(servers)}):\n")
                for node in sorted(
                    servers,
                    key=lambda n: len(n.services),
                    reverse=True,
                )[:20]:
                    svcs = ", ".join(
                        f"{p}/{pr}" for p, pr in sorted(node.services)[:8]
                    )
                    vlan_tag = f" [v{node.vlan}]" if node.vlan != '0' else ""
                    f.write(
                        f"    {node.ip:15s}{vlan_tag:8s} | "
                        f"Services: {svcs or 'none detected'}\n"
                    )

        logger.info(f"Generated network summary: {summary_file}")

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def get_summary(self, sensor_id: Optional[str] = None) -> Dict:
        """
        Get summary statistics, optionally filtered by sensor.

        Uses a short-lived cache so repeated GUI polls don't iterate
        all nodes on every request.
        """
        cache_key = sensor_id or "__all__"
        now = datetime.now()

        if (
            self._stats_cache is not None
            and self._stats_cache.get('_key') == cache_key
            and self._stats_cache_time is not None
            and (now - self._stats_cache_time).total_seconds()
            < self._stats_cache_ttl
        ):
            return self._stats_cache

        if sensor_id:
            nodes = [
                n for n in self.nodes.values()
                if n.sensor_id == sensor_id
            ]
        else:
            nodes = list(self.nodes.values())

        internal_count = sum(1 for n in nodes if n.is_internal)

        vlans = sorted({n.vlan for n in nodes if n.vlan != '0'})

        top_talkers = sorted(
            [
                (n.ip, n.sensor_id, n.vlan, n.total_connections)
                for n in nodes
            ],
            key=lambda x: x[3],
            reverse=True,
        )[:10]

        # Build device inventory grouped by type
        device_inventory: Dict[str, list] = defaultdict(list)
        for n in nodes:
            if n.device_type and n.is_internal:
                svcs = sorted(f"{p}/{pr}" for p, pr in list(n.services)[:8])
                hostnames = sorted(n.hostnames)[:3]
                device_inventory[n.device_type].append({
                    'ip': n.ip,
                    'hostnames': hostnames,
                    'services': svcs,
                    'connections': n.total_connections,
                    'sensor_id': n.sensor_id,
                })

        # Sort each category by connection count and cap at 25
        for dtype in device_inventory:
            device_inventory[dtype].sort(key=lambda x: x['connections'], reverse=True)
            device_inventory[dtype] = device_inventory[dtype][:25]

        # Ordered categories relevant to SOC
        soc_order = [
            'domain_controller', 'dns_server', 'gateway', 'vpn_gateway',
            'web_server', 'database_server', 'file_server', 'mail_server',
            'dhcp_server', 'ssh_server', 'syslog_server', 'monitoring',
            'print_server', 'workstation', 'iot_device',
        ]
        device_inventory_ordered = {}
        for dtype in soc_order:
            if dtype in device_inventory:
                device_inventory_ordered[dtype] = device_inventory[dtype]
        # Add any types not in the predefined order
        for dtype in device_inventory:
            if dtype not in device_inventory_ordered:
                device_inventory_ordered[dtype] = device_inventory[dtype]

        summary = {
            '_key': cache_key,
            'total_nodes': len(nodes),
            'sensors': sorted(self.sensors),
            'vlans': vlans,
            'internal_nodes': internal_count,
            'external_nodes': len(nodes) - internal_count,
            'total_services': sum(len(n.services) for n in nodes),
            'servers': [
                n.ip for n in nodes if 'server' in n.roles
            ][:10],
            'top_talkers': [
                {
                    'ip': ip, 'sensor_id': sid,
                    'vlan': v, 'connections': c,
                }
                for ip, sid, v, c in top_talkers
            ],
            'device_inventory': device_inventory_ordered,
            'device_counts': {
                dtype: len(items) for dtype, items in device_inventory_ordered.items()
            },
            'profiled': sum(1 for n in nodes if n.is_internal and n.device_type),
            'unprofiled': sum(1 for n in nodes if n.is_internal and not n.device_type),
        }

        self._stats_cache = summary
        self._stats_cache_time = now
        return summary

    def get_network_graph(
        self,
        sensor_id: Optional[str] = None,
        max_nodes: int = 200,
    ) -> Dict:
        """
        Get network graph suitable for visualization.

        Only returns the top `max_nodes` by connection count to keep
        the response bounded for large maps.

        Args:
            sensor_id: Optional sensor filter
            max_nodes: Maximum nodes to return (default 200)

        Returns:
            Dict with nodes, edges, and sensor list
        """
        if sensor_id:
            filtered = [
                n for n in self.nodes.values()
                if n.sensor_id == sensor_id
            ]
        else:
            filtered = list(self.nodes.values())

        # Take top N nodes by connection count
        top = sorted(
            filtered, key=lambda n: n.total_connections, reverse=True
        )[:max_nodes]
        top_keys = {
            self._node_key(n.sensor_id, n.vlan, n.ip) for n in top
        }

        nodes = []
        for node in top:
            # Show VLAN in label when tagged (non-zero)
            label = (
                f"{node.ip} (v{node.vlan})"
                if node.vlan != '0'
                else node.ip
            )
            nodes.append({
                'id': self._node_key(node.sensor_id, node.vlan, node.ip),
                'label': label,
                'sensor_id': node.sensor_id,
                'vlan': node.vlan,
                'group': 'internal' if node.is_internal else 'external',
                'size': min(node.total_connections / 10, 50),
                'roles': list(node.roles),
                'services': len(node.services),
                'device_type': node.device_type,
                'device_label': self._device_label(node.device_type),
                'tier': self._device_tier(node.device_type, node.is_internal),
            })

        # Build edges only between top nodes
        edges = []
        seen_edges: Set[tuple] = set()
        for node in top:
            src_key = self._node_key(node.sensor_id, node.vlan, node.ip)
            for dst_ip, count in sorted(
                node.connections_to.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:15]:
                dst_key = self._node_key(node.sensor_id, node.vlan, dst_ip)
                if dst_key not in top_keys:
                    continue
                edge_key = tuple(sorted([src_key, dst_key]))
                if edge_key in seen_edges:
                    continue
                edges.append({
                    'from': src_key,
                    'to': dst_key,
                    'value': count,
                    'title': f"{count} connections",
                })
                seen_edges.add(edge_key)

        return {
            'nodes': nodes,
            'edges': edges,
            'sensors': sorted(self.sensors),
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def cleanup(self):
        """Clean up plugin resources."""
        self.save_map()
        logger.info("Network Mapper cleaned up")
        self.enabled = False
