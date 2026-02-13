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
        'ip', 'sensor_id', 'vlan', 'hostnames', 'netbios_names', 'domain',
        'mac_address', 'vendor',
        'services', 'first_seen',
        'last_seen', 'total_connections', 'bytes_sent', 'bytes_received',
        'connections_to', 'connections_from', 'is_internal', 'roles',
        'device_type',
    )

    def __init__(self, ip: str, sensor_id: str = "default", vlan: str = "0"):
        self.ip = ip
        self.sensor_id = sensor_id
        self.vlan = vlan
        self.hostnames: Set[str] = set()
        self.netbios_names: Set[str] = set()  # NetBIOS/NTLM hostnames
        self.domain: str = ''  # AD domain or workgroup name
        self.mac_address: str = ''  # MAC address (from DHCP/L2 logs)
        self.vendor: str = ''  # Hardware vendor from OUI lookup
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
            'netbios_names': list(self.netbios_names),
            'domain': self.domain,
            'mac_address': self.mac_address,
            'vendor': self.vendor,
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
        node.netbios_names = set(node_data.get('netbios_names', []))
        node.domain = node_data.get('domain', '')
        node.mac_address = node_data.get('mac_address', '')
        node.vendor = node_data.get('vendor', '')
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
            ntlm_logs: List of NTLM authentication records (optional)
        """
        connections = kwargs.get('network_connections', [])
        dns_queries = kwargs.get('dns_queries', [])
        ntlm_logs = kwargs.get('ntlm_logs', [])

        logger.info(
            f"Processing {len(connections)} connections, "
            f"{len(dns_queries)} DNS queries, and "
            f"{len(ntlm_logs)} NTLM events"
        )

        # Process connections in batches to allow periodic progress logging
        batch_size = 500_000
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

        # Process NTLM logs for NetBIOS name enrichment
        if ntlm_logs:
            for ntlm in ntlm_logs:
                self._process_ntlm(ntlm)
            logger.info(f"  Processed {len(ntlm_logs)} NTLM events for NetBIOS enrichment")

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

    def _process_ntlm(self, ntlm: Dict):
        """Process an NTLM authentication event for NetBIOS name enrichment."""
        src_ip = ntlm.get('source_ip')
        dst_ip = ntlm.get('dest_ip')
        hostname = ntlm.get('hostname', '')        # Client NetBIOS name
        domainname = ntlm.get('domainname', '')     # Domain/workgroup
        server_nb = ntlm.get('server_nb_computer_name', '')  # Server NetBIOS name
        server_dns = ntlm.get('server_dns_computer_name', '')
        sensor_id = ntlm.get('sensor_id', 'default')
        vlan = str(ntlm.get('vlan', '0'))

        # Enrich the client (source) node
        if src_ip:
            src_node = self._get_or_create_node(sensor_id, vlan, src_ip)
            src_node.last_seen = datetime.now()
            if hostname and hostname != '-':
                src_node.netbios_names.add(hostname.upper())
            if domainname and domainname != '-':
                src_node.domain = domainname.upper()

        # Enrich the server (destination) node
        if dst_ip:
            dst_node = self._get_or_create_node(sensor_id, vlan, dst_ip)
            dst_node.last_seen = datetime.now()
            if server_nb and server_nb != '-':
                dst_node.netbios_names.add(server_nb.upper())
            if server_dns and server_dns != '-':
                dst_node.hostnames.add(server_dns.lower())
            if domainname and domainname != '-':
                dst_node.domain = domainname.upper()

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

    # OUI (Organizationally Unique Identifier) lookup table.
    # Maps the first 3 octets of a MAC address to the hardware vendor.
    # Covers major enterprise, networking, virtualization, and IoT vendors.
    OUI_TABLE = {
        # Virtualization
        '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
        '00:1C:14': 'VMware', '00:15:5D': 'Microsoft Hyper-V',
        '52:54:00': 'QEMU/KVM', '00:16:3E': 'Xen',
        '08:00:27': 'VirtualBox',
        # Networking equipment
        '00:1A:A1': 'Cisco', '00:1B:0D': 'Cisco', '00:1E:BD': 'Cisco',
        '00:22:55': 'Cisco', '00:24:50': 'Cisco', '00:26:0B': 'Cisco',
        '00:1D:A2': 'Cisco', '00:0D:ED': 'Cisco', 'C0:62:6B': 'Cisco',
        '68:86:A7': 'Cisco', '2C:33:11': 'Cisco', 'F4:CF:E2': 'Cisco',
        '5C:FC:66': 'Cisco', '00:1C:0F': 'Cisco',
        '00:04:96': 'Juniper', '00:05:85': 'Juniper', '00:1F:12': 'Juniper',
        '28:C0:DA': 'Juniper', '40:B4:F0': 'Juniper', '84:B5:9C': 'Juniper',
        '2C:6B:F5': 'Juniper', '54:E0:32': 'Juniper',
        '00:09:0F': 'Fortinet', '00:60:6E': 'Fortinet', '70:4C:A5': 'Fortinet',
        '08:5B:0E': 'Fortinet', 'E8:1C:BA': 'Fortinet',
        '00:1A:8C': 'Palo Alto', '00:86:9C': 'Palo Alto', 'B4:0C:25': 'Palo Alto',
        '00:0B:86': 'Aruba', '00:24:6C': 'Aruba', '20:4C:03': 'Aruba',
        '6C:F3:7F': 'Aruba', '94:B4:0F': 'Aruba', 'D8:C7:C8': 'Aruba',
        '00:12:F2': 'Brocade', '00:05:33': 'Brocade', '00:27:F8': 'Brocade',
        '00:E0:52': 'Brocade',
        'B4:FB:E4': 'Ubiquiti', '00:27:22': 'Ubiquiti', '24:A4:3C': 'Ubiquiti',
        '68:72:51': 'Ubiquiti', 'F0:9F:C2': 'Ubiquiti', 'AC:8B:A9': 'Ubiquiti',
        '74:AC:B9': 'Ubiquiti', '78:8A:20': 'Ubiquiti', 'FC:EC:DA': 'Ubiquiti',
        '00:18:0A': 'Meraki', '00:18:74': 'Meraki', '0C:8D:DB': 'Meraki',
        '34:56:FE': 'Meraki', '68:3A:1E': 'Meraki', 'E0:55:3D': 'Meraki',
        '00:04:0B': 'CheckPoint', '00:1C:7F': 'CheckPoint',
        # Server / enterprise
        '00:25:90': 'SuperMicro', '00:25:B5': 'SuperMicro',
        '0C:C4:7A': 'SuperMicro', 'AC:1F:6B': 'SuperMicro',
        '00:14:5E': 'IBM', '00:1A:64': 'IBM', '00:21:5E': 'IBM',
        '00:10:18': 'Broadcom', '98:03:9B': 'Broadcom',
        '00:17:A4': 'HP/HPE', '00:1C:C4': 'HP/HPE', '00:22:64': 'HP/HPE',
        '00:25:B3': 'HP/HPE', '3C:D9:2B': 'HP/HPE', '48:0F:CF': 'HP/HPE',
        '94:18:82': 'HP/HPE', 'A0:B3:CC': 'HP/HPE', 'A4:5D:36': 'HP/HPE',
        '14:02:EC': 'HP/HPE', '00:1E:0B': 'HP/HPE',
        '00:1E:C9': 'Dell', '14:18:77': 'Dell', '18:A9:9B': 'Dell',
        '24:6E:96': 'Dell', '34:17:EB': 'Dell', 'B0:83:FE': 'Dell',
        'F0:1F:AF': 'Dell', 'F4:8E:38': 'Dell', '00:14:22': 'Dell',
        '70:B5:E8': 'Dell', '4C:76:25': 'Dell',
        '08:94:EF': 'Lenovo', '54:AB:3A': 'Lenovo', '98:FA:9B': 'Lenovo',
        'E8:2A:44': 'Lenovo', '00:06:1B': 'Lenovo',
        # Endpoints / consumer
        '00:03:93': 'Apple', '00:0A:27': 'Apple', '00:0A:95': 'Apple',
        '00:1B:63': 'Apple', '00:1E:C2': 'Apple', '00:25:BC': 'Apple',
        '14:10:9F': 'Apple', '20:C9:D0': 'Apple', '3C:15:C2': 'Apple',
        '44:2A:60': 'Apple', '54:26:96': 'Apple', '60:03:08': 'Apple',
        '70:56:81': 'Apple', '78:31:C1': 'Apple', '80:E6:50': 'Apple',
        '84:FC:FE': 'Apple', '8C:85:90': 'Apple', 'A4:B1:97': 'Apple',
        'A8:66:7F': 'Apple', 'AC:BC:32': 'Apple', 'B8:8D:12': 'Apple',
        'BC:52:B7': 'Apple', 'C8:69:CD': 'Apple', 'D8:30:62': 'Apple',
        'F0:B4:79': 'Apple', 'F4:5C:89': 'Apple',
        'B4:2E:99': 'Intel', '00:1B:21': 'Intel', '00:1E:64': 'Intel',
        '00:1F:3B': 'Intel', '3C:97:0E': 'Intel', '48:51:B7': 'Intel',
        '68:05:CA': 'Intel', '8C:EC:4B': 'Intel', 'A4:4C:C8': 'Intel',
        '60:36:DD': 'Intel',
        '00:50:F2': 'Microsoft', '28:18:78': 'Microsoft',
        '7C:1E:52': 'Microsoft', '00:17:FA': 'Microsoft',
        '60:45:BD': 'Microsoft', 'DC:B4:C4': 'Microsoft',
        # IoT / embedded
        'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
        'E4:5F:01': 'Raspberry Pi', '28:CD:C1': 'Raspberry Pi',
        '2C:CF:67': 'Espressif (ESP)', '84:CC:A8': 'Espressif (ESP)',
        'A4:CF:12': 'Espressif (ESP)', '24:6F:28': 'Espressif (ESP)',
        '30:AE:A4': 'Espressif (ESP)', 'AC:67:B2': 'Espressif (ESP)',
        '18:FE:34': 'Espressif (ESP)',
        'B0:A7:B9': 'Hikvision', '44:19:B6': 'Hikvision',
        '54:C4:15': 'Hikvision', 'C0:56:E3': 'Hikvision',
        '9C:8E:CD': 'Dahua', '3C:EF:8C': 'Dahua',
        '00:17:C8': 'Samsung', '00:21:19': 'Samsung',
        '00:26:37': 'Samsung', '08:37:3D': 'Samsung',
        '14:49:E0': 'Samsung', '54:92:BE': 'Samsung',
        '78:52:1A': 'Samsung', 'A8:06:00': 'Samsung',
        '88:32:9B': 'Samsung', 'C0:97:27': 'Samsung',
        # Printers
        '00:00:48': 'Epson', '00:1B:A9': 'Brother', '00:1E:8F': 'Canon',
        '00:15:99': 'Xerox', '00:00:AA': 'Xerox', '00:17:08': 'Hewlett Packard',
        '00:80:77': 'Brother', '30:CD:A7': 'Roku',
        # Wireless / mobile
        '00:1A:11': 'Google', 'F4:F5:D8': 'Google', '54:60:09': 'Google',
        'A4:77:33': 'Google', '3C:5A:B4': 'Google',
        '40:4E:36': 'HTC', '00:23:76': 'HTC',
        '10:68:3F': 'LG', '00:1E:75': 'LG', '00:22:A9': 'LG',
        '34:FC:EF': 'LG', '88:C9:D0': 'LG',
        '00:BB:3A': 'Amazon', 'F0:27:2D': 'Amazon', '40:B4:CD': 'Amazon',
        '74:75:48': 'Amazon', 'A0:02:DC': 'Amazon',
        'FC:A6:67': 'Amazon', '44:65:0D': 'Amazon',
        '68:54:FD': 'Amazon', 'B4:7C:9C': 'Amazon',
    }

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

    @classmethod
    def _lookup_oui(cls, mac: str) -> str:
        """Look up hardware vendor from MAC address OUI prefix."""
        if not mac or len(mac) < 8:
            return ''
        prefix = mac[:8].upper()
        return cls.OUI_TABLE.get(prefix, '')

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

        # Query 3: NTLM logs — NetBIOS hostname and domain enrichment
        ntlm_query = '''
        search index=zeek_ntlm
        | spath
        | eval vlan=coalesce(vlan, "0")
        | table _time host vlan id.orig_h id.resp_h hostname domainname server_nb_computer_name server_dns_computer_name
        | rename host as sensor_id, "id.orig_h" as source_ip, "id.resp_h" as dest_ip
        '''

        # Query 4: Kerberos logs — responder IPs are KDCs (Domain Controllers)
        kerberos_query = '''
        search index=zeek_kerberos
        | spath
        | stats dc("id.orig_h") as unique_clients,
                values(service) as services,
                count as auth_count
          by "id.resp_h"
        | rename "id.resp_h" as ip
        | where auth_count >= 3
        '''

        # Query 5: DHCP logs — IP-to-MAC address mappings
        dhcp_query = '''
        search index=zeek_dhcp
        | spath
        | where isnotnull(assigned_addr) AND isnotnull(mac)
        | stats latest(mac) as mac,
                latest(host_name) as dhcp_hostname
          by assigned_addr
        | rename assigned_addr as ip
        '''

        # Run all five queries in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            server_future = executor.submit(
                splunk_connector.query, server_query,
                earliest_time=time_range, latest_time="now"
            )
            client_future = executor.submit(
                splunk_connector.query, client_query,
                earliest_time=time_range, latest_time="now"
            )
            ntlm_future = executor.submit(
                splunk_connector.query, ntlm_query,
                earliest_time=time_range, latest_time="now"
            )
            kerberos_future = executor.submit(
                splunk_connector.query, kerberos_query,
                earliest_time=time_range, latest_time="now"
            )
            dhcp_future = executor.submit(
                splunk_connector.query, dhcp_query,
                earliest_time=time_range, latest_time="now"
            )

            server_results = server_future.result(timeout=600)
            client_results = client_future.result(timeout=600)
            try:
                ntlm_results = ntlm_future.result(timeout=600)
            except Exception:
                ntlm_results = []  # NTLM index may not exist
            try:
                kerberos_results = kerberos_future.result(timeout=600)
            except Exception:
                kerberos_results = []  # Kerberos index may not exist
            try:
                dhcp_results = dhcp_future.result(timeout=600)
            except Exception:
                dhcp_results = []  # DHCP index may not exist

        # Build set of KDC IPs from Kerberos logs (these ARE domain controllers)
        kdc_ips: set = set()
        for row in kerberos_results:
            ip = row.get('ip', '')
            if ip:
                kdc_ips.add(ip)

        # Build map of NTLM auth server IPs -> unique client count
        # Servers receiving NTLM auths from many clients are likely DCs
        ntlm_server_clients: Dict[str, set] = defaultdict(set)

        # Enrich nodes with NTLM data (NetBIOS names + domain)
        ntlm_enriched = 0
        for row in ntlm_results:
            src_ip = row.get('source_ip', '')
            dst_ip = row.get('dest_ip', '')
            hostname = row.get('hostname', '')
            domainname = row.get('domainname', '')
            server_nb = row.get('server_nb_computer_name', '')
            server_dns = row.get('server_dns_computer_name', '')

            # Track which servers receive NTLM auths from many clients
            if src_ip and dst_ip:
                ntlm_server_clients[dst_ip].add(src_ip)

            # Find matching nodes and enrich
            for key, node in self.nodes.items():
                if node.ip == src_ip and hostname and hostname != '-':
                    node.netbios_names.add(hostname.upper())
                    if domainname and domainname != '-':
                        node.domain = domainname.upper()
                    ntlm_enriched += 1
                if node.ip == dst_ip:
                    if server_nb and server_nb != '-':
                        node.netbios_names.add(server_nb.upper())
                    if server_dns and server_dns != '-':
                        node.hostnames.add(server_dns.lower())
                    if domainname and domainname != '-':
                        node.domain = domainname.upper()
                    ntlm_enriched += 1

        # IPs that are heavy NTLM auth servers (5+ unique clients)
        ntlm_auth_servers = {
            ip for ip, clients in ntlm_server_clients.items()
            if len(clients) >= 5
        }

        # Enrich nodes with DHCP data (MAC address + OUI vendor lookup)
        dhcp_enriched = 0
        for row in dhcp_results:
            ip = row.get('ip', '')
            mac = row.get('mac', '')
            dhcp_hostname = row.get('dhcp_hostname', '')
            if not ip or not mac:
                continue
            # Normalize MAC to colon-separated uppercase
            mac = mac.strip().upper().replace('-', ':')
            for key, node in self.nodes.items():
                if node.ip == ip:
                    node.mac_address = mac
                    node.vendor = self._lookup_oui(mac)
                    if dhcp_hostname and dhcp_hostname != '-' and dhcp_hostname != 'null':
                        node.hostnames.add(dhcp_hostname.lower())
                    dhcp_enriched += 1

        logger.info(
            f"Device profiling: got {len(server_results)} server profiles, "
            f"{len(client_results)} client profiles, "
            f"{len(ntlm_results)} NTLM events ({ntlm_enriched} enrichments), "
            f"{len(kerberos_results)} Kerberos responders, "
            f"{len(kdc_ips)} KDC IPs, {len(ntlm_auth_servers)} heavy NTLM auth servers, "
            f"{len(dhcp_results)} DHCP leases ({dhcp_enriched} MAC enrichments)"
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
        dc_ports = {88, 389, 636, 3268, 135, 464}  # Kerberos, LDAP, LDAPS, GC, RPC, Kpasswd

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

            # DC detection: use Kerberos/NTLM evidence before port-only check
            device_type = ''
            if ip in kdc_ips:
                # Confirmed KDC from Kerberos logs — this IS a DC
                device_type = 'domain_controller'
            elif ip in ntlm_auth_servers and ports_served & dc_ports:
                # Heavy NTLM auth server + at least one DC port
                device_type = 'domain_controller'
            else:
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
                    'netbios_names': sorted(n.netbios_names)[:3],
                    'domain': n.domain,
                    'mac_address': n.mac_address,
                    'vendor': n.vendor,
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

        External IPs are collapsed into a single "Internet" cloud node.
        Each internal node includes its external connection details so the
        UI can display them on click.

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

        # Separate internal and external nodes
        internal_nodes = [n for n in filtered if n.is_internal]
        external_keys = {
            self._node_key(n.sensor_id, n.vlan, n.ip)
            for n in filtered if not n.is_internal
        }

        # Take top N internal nodes by connection count
        top = sorted(
            internal_nodes, key=lambda n: n.total_connections, reverse=True
        )[:max_nodes]
        top_keys = {
            self._node_key(n.sensor_id, n.vlan, n.ip) for n in top
        }

        nodes = []
        internet_total_conns = 0
        internet_unique_ips = set()

        for node in top:
            # Build label: prefer NetBIOS name, fall back to IP
            nb_name = next(iter(sorted(node.netbios_names)), '')
            if nb_name:
                label = f"{nb_name}\n{node.ip}"
            elif node.vlan != '0':
                label = f"{node.ip} (v{node.vlan})"
            else:
                label = node.ip

            # Collect external connections for this node
            ext_conns_out = []
            for dst_ip, count in sorted(
                node.connections_to.items(),
                key=lambda x: x[1], reverse=True,
            ):
                dst_key = self._node_key(node.sensor_id, node.vlan, dst_ip)
                if dst_key in external_keys:
                    ext_conns_out.append({'ip': dst_ip, 'count': count})
                    internet_unique_ips.add(dst_ip)
                    internet_total_conns += count

            ext_conns_in = []
            for src_ip, count in sorted(
                node.connections_from.items(),
                key=lambda x: x[1], reverse=True,
            ):
                src_key = self._node_key(node.sensor_id, node.vlan, src_ip)
                if src_key in external_keys:
                    ext_conns_in.append({'ip': src_ip, 'count': count})
                    internet_unique_ips.add(src_ip)

            # Collect internal peer connections for click details
            int_conns = []
            for dst_ip, count in sorted(
                node.connections_to.items(),
                key=lambda x: x[1], reverse=True,
            )[:20]:
                dst_key = self._node_key(node.sensor_id, node.vlan, dst_ip)
                if dst_key in top_keys and dst_key != self._node_key(node.sensor_id, node.vlan, node.ip):
                    int_conns.append({'ip': dst_ip, 'count': count})

            nodes.append({
                'id': self._node_key(node.sensor_id, node.vlan, node.ip),
                'label': label,
                'sensor_id': node.sensor_id,
                'vlan': node.vlan,
                'group': 'internal',
                'size': min(node.total_connections / 10, 50),
                'roles': list(node.roles),
                'services': len(node.services),
                'device_type': node.device_type,
                'device_label': self._device_label(node.device_type),
                'tier': self._device_tier(node.device_type, node.is_internal),
                'netbios_names': sorted(node.netbios_names)[:3],
                'domain': node.domain,
                'hostnames': sorted(node.hostnames)[:3],
                'external_connections_out': ext_conns_out[:50],
                'external_connections_in': ext_conns_in[:50],
                'internal_connections': int_conns,
            })

        # Add a single "Internet" cloud node if there are external connections
        has_external = len(internet_unique_ips) > 0
        internet_node_id = '__internet__'

        if has_external:
            nodes.append({
                'id': internet_node_id,
                'label': f"Internet\n{len(internet_unique_ips)} IPs",
                'group': 'internet',
                'size': 50,
                'roles': [],
                'services': 0,
                'device_type': 'internet',
                'device_label': 'Internet',
                'tier': 0,
                'unique_ips': len(internet_unique_ips),
                'total_connections': internet_total_conns,
            })

        # Build edges between internal nodes
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

        # Build edges from internal nodes to the Internet cloud
        if has_external:
            for node in top:
                src_key = self._node_key(node.sensor_id, node.vlan, node.ip)
                ext_count = sum(
                    count for dst_ip, count in node.connections_to.items()
                    if self._node_key(node.sensor_id, node.vlan, dst_ip) in external_keys
                )
                if ext_count > 0:
                    edges.append({
                        'from': src_key,
                        'to': internet_node_id,
                        'value': ext_count,
                        'title': f"{ext_count} external connections",
                    })

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
