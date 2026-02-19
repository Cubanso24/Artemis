"""
Network Mapper Plugin

Builds and maintains a network topology map from observed traffic.
Tracks hosts, connections, services, and communication patterns.
Supports multi-sensor environments with per-sensor network segmentation.
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Optional, Tuple
from collections import defaultdict
from pathlib import Path

from artemis.plugins import ArtemisPlugin


logger = logging.getLogger("artemis.plugins.network_mapper")


class MacIpBinding:
    """A single MAC-to-IP binding observed at a point in time."""

    __slots__ = ('ip', 'vlan', 'sensor_id', 'hostname', 'first_seen', 'last_seen')

    def __init__(self, ip: str, vlan: str = "0", sensor_id: str = "default",
                 hostname: str = "", first_seen: str = "", last_seen: str = ""):
        self.ip = ip
        self.vlan = vlan
        self.sensor_id = sensor_id
        self.hostname = hostname
        self.first_seen = first_seen or datetime.now().isoformat()
        self.last_seen = last_seen or self.first_seen

    def to_dict(self) -> Dict:
        return {
            'ip': self.ip,
            'vlan': self.vlan,
            'sensor_id': self.sensor_id,
            'hostname': self.hostname,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
        }


class NetworkNode:
    """Represents a network host observed by a specific sensor on a specific VLAN."""

    __slots__ = (
        'ip', 'sensor_id', 'vlan', 'hostnames', 'netbios_names', 'domain',
        'mac_address', 'vendor', 'is_virtual', 'virtual_platform',
        'os_info', 'device_model', 'software', 'user_agents',
        'services', 'first_seen',
        'last_seen', 'total_connections', 'bytes_sent', 'bytes_received',
        'connections_to', 'connections_from', 'is_internal', 'roles',
        'device_type',
        # Deep fingerprint fields
        'dhcp_client_fqdn', 'dhcp_vendor_class',
        'ja3_fingerprints', 'ja3s_fingerprints',
        'tls_server_names', 'tls_versions_seen',
        'dns_profile',
        'rdp_info',
        'cert_subjects', 'cert_issuers',
        'file_mime_types',
        # Router/firewall/gateway fields
        'is_gateway_for',       # set of /24 subnets this device is a gateway for
        'gateway_evidence',     # list of evidence strings explaining why detected
        # Host identification (combined Zeek Workbench-style)
        'host_id',              # dict with unified host identification summary
        'known_services_names', # service names from zeek_known_services
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
        self.is_virtual: bool = False  # True if MAC OUI indicates a virtual machine
        self.virtual_platform: str = ''  # Hypervisor platform (VMware, Hyper-V, etc.)
        self.os_info: str = ''  # OS / system description (from SNMP sysDescr, SSH banner, etc.)
        self.device_model: str = ''  # Device model (from SNMP sysObjectID OID mapping)
        self.software: List[str] = []  # Detected software names/versions
        self.user_agents: List[str] = []  # HTTP User-Agent strings observed from this IP
        self.services: Set[tuple] = set()  # (port, protocol) tuples
        # Deep fingerprint fields
        self.dhcp_client_fqdn: str = ''  # FQDN from DHCP negotiation
        self.dhcp_vendor_class: str = ''  # DHCP Option 60 vendor class identifier
        self.ja3_fingerprints: List[str] = []  # JA3 TLS client hello hashes
        self.ja3s_fingerprints: List[str] = []  # JA3S TLS server hello hashes
        self.tls_server_names: List[str] = []  # SNI hostnames from outgoing TLS connections
        self.tls_versions_seen: List[str] = []  # TLS versions observed (e.g. TLSv12, TLSv13)
        self.dns_profile: Dict = {}  # DNS behavioral profile {query_count, unique_domains, top_tlds, nxdomain_ratio, query_types}
        self.rdp_info: Dict = {}  # RDP client details {cookie, client_build, client_name, keyboard_layout, resolution}
        self.cert_subjects: List[str] = []  # x509 certificate subjects served
        self.cert_issuers: List[str] = []  # x509 certificate issuers
        self.file_mime_types: List[str] = []  # MIME types of files transferred by this host
        self.is_gateway_for: Set[str] = set()  # /24 subnets this device acts as gateway for
        self.gateway_evidence: List[str] = []  # Evidence strings for router/firewall detection
        self.host_id: Dict = {}  # Unified host identification: {os, os_source, confidence, signals}
        self.known_services_names: List[str] = []  # Named services from zeek_known_services
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
            'is_virtual': self.is_virtual,
            'virtual_platform': self.virtual_platform,
            'os_info': self.os_info,
            'device_model': self.device_model,
            'software': self.software[:10],
            'user_agents': self.user_agents[:20],
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
            )[:50]),
            # Deep fingerprint fields
            'dhcp_client_fqdn': self.dhcp_client_fqdn,
            'dhcp_vendor_class': self.dhcp_vendor_class,
            'ja3_fingerprints': self.ja3_fingerprints[:20],
            'ja3s_fingerprints': self.ja3s_fingerprints[:20],
            'tls_server_names': self.tls_server_names[:30],
            'tls_versions_seen': self.tls_versions_seen[:10],
            'dns_profile': self.dns_profile,
            'rdp_info': self.rdp_info,
            'cert_subjects': self.cert_subjects[:20],
            'cert_issuers': self.cert_issuers[:20],
            'file_mime_types': self.file_mime_types[:20],
            'is_gateway_for': sorted(self.is_gateway_for),
            'gateway_evidence': self.gateway_evidence[:10],
            'host_id': self.host_id,
            'known_services_names': self.known_services_names[:30],
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

        # MAC-to-IP history: tracks all IPs a MAC has been assigned over time.
        # key = normalized MAC (upper, colon-separated), value = list[MacIpBinding]
        self.mac_history: Dict[str, List[MacIpBinding]] = {}

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
        self._load_mac_history()

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
        node.is_virtual = node_data.get('is_virtual', False)
        node.virtual_platform = node_data.get('virtual_platform', '')
        # Backward compat: detect virtualization for maps saved before this field existed
        if not node.is_virtual and node.mac_address:
            virt = self._detect_virtual(node.mac_address)
            if virt:
                node.is_virtual = True
                node.virtual_platform = virt
        node.os_info = node_data.get('os_info', '')
        node.device_model = node_data.get('device_model', '')
        node.software = node_data.get('software', [])
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

        # Deep fingerprint fields
        node.dhcp_client_fqdn = node_data.get('dhcp_client_fqdn', '')
        node.dhcp_vendor_class = node_data.get('dhcp_vendor_class', '')
        node.ja3_fingerprints = node_data.get('ja3_fingerprints', [])
        node.ja3s_fingerprints = node_data.get('ja3s_fingerprints', [])
        node.tls_server_names = node_data.get('tls_server_names', [])
        node.tls_versions_seen = node_data.get('tls_versions_seen', [])
        node.dns_profile = node_data.get('dns_profile', {})
        node.rdp_info = node_data.get('rdp_info', {})
        node.cert_subjects = node_data.get('cert_subjects', [])
        node.cert_issuers = node_data.get('cert_issuers', [])
        node.file_mime_types = node_data.get('file_mime_types', [])

        # Router/firewall fields
        node.is_gateway_for = set(node_data.get('is_gateway_for', []))
        node.gateway_evidence = node_data.get('gateway_evidence', [])
        # Host identification
        node.host_id = node_data.get('host_id', {})
        node.known_services_names = node_data.get('known_services_names', [])

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
    # MAC history persistence
    # ------------------------------------------------------------------

    def _load_mac_history(self):
        """Load MAC-to-IP history from disk."""
        hist_file = self.output_dir / "mac_history.json"
        if not hist_file.exists():
            return
        try:
            with open(hist_file) as f:
                data = json.load(f)
            for mac, bindings in data.items():
                mac = mac.upper()
                self.mac_history[mac] = [
                    MacIpBinding(
                        ip=b['ip'],
                        vlan=b.get('vlan', '0'),
                        sensor_id=b.get('sensor_id', 'default'),
                        hostname=b.get('hostname', ''),
                        first_seen=b.get('first_seen', ''),
                        last_seen=b.get('last_seen', ''),
                    )
                    for b in bindings
                ]
            logger.info(
                f"Loaded MAC history: {len(self.mac_history)} MACs, "
                f"{sum(len(v) for v in self.mac_history.values())} bindings"
            )
        except Exception as e:
            logger.error(f"Error loading MAC history: {e}")

    def _save_mac_history(self):
        """Save MAC-to-IP history to disk."""
        hist_file = self.output_dir / "mac_history.json"
        data = {}
        for mac, bindings in self.mac_history.items():
            data[mac] = [b.to_dict() for b in bindings]
        try:
            with open(hist_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Error saving MAC history: {e}")

    def _update_mac_history(self, mac: str, ip: str, vlan: str = "0",
                            sensor_id: str = "default", hostname: str = "",
                            timestamp: str = ""):
        """Record a MAC-to-IP binding observation.

        If the same MAC+IP+VLAN+sensor combination already exists, update
        last_seen.  Otherwise append a new binding.
        """
        mac = mac.strip().upper().replace('-', ':')
        if not mac or len(mac) < 8:
            return

        bindings = self.mac_history.setdefault(mac, [])
        ts = timestamp or datetime.now().isoformat()

        for b in bindings:
            if b.ip == ip and b.vlan == vlan and b.sensor_id == sensor_id:
                # Update last_seen if this timestamp is later
                if ts > b.last_seen:
                    b.last_seen = ts
                if ts < b.first_seen:
                    b.first_seen = ts
                if hostname and not b.hostname:
                    b.hostname = hostname
                return

        # New binding
        bindings.append(MacIpBinding(
            ip=ip, vlan=vlan, sensor_id=sensor_id,
            hostname=hostname, first_seen=ts, last_seen=ts,
        ))

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
        # Routing protocol ports: BGP, HSRP, RIP
        if any(
            p in node.services
            for p in [(179, 'tcp'), (1985, 'udp'), (520, 'udp')]
        ):
            node.roles.add('router')

    # ------------------------------------------------------------------
    # Device profiling
    # ------------------------------------------------------------------

    # MAC OUI prefixes that indicate the host is a virtual machine.
    # Maps OUI prefix -> hypervisor platform name.
    VIRTUAL_OUI = {
        '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
        '00:1C:14': 'VMware',
        '00:15:5D': 'Hyper-V',
        '52:54:00': 'QEMU/KVM',
        '00:16:3E': 'Xen',
        '08:00:27': 'VirtualBox',
        '00:1C:42': 'Parallels',
        '02:42:AC': 'Docker',  # Default Docker bridge (02:42:xx)
    }

    # Network infrastructure vendors — used to identify likely routers,
    # switches, firewalls, and access points based on MAC OUI.
    # Maps vendor name (from OUI_TABLE) to an infrastructure hint.
    NETWORK_INFRA_VENDORS = {
        'Cisco': 'router_or_switch',
        'Juniper': 'router_or_firewall',
        'Fortinet': 'firewall',
        'Palo Alto': 'firewall',
        'CheckPoint': 'firewall',
        'Aruba': 'wireless_controller',
        'Meraki': 'router_or_switch',
        'Ubiquiti': 'router_or_switch',
        'Brocade': 'switch',
        'MikroTik': 'router',
    }

    # Additional MAC OUI prefixes for MikroTik (not in main OUI_TABLE)
    MIKROTIK_OUI = {
        '00:0C:42': 'MikroTik', '2C:C8:1B': 'MikroTik',
        '48:A9:8A': 'MikroTik', '4C:5E:0C': 'MikroTik',
        '6C:3B:6B': 'MikroTik', '74:4D:28': 'MikroTik',
        'B8:69:F4': 'MikroTik', 'CC:2D:E0': 'MikroTik',
        'D4:01:C3': 'MikroTik', 'E4:8D:8C': 'MikroTik',
        '18:FD:74': 'MikroTik', '08:55:31': 'MikroTik',
    }

    # OUI (Organizationally Unique Identifier) lookup table.
    # Maps the first 3 octets of a MAC address to the hardware vendor.
    # Covers major enterprise, networking, virtualization, and IoT vendors.
    OUI_TABLE = {
        # Virtualization
        '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
        '00:1C:14': 'VMware', '00:15:5D': 'Microsoft Hyper-V',
        '52:54:00': 'QEMU/KVM', '00:16:3E': 'Xen',
        '08:00:27': 'VirtualBox', '00:1C:42': 'Parallels',
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
        # MikroTik
        '00:0C:42': 'MikroTik', '2C:C8:1B': 'MikroTik',
        '48:A9:8A': 'MikroTik', '4C:5E:0C': 'MikroTik',
        '6C:3B:6B': 'MikroTik', '74:4D:28': 'MikroTik',
        'B8:69:F4': 'MikroTik', 'CC:2D:E0': 'MikroTik',
        'D4:01:C3': 'MikroTik', 'E4:8D:8C': 'MikroTik',
        '18:FD:74': 'MikroTik', '08:55:31': 'MikroTik',
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

    # SNMP sysObjectID (OID) prefix to device model mapping.
    # When Zeek observes SNMP traffic we can match the sysObjectID to
    # identify the hardware model or platform family.
    SNMP_OID_TABLE = {
        # Cisco
        '1.3.6.1.4.1.9.1': 'Cisco Router/Switch',
        '1.3.6.1.4.1.9.5': 'Cisco Catalyst Switch',
        '1.3.6.1.4.1.9.6': 'Cisco Access Point',
        '1.3.6.1.4.1.9.12': 'Cisco Firewall (ASA/FTD)',
        # Juniper
        '1.3.6.1.4.1.2636.1.1.1': 'Juniper Router',
        '1.3.6.1.4.1.2636.1.2': 'Juniper Switch (EX)',
        '1.3.6.1.4.1.2636.1.3': 'Juniper Firewall (SRX)',
        # Palo Alto
        '1.3.6.1.4.1.25461.2': 'Palo Alto Firewall',
        # Fortinet
        '1.3.6.1.4.1.12356.101': 'FortiGate Firewall',
        '1.3.6.1.4.1.12356.102': 'FortiSwitch',
        '1.3.6.1.4.1.12356.103': 'FortiAP',
        # Aruba
        '1.3.6.1.4.1.14823.1.1': 'Aruba Controller',
        '1.3.6.1.4.1.14823.1.2': 'Aruba Access Point',
        # HP / HPE
        '1.3.6.1.4.1.11.2.3.7.11': 'HP ProCurve Switch',
        '1.3.6.1.4.1.232': 'HPE ProLiant Server',
        # Dell
        '1.3.6.1.4.1.674.10895': 'Dell PowerConnect Switch',
        '1.3.6.1.4.1.674.10892': 'Dell PowerEdge Server (iDRAC)',
        # Ubiquiti
        '1.3.6.1.4.1.41112.1.6': 'Ubiquiti UniFi AP',
        '1.3.6.1.4.1.41112.1.5': 'Ubiquiti UniFi Switch',
        # VMware
        '1.3.6.1.4.1.6876': 'VMware ESXi Host',
        # Linux / Net-SNMP
        '1.3.6.1.4.1.8072.3.2.10': 'Linux Server (net-snmp)',
        # Microsoft Windows SNMP
        '1.3.6.1.4.1.311.1.1.3': 'Windows Server',
        # Synology
        '1.3.6.1.4.1.6574': 'Synology NAS',
        # QNAP
        '1.3.6.1.4.1.24681': 'QNAP NAS',
        # APC / Schneider (UPS)
        '1.3.6.1.4.1.318.1': 'APC UPS',
        # Xerox / printers
        '1.3.6.1.4.1.253': 'Xerox Printer',
        # HP printers
        '1.3.6.1.4.1.11.2.3.9': 'HP Printer',
        # Brother printers
        '1.3.6.1.4.1.2435': 'Brother Printer',
        # Canon printers
        '1.3.6.1.4.1.1602': 'Canon Printer',
        # Hikvision
        '1.3.6.1.4.1.39165': 'Hikvision Camera',
        # Meraki
        '1.3.6.1.4.1.29671': 'Cisco Meraki',
        # CheckPoint
        '1.3.6.1.4.1.2620.1': 'CheckPoint Firewall',
        # Brocade / Ruckus
        '1.3.6.1.4.1.1991': 'Brocade/Ruckus Switch',
    }

    # RDP client_build to Windows version mapping.
    # The build number from Zeek rdp.log directly identifies the Windows release.
    RDP_BUILD_TO_WINDOWS = {
        2600: 'Windows XP',
        3790: 'Windows Server 2003',
        6000: 'Windows Vista',
        6001: 'Windows Vista SP1 / Server 2008',
        6002: 'Windows Vista SP2 / Server 2008 SP2',
        7600: 'Windows 7 / Server 2008 R2',
        7601: 'Windows 7 SP1 / Server 2008 R2 SP1',
        9200: 'Windows 8 / Server 2012',
        9600: 'Windows 8.1 / Server 2012 R2',
        10240: 'Windows 10 1507',
        10586: 'Windows 10 1511',
        14393: 'Windows 10 1607 / Server 2016',
        15063: 'Windows 10 1703',
        16299: 'Windows 10 1709',
        17134: 'Windows 10 1803',
        17763: 'Windows 10 1809 / Server 2019',
        18362: 'Windows 10 1903',
        18363: 'Windows 10 1909',
        19041: 'Windows 10 2004',
        19042: 'Windows 10 20H2',
        19043: 'Windows 10 21H1',
        19044: 'Windows 10 21H2',
        19045: 'Windows 10 22H2',
        20348: 'Windows Server 2022',
        22000: 'Windows 11 21H2',
        22621: 'Windows 11 22H2',
        22631: 'Windows 11 23H2',
        26100: 'Windows 11 24H2 / Server 2025',
    }

    # DHCP vendor class (Option 60) to OS/device type mapping.
    # These prefixes in the vendor_class field identify the client platform.
    DHCP_VENDOR_CLASS_MAP = {
        'MSFT 5.0': 'Windows 2000/XP/2003',
        'MSFT 6.0': 'Windows Vista/2008',
        'MSFT 7.0': 'Windows 7',
        'MSFT 8.0': 'Windows 8',
        'MSFT 9.0': 'Windows 8.1',
        'MSFT 10.0': 'Windows 10/11',
        'dhcpcd': 'Linux/BSD (dhcpcd)',
        'udhcp': 'Embedded Linux (BusyBox)',
        'android-dhcp': 'Android',
        'Apple AirPort': 'Apple AirPort',
        'AAPLBSDPC': 'macOS (Apple BSDP)',
    }

    @classmethod
    def _lookup_rdp_build(cls, build: int) -> str:
        """Map RDP client_build number to Windows version string."""
        # Exact match first
        if build in cls.RDP_BUILD_TO_WINDOWS:
            return cls.RDP_BUILD_TO_WINDOWS[build]
        # Range-based fallback for builds between known versions
        if build < 6000:
            return 'Windows XP/2003'
        if build < 7600:
            return 'Windows Vista/2008'
        if build < 9200:
            return 'Windows 7/2008 R2'
        if build < 9600:
            return 'Windows 8/2012'
        if build < 10240:
            return 'Windows 8.1/2012 R2'
        if build < 22000:
            return f'Windows 10 (build {build})'
        return f'Windows 11 (build {build})'

    @classmethod
    def _lookup_dhcp_vendor_class(cls, vendor_class: str) -> str:
        """Map DHCP vendor class identifier to OS/device type."""
        if not vendor_class:
            return ''
        # Exact match
        if vendor_class in cls.DHCP_VENDOR_CLASS_MAP:
            return cls.DHCP_VENDOR_CLASS_MAP[vendor_class]
        # Prefix match
        vc_lower = vendor_class.lower()
        for prefix, os_name in cls.DHCP_VENDOR_CLASS_MAP.items():
            if vc_lower.startswith(prefix.lower()):
                return os_name
        return ''

    @classmethod
    def _lookup_snmp_oid(cls, oid: str) -> str:
        """Look up device model from SNMP sysObjectID by matching OID prefixes."""
        if not oid:
            return ''
        # Try progressively shorter prefixes for a match
        for prefix, model in cls.SNMP_OID_TABLE.items():
            if oid.startswith(prefix):
                return model
        return ''

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
            'type': 'router',
            'label': 'Router',
            # Routing protocol ports: BGP, OSPF (often not visible in Zeek),
            # HSRP, VRRP, RIP, Cisco EIGRP, BFD
            'required': {179, 1985, 520, 521},
            'bonus': {22, 23, 161, 2601, 2602, 2604, 2605},  # SSH, Telnet, SNMP, Zebra/Quagga
            'min_match': 1,
        },
        {
            'type': 'firewall',
            'label': 'Firewall',
            # Firewall management ports: PAN-OS, FortiGate, Check Point, pfSense
            'required': {4443, 8443, 18264, 443, 981, 4434},
            'bonus': {22, 161, 500, 4500},  # SSH, SNMP, IPSec
            'min_match': 2,
            'min_clients': 3,
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

    @classmethod
    def _detect_network_infra(cls, vendor: str) -> str:
        """Detect if a MAC vendor is a known network infrastructure manufacturer.

        Returns an infrastructure hint string (e.g. 'router_or_switch',
        'firewall') or empty string if the vendor is not network infra.
        """
        if not vendor:
            return ''
        return cls.NETWORK_INFRA_VENDORS.get(vendor, '')

    @classmethod
    def _infer_type_from_snmp_oid(cls, device_model: str) -> str:
        """Infer device_type from SNMP OID-derived device model string.

        The SNMP_OID_TABLE maps OIDs to strings like 'Cisco Router/Switch',
        'FortiGate Firewall', etc.  This method parses those strings to
        return a device_type suitable for classification.
        """
        if not device_model:
            return ''
        model_lower = device_model.lower()
        # Firewall matches
        if 'firewall' in model_lower or 'asa' in model_lower or 'ftd' in model_lower:
            return 'firewall'
        if 'fortigate' in model_lower:
            return 'firewall'
        # Router matches
        if 'router' in model_lower:
            return 'router'
        # Switch matches (switches are not routers/firewalls but worth noting)
        if 'switch' in model_lower and 'router' not in model_lower:
            return 'switch'
        # Access point / wireless controller
        if 'access point' in model_lower or 'controller' in model_lower:
            return ''  # Not a router/firewall
        return ''

    @classmethod
    def _detect_virtual(cls, mac: str) -> str:
        """Detect virtualization platform from MAC address OUI.

        Returns the hypervisor platform name (e.g. 'VMware', 'Hyper-V') if
        the MAC belongs to a known virtual NIC, or empty string otherwise.
        Docker containers using the default bridge (02:42:xx) are also detected.
        """
        if not mac or len(mac) < 8:
            return ''
        prefix = mac[:8].upper()
        platform = cls.VIRTUAL_OUI.get(prefix)
        if platform:
            return platform
        # Docker uses locally-administered MACs starting with 02:42
        if prefix.startswith('02:42:'):
            return 'Docker'
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
            'router': 'Router',
            'firewall': 'Firewall',
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
            'router': 1,
            'firewall': 1,
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

    # ------------------------------------------------------------------
    # Profiling helpers — time-window batching
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_time_range_hours(time_range: str) -> float:
        """Parse a Splunk-style relative time range into total hours."""
        m = re.match(r'^-(\d+)(s|m|h|d|w|mon)$', time_range.strip())
        if not m:
            return 0
        value = int(m.group(1))
        unit = m.group(2)
        multipliers = {
            's': 1 / 3600, 'm': 1 / 60, 'h': 1,
            'd': 24, 'w': 168, 'mon': 720,
        }
        return value * multipliers.get(unit, 0)

    @staticmethod
    def _generate_profile_windows(
        time_range: str,
        window_hours: int = 24,
    ) -> List[Tuple[str, str]]:
        """Split a time range into fixed-size windows for profiling.

        Returns a list of (earliest_iso, latest_iso) string pairs.
        For ranges <= window_hours a single (time_range, "now") pair is
        returned so existing behaviour is preserved.
        """
        now = datetime.utcnow()
        m = re.match(r'^-(\d+)(s|m|h|d|w|mon)$', time_range.strip())
        if not m:
            return [(time_range, "now")]

        value = int(m.group(1))
        unit = m.group(2)
        unit_seconds = {
            's': 1, 'm': 60, 'h': 3600,
            'd': 86400, 'w': 604800, 'mon': 2592000,
        }
        total_seconds = value * unit_seconds.get(unit, 3600)
        if total_seconds <= window_hours * 3600:
            return [(time_range, "now")]

        start = now - timedelta(seconds=total_seconds)
        end = now
        ws = window_hours * 3600
        windows: List[Tuple[str, str]] = []
        cursor = start
        while cursor < end:
            window_end = min(cursor + timedelta(seconds=ws), end)
            windows.append((
                cursor.strftime('%Y-%m-%dT%H:%M:%S'),
                window_end.strftime('%Y-%m-%dT%H:%M:%S'),
            ))
            cursor = window_end
        return windows

    def _run_profile_queries(self, splunk_connector, earliest, latest):
        """Run the profiling Splunk queries for a single time window.

        Returns a dict with keys: server, client, ntlm, kerberos, dhcp,
        snmp, smb, software, ssh, x509, http_ua — each holding a list of
        result rows.
        """
        from concurrent.futures import ThreadPoolExecutor

        queries = self._profile_query_definitions()

        _HEAVY_TIMEOUT = 1800
        _LIGHT_TIMEOUT = 600

        with ThreadPoolExecutor(max_workers=len(queries)) as executor:
            futures = {}
            for name, spl in queries.items():
                futures[name] = executor.submit(
                    splunk_connector.query, spl,
                    earliest_time=earliest, latest_time=latest,
                )

            results = {}
            for name, fut in futures.items():
                timeout = _HEAVY_TIMEOUT if name in ('server', 'client') else _LIGHT_TIMEOUT
                try:
                    results[name] = fut.result(timeout=timeout)
                except Exception as e:
                    logger.warning(f"{name} query failed for window {earliest}..{latest}: {e}")
                    results[name] = []

        return results

    @staticmethod
    def _merge_profile_results(accumulated, new_results):
        """Merge a new window's query results into the accumulated totals.

        Server/client profiles are aggregated per-IP (max dc, sum counts,
        union ports).  Enrichment queries (NTLM, DHCP, etc.) are
        concatenated since the enrichment loop handles dedup via sets.
        """
        # --- server profile: merge per-IP ---
        for row in new_results.get('server', []):
            ip = row.get('ip') or (row.get('id.resp_h'))
            if not ip:
                continue
            if isinstance(ip, list):
                ip = ip[0]
            ip = str(ip)
            existing = accumulated['server_agg'].get(ip)
            new_clients = int(row.get('unique_clients', 0))
            new_count = int(row.get('incoming_count', 0))
            ports_raw = row.get('ports', [])
            if isinstance(ports_raw, str):
                ports_raw = [ports_raw]
            new_ports = set()
            for p in ports_raw:
                try:
                    new_ports.add(int(p))
                except (ValueError, TypeError):
                    pass
            if existing:
                existing['unique_clients'] = max(existing['unique_clients'], new_clients)
                existing['incoming_count'] += new_count
                existing['ports'] |= new_ports
            else:
                accumulated['server_agg'][ip] = {
                    'unique_clients': new_clients,
                    'incoming_count': new_count,
                    'ports': new_ports,
                }

        # --- client profile: merge per-IP ---
        for row in new_results.get('client', []):
            ip = row.get('ip') or (row.get('id.orig_h'))
            if not ip:
                continue
            if isinstance(ip, list):
                ip = ip[0]
            ip = str(ip)
            existing = accumulated['client_agg'].get(ip)
            new_dests = int(row.get('unique_destinations', 0))
            new_count = int(row.get('outgoing_count', 0))
            if existing:
                existing['unique_destinations'] = max(existing['unique_destinations'], new_dests)
                existing['outgoing_count'] += new_count
            else:
                accumulated['client_agg'][ip] = {
                    'unique_destinations': new_dests,
                    'outgoing_count': new_count,
                }

        # --- enrichment queries: just concatenate ---
        for key in ('ntlm', 'kerberos', 'dhcp', 'snmp', 'smb',
                     'software', 'ssh', 'x509', 'http_ua',
                     'ja3_ssl', 'ja3s_server', 'dns_profile', 'rdp',
                     'dhcp_extended', 'files', 'x509_extended',
                     'known_services', 'smtp_banner', 'ftp_banner',
                     'dhcp_gateway', 'snmp_oid'):
            accumulated[key].extend(new_results.get(key, []))

    def _profile_query_definitions(self):
        """Return a dict of {name: SPL_query} for profiling."""
        return {
            'server': '''
            search index=zeek_conn OR index=suricata
            | spath
            | stats dc("id.orig_h") as unique_clients,
                    values("id.resp_p") as ports,
                    count as incoming_count
              by "id.resp_h"
            | rename "id.resp_h" as ip
            | where incoming_count >= 3
            ''',
            'client': '''
            search index=zeek_conn OR index=suricata
            | spath
            | stats dc("id.resp_h") as unique_destinations,
                    count as outgoing_count
              by "id.orig_h"
            | rename "id.orig_h" as ip
            | where outgoing_count >= 3
            ''',
            'ntlm': '''
            search index=zeek_ntlm
            | spath
            | eval vlan=coalesce(vlan, "0")
            | table _time host vlan id.orig_h id.resp_h hostname domainname server_nb_computer_name server_dns_computer_name
            | rename host as sensor_id, "id.orig_h" as source_ip, "id.resp_h" as dest_ip
            ''',
            'kerberos': '''
            search index=zeek_kerberos
            | spath
            | stats dc("id.orig_h") as unique_clients,
                    values(service) as services,
                    count as auth_count
              by "id.resp_h"
            | rename "id.resp_h" as ip
            | where auth_count >= 3
            ''',
            'dhcp': '''
            search index=zeek_dhcp
            | spath
            | where isnotnull(assigned_addr) AND isnotnull(mac)
            | eval vlan=coalesce(vlan, "0")
            | stats min(_time) as first_seen,
                    max(_time) as last_seen,
                    latest(host_name) as dhcp_hostname,
                    latest(host) as sensor_id
              by assigned_addr, mac, vlan
            | rename assigned_addr as ip
            ''',
            'snmp': '''
            search index=zeek_snmp
            | spath
            | where isnotnull("id.resp_h")
            | eval oid=coalesce("id.resp_p", "")
            | stats latest(community) as community,
                    latest(version) as snmp_version
              by "id.resp_h"
            | rename "id.resp_h" as ip
            ''',
            'smb': '''
            search index=zeek_smb_mapping OR index=zeek_smb_files
            | spath
            | eval nb_name=coalesce(server_name, "")
            | where nb_name!="" AND nb_name!="-"
            | stats values(nb_name) as nb_names,
                    values(share_type) as share_types
              by "id.resp_h"
            | rename "id.resp_h" as ip
            ''',
            'software': '''
            search index=zeek_software
            | spath
            | where isnotnull(host) OR isnotnull("id.orig_h")
            | eval ip=coalesce(host, "id.orig_h")
            | eval sw=name . " " . coalesce("version.major","") . "." . coalesce("version.minor","")
            | stats values(sw) as software,
                    values(software_type) as sw_types
              by ip
            ''',
            'ssh': '''
            search index=zeek_ssh
            | spath
            | stats latest(client) as ssh_client,
                    latest(server) as ssh_server
              by "id.orig_h", "id.resp_h"
            | rename "id.orig_h" as client_ip, "id.resp_h" as server_ip
            ''',
            'x509': '''
            search index=zeek_x509
            | spath
            | where isnotnull("certificate.subject")
            | rex field="certificate.subject" "CN=(?<cn>[^,/]+)"
            | where isnotnull(cn)
            | stats values(cn) as cert_names by host
            | rename host as sensor_id
            ''',
            'http_ua': '''
            search index=zeek_http
            | spath
            | where isnotnull(user_agent) AND user_agent!="-"
            | stats values(user_agent) as user_agents,
                    dc(host) as sites_visited,
                    count as http_count
              by "id.orig_h"
            | rename "id.orig_h" as ip
            | where http_count >= 2
            ''',
            # --- Deep fingerprint queries ---
            'ja3_ssl': '''
            search index=zeek_ssl
            | spath
            | where isnotnull(ja3) AND ja3!="-"
            | stats values(ja3) as ja3_hashes,
                    values(ja3s) as ja3s_hashes,
                    values(server_name) as sni_names,
                    values(version) as tls_versions,
                    dc("id.resp_h") as unique_servers,
                    count as tls_count
              by "id.orig_h"
            | rename "id.orig_h" as ip
            | where tls_count >= 2
            ''',
            'ja3s_server': '''
            search index=zeek_ssl
            | spath
            | where isnotnull(ja3s) AND ja3s!="-"
            | stats values(ja3s) as ja3s_hashes,
                    values(subject) as cert_subjects,
                    values(issuer) as cert_issuers,
                    values(version) as tls_versions,
                    dc("id.orig_h") as unique_clients
              by "id.resp_h"
            | rename "id.resp_h" as ip
            | where unique_clients >= 1
            ''',
            'dns_profile': '''
            search index=zeek_dns
            | spath
            | where isnotnull(query) AND query!="-"
            | eval tld=mvindex(split(query, "."), -1)
            | eval is_nxdomain=if(rcode_name=="NXDOMAIN", 1, 0)
            | stats count as query_count,
                    dc(query) as unique_domains,
                    values(tld) as tlds,
                    sum(is_nxdomain) as nxdomain_count,
                    values(qtype_name) as query_types
              by "id.orig_h"
            | rename "id.orig_h" as ip
            | eval nxdomain_ratio=round(nxdomain_count/query_count, 4)
            | where query_count >= 5
            ''',
            'rdp': '''
            search index=zeek_rdp
            | spath
            | where isnotnull(cookie) OR isnotnull(client_build)
            | stats latest(cookie) as rdp_cookie,
                    latest(client_build) as client_build,
                    latest(client_name) as client_name,
                    latest(keyboard_layout) as keyboard_layout,
                    latest(desktop_width) as desktop_width,
                    latest(desktop_height) as desktop_height,
                    latest(security_protocol) as security_protocol,
                    count as rdp_count
              by "id.orig_h"
            | rename "id.orig_h" as ip
            ''',
            'dhcp_extended': '''
            search index=zeek_dhcp
            | spath
            | where isnotnull(assigned_addr) AND isnotnull(mac)
            | eval vlan=coalesce(vlan, "0")
            | stats latest(client_fqdn) as client_fqdn,
                    latest(domain) as dhcp_domain,
                    latest(vendor_class) as vendor_class,
                    latest(lease_time) as lease_time,
                    values(msg_types) as msg_types,
                    latest(host) as sensor_id
              by assigned_addr, mac, vlan
            | rename assigned_addr as ip
            | where isnotnull(client_fqdn) OR isnotnull(vendor_class)
            ''',
            'files': '''
            search index=zeek_files
            | spath
            | where isnotnull(mime_type) AND mime_type!="-"
            | eval ip=coalesce(tx_hosts, rx_hosts)
            | mvexpand ip
            | stats values(mime_type) as mime_types,
                    values(source) as file_sources,
                    dc(mime_type) as unique_types,
                    sum(total_bytes) as total_file_bytes,
                    count as file_count
              by ip
            | where file_count >= 2
            ''',
            'x509_extended': '''
            search index=zeek_x509
            | spath
            | where isnotnull("certificate.subject")
            | rex field="certificate.subject" "CN=(?<cn>[^,/]+)"
            | rex field="certificate.issuer" "CN=(?<issuer_cn>[^,/]+)"
            | rex field="certificate.issuer" "O=(?<issuer_org>[^,/]+)"
            | stats values(cn) as cert_names,
                    values(issuer_cn) as issuer_names,
                    values(issuer_org) as issuer_orgs,
                    values("certificate.key_type") as key_types,
                    values("certificate.key_length") as key_lengths,
                    dc(cn) as unique_certs
              by host
            | rename host as sensor_id
            ''',
            # --- Host identification queries (Zeek Workbench style) ---
            'known_services': '''
            search index=zeek_known_services
            | spath
            | where isnotnull(host) AND isnotnull(port_num)
            | eval svc=if(isnotnull(service) AND service!="-" AND service!="",
                          service, port_num."/".port_proto)
            | stats values(svc) as service_names,
                    dc(port_num) as port_count
              by host
            | rename host as ip
            ''',
            'smtp_banner': '''
            search index=zeek_smtp
            | spath
            | where isnotnull("id.resp_h")
            | stats values(helo) as helo_names,
                    latest(last_reply) as last_banner,
                    dc("id.orig_h") as unique_clients,
                    count as smtp_count
              by "id.resp_h"
            | rename "id.resp_h" as ip
            | where smtp_count >= 2
            ''',
            'ftp_banner': '''
            search index=zeek_ftp
            | spath
            | where isnotnull("id.resp_h")
            | stats latest(reply_msg) as ftp_banner,
                    dc("id.orig_h") as unique_clients,
                    count as ftp_count
              by "id.resp_h"
            | rename "id.resp_h" as ip
            | where ftp_count >= 1
            ''',
            # --- Router / firewall detection queries ---
            'dhcp_gateway': '''
            search index=zeek_dhcp
            | spath
            | where isnotnull(assigned_addr) AND isnotnull(router)
            | eval vlan=coalesce(vlan, "0")
            | eval gw=mvindex(router, 0)
            | where isnotnull(gw) AND gw!="" AND gw!="-"
            | stats dc(assigned_addr) as client_count,
                    values(assigned_addr) as clients
              by gw, vlan
            | rename gw as gateway_ip
            | where client_count >= 1
            ''',
            'snmp_oid': '''
            search index=zeek_snmp
            | spath
            | where isnotnull("id.resp_h")
            | eval oid=coalesce(community, "")
            | stats latest(community) as community,
                    latest(version) as snmp_version
              by "id.resp_h"
            | rename "id.resp_h" as ip
            ''',
        }

    def profile_devices(self, splunk_connector, time_range: str = "-24h",
                         progress_callback=None) -> Dict:
        """
        Profile network devices by querying Splunk zeek logs.

        For time ranges > 24 h the work is split into 24-hour windows so
        that no single Splunk search job becomes too large.  Results are
        merged across windows before enrichment and classification.

        Args:
            splunk_connector: SplunkConnector instance
            time_range: Splunk time range to analyze (default -24h).
                Supports -Nd, -Nw, -Nmon for multi-day profiling.
            progress_callback: Optional callable(stage, message, pct) for
                progress reporting back to the caller.

        Returns:
            Dict with profiling results summary
        """

        def _sv(val, default=""):
            """Normalize a Splunk field to a single string value.
            Multivalue fields come back as Python lists from JSON output."""
            if isinstance(val, list):
                return str(val[0]) if val else default
            return str(val) if val is not None else default

        def _progress(stage, message, pct):
            if progress_callback:
                try:
                    progress_callback(stage, message, pct)
                except Exception:
                    pass

        logger.info(f"Starting device profiling with time_range={time_range}")

        internal_count = sum(1 for n in self.nodes.values() if n.is_internal)
        _progress('profile', f'Network map loaded: {len(self.nodes)} nodes ({internal_count} internal)', 30)

        # ---- Split time range into windows ----
        windows = self._generate_profile_windows(time_range, window_hours=24)
        total_windows = len(windows)
        logger.info(f"Profiling will use {total_windows} time window(s)")

        # Accumulator for cross-window merging
        accumulated = {
            'server_agg': {},   # ip -> {unique_clients, incoming_count, ports}
            'client_agg': {},   # ip -> {unique_destinations, outgoing_count}
            'ntlm': [], 'kerberos': [], 'dhcp': [], 'snmp': [],
            'smb': [], 'software': [], 'ssh': [], 'x509': [],
            'http_ua': [],
            # Deep fingerprint accumulators
            'ja3_ssl': [], 'ja3s_server': [], 'dns_profile': [],
            'rdp': [], 'dhcp_extended': [], 'files': [],
            'x509_extended': [],
            # Host identification accumulators
            'known_services': [], 'smtp_banner': [], 'ftp_banner': [],
            # Router/firewall detection accumulators
            'dhcp_gateway': [], 'snmp_oid': [],
        }

        # Progress: queries run from 35% to 70%.  Divide evenly across windows.
        pct_query_start = 35
        pct_query_end = 70
        pct_per_window = (pct_query_end - pct_query_start) / max(total_windows, 1)

        for win_idx, (earliest, latest) in enumerate(windows, 1):
            win_label = (f"Window {win_idx}/{total_windows}: {earliest} → {latest}"
                         if total_windows > 1 else "Querying Splunk...")
            pct = int(pct_query_start + (win_idx - 1) * pct_per_window)
            _progress('profile',
                      f'{win_label} — submitting 23 queries in parallel...',
                      pct)
            logger.info(f"Profiling window {win_idx}/{total_windows}: "
                        f"{earliest} → {latest}")

            window_results = self._run_profile_queries(
                splunk_connector, earliest, latest,
            )
            self._merge_profile_results(accumulated, window_results)

            logger.info(
                f"Window {win_idx}/{total_windows} done — "
                f"server IPs: {len(accumulated['server_agg'])}, "
                f"client IPs: {len(accumulated['client_agg'])}, "
                f"NTLM rows: {len(accumulated['ntlm'])}"
            )

        # Unpack accumulated enrichment rows
        ntlm_results = accumulated['ntlm']
        kerberos_results = accumulated['kerberos']
        dhcp_results = accumulated['dhcp']
        snmp_results = accumulated['snmp']
        smb_results = accumulated['smb']
        software_results = accumulated['software']
        ssh_results = accumulated['ssh']
        x509_results = accumulated['x509']
        http_ua_results = accumulated['http_ua']
        # Deep fingerprint results
        ja3_ssl_results = accumulated['ja3_ssl']
        ja3s_server_results = accumulated['ja3s_server']
        dns_profile_results = accumulated['dns_profile']
        rdp_results = accumulated['rdp']
        dhcp_extended_results = accumulated['dhcp_extended']
        files_results = accumulated['files']
        x509_extended_results = accumulated['x509_extended']
        # Host identification results
        known_services_results = accumulated['known_services']
        smtp_banner_results = accumulated['smtp_banner']
        ftp_banner_results = accumulated['ftp_banner']
        # Router/firewall detection results
        dhcp_gateway_results = accumulated['dhcp_gateway']
        snmp_oid_results = accumulated['snmp_oid']

        query_counts = (
            f"{len(accumulated['server_agg'])} server IPs, "
            f"{len(accumulated['client_agg'])} client IPs, "
            f"{len(ntlm_results)} NTLM, {len(kerberos_results)} Kerberos, "
            f"{len(dhcp_results)} DHCP, {len(snmp_results)} SNMP, "
            f"{len(smb_results)} SMB, {len(software_results)} software, "
            f"{len(ssh_results)} SSH, {len(x509_results)} x509, "
            f"{len(http_ua_results)} HTTP UA, "
            f"{len(ja3_ssl_results)} JA3/SSL, {len(ja3s_server_results)} JA3S server, "
            f"{len(dns_profile_results)} DNS profile, {len(rdp_results)} RDP, "
            f"{len(dhcp_extended_results)} DHCP ext, {len(files_results)} files, "
            f"{len(x509_extended_results)} x509 ext"
        )
        _progress('profile',
                  f'All {total_windows} window(s) done: {query_counts}. '
                  f'Enriching nodes...', 70)

        # Build set of KDC IPs from Kerberos logs (these ARE domain controllers)
        kdc_ips: set = set()
        for row in kerberos_results:
            ip = _sv(row.get('ip'))
            if ip:
                kdc_ips.add(ip)

        # Build IP -> [node keys] lookup for O(1) enrichment
        ip_to_keys: Dict[str, List[str]] = defaultdict(list)
        for key, node in self.nodes.items():
            ip_to_keys[node.ip].append(key)

        # Build map of NTLM auth server IPs -> unique client count
        # Servers receiving NTLM auths from many clients are likely DCs
        ntlm_server_clients: Dict[str, set] = defaultdict(set)

        # Enrich nodes with NTLM data (NetBIOS names + domain)
        ntlm_enriched = 0
        for row in ntlm_results:
            src_ip = _sv(row.get('source_ip'))
            dst_ip = _sv(row.get('dest_ip'))
            hostname = _sv(row.get('hostname'))
            domainname = _sv(row.get('domainname'))
            server_nb = _sv(row.get('server_nb_computer_name'))
            server_dns = _sv(row.get('server_dns_computer_name'))

            # Track which servers receive NTLM auths from many clients
            if src_ip and dst_ip:
                ntlm_server_clients[dst_ip].add(src_ip)

            # Enrich source nodes
            if hostname and hostname != '-':
                for key in ip_to_keys.get(src_ip, []):
                    node = self.nodes[key]
                    node.netbios_names.add(hostname.upper())
                    if domainname and domainname != '-':
                        node.domain = domainname.upper()
                    ntlm_enriched += 1

            # Enrich destination nodes
            for key in ip_to_keys.get(dst_ip, []):
                node = self.nodes[key]
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

        # Enrich nodes with DHCP data (MAC address + OUI vendor + MAC history)
        dhcp_enriched = 0
        mac_bindings_recorded = 0
        for row in dhcp_results:
            ip = _sv(row.get('ip'))
            mac = _sv(row.get('mac'))
            dhcp_hostname = _sv(row.get('dhcp_hostname'))
            vlan = _sv(row.get('vlan'), '0')
            sensor_id = _sv(row.get('sensor_id'), 'default')
            first_seen = _sv(row.get('first_seen'))
            last_seen = _sv(row.get('last_seen'))
            if not ip or not mac:
                continue
            # Normalize MAC to colon-separated uppercase
            mac = mac.strip().upper().replace('-', ':')

            # Record MAC-to-IP binding for device tracking
            hn = ''
            if dhcp_hostname and dhcp_hostname != '-' and dhcp_hostname != 'null':
                hn = dhcp_hostname.lower()
            self._update_mac_history(
                mac, ip, vlan=vlan, sensor_id=sensor_id,
                hostname=hn, timestamp=first_seen,
            )
            # Update last_seen separately if different
            if last_seen and last_seen != first_seen:
                self._update_mac_history(
                    mac, ip, vlan=vlan, sensor_id=sensor_id,
                    hostname=hn, timestamp=last_seen,
                )
            mac_bindings_recorded += 1

            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                node.mac_address = mac
                node.vendor = self._lookup_oui(mac)
                virt = self._detect_virtual(mac)
                if virt:
                    node.is_virtual = True
                    node.virtual_platform = virt
                if hn:
                    node.hostnames.add(hn)
                dhcp_enriched += 1

        # Enrich nodes with SNMP data (device model from OID, community string)
        snmp_enriched = 0
        for row in snmp_results:
            ip = _sv(row.get('ip'))
            community = _sv(row.get('community'))
            snmp_version = _sv(row.get('snmp_version'))
            if not ip:
                continue
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                # Community string often contains the sysObjectID or description
                # The SNMP index/version info itself confirms SNMP is running
                if community and community != '-':
                    # Note: we don't expose the community string (security)
                    # but we mark the device as SNMP-managed
                    if not node.device_model:
                        node.device_model = 'SNMP-managed device'
                if snmp_version and snmp_version != '-':
                    sw_entry = f"SNMP {snmp_version}"
                    if sw_entry not in node.software:
                        node.software.append(sw_entry)
                snmp_enriched += 1

        # Enrich nodes with SMB data (NetBIOS names from file sharing)
        smb_enriched = 0
        for row in smb_results:
            ip = _sv(row.get('ip'))
            nb_names_raw = row.get('nb_names', [])
            if isinstance(nb_names_raw, str):
                nb_names_raw = [nb_names_raw]
            if not ip:
                continue
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for name in nb_names_raw:
                    name = str(name).strip()
                    if name and name != '-':
                        node.netbios_names.add(name.upper())
                        smb_enriched += 1

        # Enrich nodes with Zeek software detection (OS, browsers, SSH, etc.)
        software_enriched = 0
        for row in software_results:
            ip = _sv(row.get('ip'))
            sw_list = row.get('software', [])
            sw_types = row.get('sw_types', [])
            if isinstance(sw_list, str):
                sw_list = [sw_list]
            if isinstance(sw_types, str):
                sw_types = [sw_types]
            if not ip:
                continue
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for sw in sw_list:
                    sw = str(sw).strip()
                    if sw and sw != '-' and sw not in node.software:
                        node.software.append(sw)
                # Zeek software types like "OS::*" give us OS info
                for st in sw_types:
                    st_str = str(st).strip()
                    if 'OS' in st_str and not node.os_info:
                        # Use the matching software entry as OS info
                        for sw in sw_list:
                            sw = str(sw).strip()
                            if sw and sw != '-':
                                node.os_info = sw
                                break
                software_enriched += 1

        # Enrich nodes with SSH client/server version strings
        ssh_enriched = 0
        for row in ssh_results:
            client_ip = _sv(row.get('client_ip'))
            server_ip = _sv(row.get('server_ip'))
            ssh_client = _sv(row.get('ssh_client'))
            ssh_server = _sv(row.get('ssh_server'))

            if client_ip and ssh_client and ssh_client != '-':
                for key in ip_to_keys.get(client_ip, []):
                    node = self.nodes[key]
                    entry = f"SSH client: {ssh_client}"
                    if entry not in node.software:
                        node.software.append(entry)
                    # Extract OS hints from SSH banner (e.g. "OpenSSH_8.9p1 Ubuntu-3")
                    if not node.os_info:
                        banner = ssh_client.lower()
                        if 'ubuntu' in banner:
                            node.os_info = 'Ubuntu Linux'
                        elif 'debian' in banner:
                            node.os_info = 'Debian Linux'
                        elif 'rhel' in banner or 'redhat' in banner:
                            node.os_info = 'Red Hat Linux'
                        elif 'windows' in banner:
                            node.os_info = 'Windows'
                    ssh_enriched += 1

            if server_ip and ssh_server and ssh_server != '-':
                for key in ip_to_keys.get(server_ip, []):
                    node = self.nodes[key]
                    entry = f"SSH server: {ssh_server}"
                    if entry not in node.software:
                        node.software.append(entry)
                    if not node.os_info:
                        banner = ssh_server.lower()
                        if 'ubuntu' in banner:
                            node.os_info = 'Ubuntu Linux'
                        elif 'debian' in banner:
                            node.os_info = 'Debian Linux'
                        elif 'rhel' in banner or 'redhat' in banner:
                            node.os_info = 'Red Hat Linux'
                        elif 'windows' in banner:
                            node.os_info = 'Windows'
                    ssh_enriched += 1

        # Enrich nodes with HTTP User-Agent strings
        ua_enriched = 0
        for row in http_ua_results:
            ip = _sv(row.get('ip'))
            ua_list = row.get('user_agents', [])
            if isinstance(ua_list, str):
                ua_list = [ua_list]
            if not ip:
                continue
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for ua in ua_list:
                    ua = str(ua).strip()
                    if ua and ua != '-' and ua not in node.user_agents:
                        node.user_agents.append(ua)
                # Infer OS from user-agent strings if not already set
                if not node.os_info:
                    for ua in node.user_agents:
                        ua_lower = ua.lower()
                        if 'windows nt 10' in ua_lower:
                            node.os_info = 'Windows 10/11'
                            break
                        elif 'windows nt 6.3' in ua_lower:
                            node.os_info = 'Windows 8.1'
                            break
                        elif 'windows nt 6.1' in ua_lower:
                            node.os_info = 'Windows 7'
                            break
                        elif 'windows' in ua_lower:
                            node.os_info = 'Windows'
                            break
                        elif 'macintosh' in ua_lower or 'mac os x' in ua_lower:
                            node.os_info = 'macOS'
                            break
                        elif 'linux' in ua_lower and 'android' not in ua_lower:
                            node.os_info = 'Linux'
                            break
                        elif 'android' in ua_lower:
                            node.os_info = 'Android'
                            break
                        elif 'iphone' in ua_lower or 'ipad' in ua_lower:
                            node.os_info = 'iOS'
                            break
                ua_enriched += 1

        # ---- Deep fingerprint enrichment ----

        # Enrich nodes with JA3 TLS client fingerprints + SNI + TLS versions
        ja3_enriched = 0
        for row in ja3_ssl_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            ja3_list = row.get('ja3_hashes', [])
            ja3s_list = row.get('ja3s_hashes', [])
            sni_list = row.get('sni_names', [])
            tls_vers = row.get('tls_versions', [])
            if isinstance(ja3_list, str):
                ja3_list = [ja3_list]
            if isinstance(ja3s_list, str):
                ja3s_list = [ja3s_list]
            if isinstance(sni_list, str):
                sni_list = [sni_list]
            if isinstance(tls_vers, str):
                tls_vers = [tls_vers]
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for h in ja3_list:
                    h = str(h).strip()
                    if h and h != '-' and h not in node.ja3_fingerprints:
                        node.ja3_fingerprints.append(h)
                for h in ja3s_list:
                    h = str(h).strip()
                    if h and h != '-' and h not in node.ja3s_fingerprints:
                        node.ja3s_fingerprints.append(h)
                for sni in sni_list:
                    sni = str(sni).strip()
                    if sni and sni != '-' and sni not in node.tls_server_names:
                        node.tls_server_names.append(sni)
                for tv in tls_vers:
                    tv = str(tv).strip()
                    if tv and tv != '-' and tv not in node.tls_versions_seen:
                        node.tls_versions_seen.append(tv)
                ja3_enriched += 1

        # Enrich server-side nodes with JA3S + certificate info from SSL
        ja3s_enriched = 0
        for row in ja3s_server_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            ja3s_list = row.get('ja3s_hashes', [])
            cert_subj = row.get('cert_subjects', [])
            cert_iss = row.get('cert_issuers', [])
            tls_vers = row.get('tls_versions', [])
            if isinstance(ja3s_list, str):
                ja3s_list = [ja3s_list]
            if isinstance(cert_subj, str):
                cert_subj = [cert_subj]
            if isinstance(cert_iss, str):
                cert_iss = [cert_iss]
            if isinstance(tls_vers, str):
                tls_vers = [tls_vers]
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for h in ja3s_list:
                    h = str(h).strip()
                    if h and h != '-' and h not in node.ja3s_fingerprints:
                        node.ja3s_fingerprints.append(h)
                for subj in cert_subj:
                    subj = str(subj).strip()
                    if subj and subj != '-' and subj not in node.cert_subjects:
                        node.cert_subjects.append(subj)
                for iss in cert_iss:
                    iss = str(iss).strip()
                    if iss and iss != '-' and iss not in node.cert_issuers:
                        node.cert_issuers.append(iss)
                for tv in tls_vers:
                    tv = str(tv).strip()
                    if tv and tv != '-' and tv not in node.tls_versions_seen:
                        node.tls_versions_seen.append(tv)
                ja3s_enriched += 1

        # Enrich nodes with DNS behavioral profiles
        dns_profiled = 0
        for row in dns_profile_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            query_count = int(_sv(row.get('query_count'), '0'))
            unique_domains = int(_sv(row.get('unique_domains'), '0'))
            nxdomain_ratio = float(_sv(row.get('nxdomain_ratio'), '0'))
            tlds = row.get('tlds', [])
            query_types = row.get('query_types', [])
            if isinstance(tlds, str):
                tlds = [tlds]
            if isinstance(query_types, str):
                query_types = [query_types]
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                # Merge: keep the higher values across windows
                existing_qc = node.dns_profile.get('query_count', 0)
                node.dns_profile = {
                    'query_count': max(query_count, existing_qc),
                    'unique_domains': max(unique_domains,
                                          node.dns_profile.get('unique_domains', 0)),
                    'nxdomain_ratio': max(nxdomain_ratio,
                                          node.dns_profile.get('nxdomain_ratio', 0)),
                    'top_tlds': [str(t).strip() for t in tlds
                                 if str(t).strip() and str(t).strip() != '-'][:15],
                    'query_types': [str(t).strip() for t in query_types
                                    if str(t).strip() and str(t).strip() != '-'][:10],
                }
                dns_profiled += 1

        # Enrich nodes with RDP client fingerprints
        rdp_enriched = 0
        for row in rdp_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            rdp_cookie = _sv(row.get('rdp_cookie'))
            client_build_str = _sv(row.get('client_build'))
            client_name = _sv(row.get('client_name'))
            keyboard_layout = _sv(row.get('keyboard_layout'))
            desktop_w = _sv(row.get('desktop_width'))
            desktop_h = _sv(row.get('desktop_height'))
            sec_proto = _sv(row.get('security_protocol'))

            rdp_data = {}
            if rdp_cookie and rdp_cookie != '-':
                rdp_data['cookie'] = rdp_cookie
            if client_build_str and client_build_str != '-':
                try:
                    rdp_data['client_build'] = int(client_build_str)
                except (ValueError, TypeError):
                    pass
            if client_name and client_name != '-':
                rdp_data['client_name'] = client_name
            if keyboard_layout and keyboard_layout != '-':
                rdp_data['keyboard_layout'] = keyboard_layout
            if desktop_w and desktop_h and desktop_w != '-' and desktop_h != '-':
                rdp_data['resolution'] = f"{desktop_w}x{desktop_h}"
            if sec_proto and sec_proto != '-':
                rdp_data['security_protocol'] = sec_proto

            if rdp_data:
                for key in ip_to_keys.get(ip, []):
                    node = self.nodes[key]
                    node.rdp_info = rdp_data

                    # RDP cookie often contains the client hostname
                    if rdp_cookie and rdp_cookie != '-':
                        node.netbios_names.add(rdp_cookie.upper())

                    # Infer Windows version from build number
                    build = rdp_data.get('client_build')
                    if build and not node.os_info:
                        node.os_info = self._lookup_rdp_build(build)
                    rdp_enriched += 1

        # Enrich nodes with extended DHCP data (FQDN, vendor class)
        dhcp_ext_enriched = 0
        for row in dhcp_extended_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            client_fqdn = _sv(row.get('client_fqdn'))
            vendor_class = _sv(row.get('vendor_class'))
            dhcp_domain = _sv(row.get('dhcp_domain'))

            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                if client_fqdn and client_fqdn != '-' and client_fqdn != 'null':
                    node.dhcp_client_fqdn = client_fqdn.lower()
                    node.hostnames.add(client_fqdn.lower())
                if vendor_class and vendor_class != '-' and vendor_class != 'null':
                    node.dhcp_vendor_class = vendor_class
                    # Infer OS from DHCP vendor class if not already set
                    if not node.os_info:
                        vc_os = self._lookup_dhcp_vendor_class(vendor_class)
                        if vc_os:
                            node.os_info = vc_os
                if dhcp_domain and dhcp_domain != '-' and dhcp_domain != 'null':
                    if not node.domain:
                        node.domain = dhcp_domain.upper()
                dhcp_ext_enriched += 1

        # Enrich nodes with file transfer MIME types
        files_enriched = 0
        for row in files_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            mime_list = row.get('mime_types', [])
            if isinstance(mime_list, str):
                mime_list = [mime_list]
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for mime in mime_list:
                    mime = str(mime).strip()
                    if mime and mime != '-' and mime not in node.file_mime_types:
                        node.file_mime_types.append(mime)
                files_enriched += 1

        # Enrich with extended x509 certificate data (issuers, key info)
        x509_ext_enriched = 0
        for row in x509_extended_results:
            cert_names = row.get('cert_names', [])
            issuer_names = row.get('issuer_names', [])
            issuer_orgs = row.get('issuer_orgs', [])
            if isinstance(cert_names, str):
                cert_names = [cert_names]
            if isinstance(issuer_names, str):
                issuer_names = [issuer_names]
            if isinstance(issuer_orgs, str):
                issuer_orgs = [issuer_orgs]

            # x509 logs are per-sensor, try to match cert CN to node hostnames
            for key, node in self.nodes.items():
                for cn in cert_names:
                    cn = str(cn).strip().lower()
                    if cn and cn != '-':
                        # Match if CN is in this node's hostnames or netbios_names
                        cn_base = cn.lstrip('*.').split('.')[0]
                        node_names = {h.lower() for h in node.hostnames}
                        node_names |= {nb.lower() for nb in node.netbios_names}
                        if cn in node_names or cn_base in node_names or any(
                            cn in h for h in node_names
                        ):
                            if cn not in node.cert_subjects:
                                node.cert_subjects.append(cn)
                            for iss in issuer_names:
                                iss = str(iss).strip()
                                if iss and iss != '-' and iss not in node.cert_issuers:
                                    node.cert_issuers.append(iss)
                            for org in issuer_orgs:
                                org = str(org).strip()
                                if org and org != '-':
                                    iss_entry = f"O={org}"
                                    if iss_entry not in node.cert_issuers:
                                        node.cert_issuers.append(iss_entry)
                            x509_ext_enriched += 1

        # ---- Zeek Workbench host identification enrichment ----

        # Enrich with known_services (zeek_known_services)
        known_svc_enriched = 0
        for row in known_services_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            svc_names = row.get('service_names', [])
            if isinstance(svc_names, str):
                svc_names = [svc_names]
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                for svc in svc_names:
                    svc = str(svc).strip()
                    if svc and svc != '-' and svc not in node.known_services_names:
                        node.known_services_names.append(svc)
                known_svc_enriched += 1

        # Enrich with SMTP banner data
        smtp_enriched = 0
        for row in smtp_banner_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            helo_names = row.get('helo_names', [])
            last_banner = _sv(row.get('last_banner'))
            if isinstance(helo_names, str):
                helo_names = [helo_names]
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                # SMTP HELO reveals server identity
                for helo in helo_names:
                    helo = str(helo).strip()
                    if helo and helo != '-':
                        node.hostnames.add(helo.lower())
                # SMTP banner often reveals software/OS
                if last_banner and last_banner != '-':
                    entry = f"SMTP: {last_banner[:120]}"
                    if entry not in node.software:
                        node.software.append(entry)
                    # Extract OS hints from SMTP banner
                    banner_lower = last_banner.lower()
                    if not node.os_info:
                        if 'ubuntu' in banner_lower:
                            node.os_info = 'Ubuntu Linux'
                        elif 'debian' in banner_lower:
                            node.os_info = 'Debian Linux'
                        elif 'centos' in banner_lower:
                            node.os_info = 'CentOS Linux'
                        elif 'microsoft' in banner_lower or 'exchange' in banner_lower:
                            node.os_info = 'Windows Server'
                smtp_enriched += 1

        # Enrich with FTP banner data
        ftp_enriched = 0
        for row in ftp_banner_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            ftp_banner = _sv(row.get('ftp_banner'))
            if not ftp_banner or ftp_banner == '-':
                continue
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                entry = f"FTP: {ftp_banner[:120]}"
                if entry not in node.software:
                    node.software.append(entry)
                # Extract OS hints from FTP banner
                banner_lower = ftp_banner.lower()
                if not node.os_info:
                    if 'windows' in banner_lower or 'microsoft' in banner_lower:
                        node.os_info = 'Windows Server'
                    elif 'ubuntu' in banner_lower:
                        node.os_info = 'Ubuntu Linux'
                    elif 'debian' in banner_lower:
                        node.os_info = 'Debian Linux'
                    elif 'vsftpd' in banner_lower or 'proftpd' in banner_lower:
                        node.os_info = 'Linux'
                ftp_enriched += 1

        # ---- Build unified host_id for every internal node ----
        # Combines ALL identification signals into a single summary dict.
        host_id_built = 0
        for key, node in self.nodes.items():
            if not node.is_internal:
                continue

            signals = []  # List of {source, value, confidence} dicts
            os_candidates = []  # (os_string, source, confidence)

            # 1) OS from DHCP vendor class (high confidence)
            if node.dhcp_vendor_class:
                vc = node.dhcp_vendor_class
                signals.append({
                    'source': 'DHCP Vendor Class',
                    'value': vc,
                })
                vc_lower = vc.lower()
                if 'msft' in vc_lower or 'microsoft' in vc_lower:
                    os_candidates.append(('Windows', 'DHCP Vendor Class', 90))
                elif 'android' in vc_lower:
                    os_candidates.append(('Android', 'DHCP Vendor Class', 85))
                elif 'linux' in vc_lower:
                    os_candidates.append(('Linux', 'DHCP Vendor Class', 80))
                elif 'apple' in vc_lower or 'darwin' in vc_lower:
                    os_candidates.append(('macOS/iOS', 'DHCP Vendor Class', 85))

            # 2) OS from software.log (high confidence)
            for sw in node.software[:10]:
                sw_lower = sw.lower()
                if 'windows' in sw_lower:
                    # Try to extract specific version
                    if 'windows 10' in sw_lower or 'windows 11' in sw_lower:
                        os_candidates.append((sw.split(',')[0][:60], 'Zeek Software', 90))
                    else:
                        os_candidates.append(('Windows', 'Zeek Software', 85))
                    signals.append({'source': 'Zeek Software', 'value': sw[:80]})
                    break
                elif any(x in sw_lower for x in ['ubuntu', 'debian', 'centos', 'rhel', 'fedora']):
                    os_candidates.append((sw.split(',')[0][:60], 'Zeek Software', 90))
                    signals.append({'source': 'Zeek Software', 'value': sw[:80]})
                    break
                elif 'macos' in sw_lower or 'darwin' in sw_lower:
                    os_candidates.append(('macOS', 'Zeek Software', 85))
                    signals.append({'source': 'Zeek Software', 'value': sw[:80]})
                    break
                elif any(x in sw_lower for x in ['ssh server:', 'ssh client:', 'smtp:', 'ftp:']):
                    signals.append({'source': 'Zeek Software', 'value': sw[:80]})

            # 3) OS from direct os_info field
            if node.os_info:
                os_candidates.append((node.os_info, 'OS Detection', 80))
                if not any(s['source'] == 'OS Detection' for s in signals):
                    signals.append({
                        'source': 'OS Detection',
                        'value': node.os_info,
                    })

            # 4) SSH banners (medium-high confidence)
            for sw in node.software[:10]:
                if sw.startswith('SSH server:') or sw.startswith('SSH client:'):
                    banner = sw.split(':', 1)[1].strip()
                    if not any(s['source'] == 'SSH Banner' for s in signals):
                        signals.append({
                            'source': 'SSH Banner',
                            'value': banner[:80],
                        })
                    banner_lower = banner.lower()
                    if 'ubuntu' in banner_lower:
                        os_candidates.append(('Ubuntu Linux', 'SSH Banner', 75))
                    elif 'debian' in banner_lower:
                        os_candidates.append(('Debian Linux', 'SSH Banner', 75))
                    elif 'windows' in banner_lower:
                        os_candidates.append(('Windows', 'SSH Banner', 75))

            # 5) HTTP User-Agent (medium confidence, client-side)
            for ua in node.user_agents[:3]:
                ua_lower = ua.lower()
                signals.append({
                    'source': 'HTTP User-Agent',
                    'value': ua[:100],
                })
                if 'windows nt 10' in ua_lower:
                    os_candidates.append(('Windows 10/11', 'HTTP User-Agent', 65))
                elif 'windows nt 6.3' in ua_lower:
                    os_candidates.append(('Windows 8.1', 'HTTP User-Agent', 65))
                elif 'windows nt 6.1' in ua_lower:
                    os_candidates.append(('Windows 7', 'HTTP User-Agent', 65))
                elif 'macintosh' in ua_lower or 'mac os x' in ua_lower:
                    os_candidates.append(('macOS', 'HTTP User-Agent', 65))
                elif 'linux' in ua_lower and 'android' not in ua_lower:
                    os_candidates.append(('Linux', 'HTTP User-Agent', 60))
                elif 'android' in ua_lower:
                    os_candidates.append(('Android', 'HTTP User-Agent', 65))
                elif 'iphone' in ua_lower or 'ipad' in ua_lower:
                    os_candidates.append(('iOS', 'HTTP User-Agent', 65))
                break  # Only use first UA

            # 6) RDP build number (high confidence for Windows)
            if node.rdp_info:
                build = node.rdp_info.get('client_build')
                if build:
                    signals.append({
                        'source': 'RDP Build',
                        'value': f"Build {build}",
                    })
                    rdp_os = self._lookup_rdp_build(build)
                    if rdp_os:
                        os_candidates.append((rdp_os, 'RDP Build', 92))

            # 7) DHCP client FQDN
            if node.dhcp_client_fqdn:
                signals.append({
                    'source': 'DHCP FQDN',
                    'value': node.dhcp_client_fqdn,
                })

            # 8) SMTP/FTP banners
            for sw in node.software[:15]:
                if sw.startswith('SMTP:'):
                    if not any(s['source'] == 'SMTP Banner' for s in signals):
                        signals.append({
                            'source': 'SMTP Banner',
                            'value': sw[5:].strip()[:80],
                        })
                elif sw.startswith('FTP:'):
                    if not any(s['source'] == 'FTP Banner' for s in signals):
                        signals.append({
                            'source': 'FTP Banner',
                            'value': sw[4:].strip()[:80],
                        })

            # 9) Known services
            if node.known_services_names:
                signals.append({
                    'source': 'Zeek Known Services',
                    'value': ', '.join(node.known_services_names[:10]),
                })

            # 10) TLS/JA3 data
            if node.tls_server_names:
                signals.append({
                    'source': 'TLS SNI',
                    'value': ', '.join(node.tls_server_names[:5]),
                })
            if node.ja3_fingerprints:
                signals.append({
                    'source': 'JA3 Client',
                    'value': ', '.join(node.ja3_fingerprints[:3]),
                })

            # 11) Cert subjects
            if node.cert_subjects:
                signals.append({
                    'source': 'TLS Certificate',
                    'value': ', '.join(node.cert_subjects[:3]),
                })

            # 12) MAC vendor
            if node.vendor:
                signals.append({
                    'source': 'MAC Vendor',
                    'value': node.vendor,
                })

            # Skip nodes with no identification signals
            if not signals:
                continue

            # Pick best OS candidate by confidence
            best_os = None
            best_os_source = None
            best_os_confidence = 0
            for os_str, source, conf in os_candidates:
                if conf > best_os_confidence:
                    best_os = os_str
                    best_os_source = source
                    best_os_confidence = conf

            # Compute overall confidence based on signal count + OS confidence
            signal_count = len(signals)
            overall_confidence = min(
                best_os_confidence + (signal_count * 3),
                100,
            ) if best_os else min(signal_count * 12, 60)

            node.host_id = {
                'os': best_os or 'Unknown',
                'os_source': best_os_source or '',
                'os_confidence': best_os_confidence,
                'confidence': overall_confidence,
                'signal_count': signal_count,
                'signals': signals[:15],  # Cap to 15 signals
            }
            host_id_built += 1

        logger.info(
            f"Device profiling ({total_windows} window(s)): "
            f"{len(accumulated['server_agg'])} server IPs, "
            f"{len(accumulated['client_agg'])} client IPs, "
            f"{len(ntlm_results)} NTLM events ({ntlm_enriched} enrichments), "
            f"{len(kerberos_results)} Kerberos responders, "
            f"{len(kdc_ips)} KDC IPs, {len(ntlm_auth_servers)} heavy NTLM auth servers, "
            f"{len(dhcp_results)} DHCP leases ({dhcp_enriched} MAC enrichments, "
            f"{mac_bindings_recorded} MAC-IP bindings recorded, "
            f"{len(self.mac_history)} unique MACs tracked), "
            f"{len(snmp_results)} SNMP hosts ({snmp_enriched} enrichments), "
            f"{len(smb_results)} SMB hosts ({smb_enriched} NetBIOS names), "
            f"{len(software_results)} software detections ({software_enriched} enrichments), "
            f"{len(ssh_results)} SSH sessions ({ssh_enriched} enrichments), "
            f"{len(http_ua_results)} HTTP UA profiles ({ua_enriched} enrichments)"
        )
        logger.info(
            f"Deep fingerprint enrichment: "
            f"{len(ja3_ssl_results)} JA3/SSL ({ja3_enriched} enrichments), "
            f"{len(ja3s_server_results)} JA3S server ({ja3s_enriched} enrichments), "
            f"{len(dns_profile_results)} DNS profiles ({dns_profiled} enrichments), "
            f"{len(rdp_results)} RDP ({rdp_enriched} enrichments), "
            f"{len(dhcp_extended_results)} DHCP extended ({dhcp_ext_enriched} enrichments), "
            f"{len(files_results)} file transfers ({files_enriched} enrichments), "
            f"{len(x509_extended_results)} x509 extended ({x509_ext_enriched} enrichments)"
        )
        logger.info(
            f"Host identification: "
            f"{len(known_services_results)} known services ({known_svc_enriched} enrichments), "
            f"{len(smtp_banner_results)} SMTP banners ({smtp_enriched} enrichments), "
            f"{len(ftp_banner_results)} FTP banners ({ftp_enriched} enrichments), "
            f"{host_id_built} host IDs built"
        )

        # Use pre-aggregated server/client data from windowed merge
        server_data = accumulated['server_agg']
        client_data = accumulated['client_agg']

        # ---- Router / firewall detection ----
        # Phase 1: Build gateway IP set from DHCP Option 3 (router field)
        dhcp_gateway_ips: Dict[str, set] = defaultdict(set)  # ip -> set of subnets
        for row in dhcp_gateway_results:
            gw_ip = _sv(row.get('gateway_ip'))
            vlan = _sv(row.get('vlan'), '0')
            client_count = int(_sv(row.get('client_count'), '0'))
            clients = row.get('clients', [])
            if isinstance(clients, str):
                clients = [clients]
            if not gw_ip or gw_ip == '-':
                continue
            # Compute subnet from a sample client IP
            for client_ip in clients:
                client_ip = str(client_ip).strip()
                parts = client_ip.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3]) + '.0/24'
                    dhcp_gateway_ips[gw_ip].add(subnet)
                    break
            else:
                # No client IP to derive subnet — use gateway's own /24
                parts = gw_ip.split('.')
                if len(parts) == 4:
                    dhcp_gateway_ips[gw_ip].add('.'.join(parts[:3]) + '.0/24')

        # Phase 2: SNMP OID enrichment for network infrastructure
        snmp_infra_ips: Dict[str, str] = {}  # ip -> inferred type from OID
        for row in snmp_oid_results:
            ip = _sv(row.get('ip'))
            if not ip:
                continue
            # Try to get device model from OID for the node
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                if node.device_model:
                    oid_type = self._infer_type_from_snmp_oid(node.device_model)
                    if oid_type:
                        snmp_infra_ips[ip] = oid_type

        # Phase 3: Detect default gateways from subnet .1 / .254 heuristic
        # Any IP ending in .1 or .254 that has significant inbound connections
        # from its own /24 subnet is likely a gateway
        subnet_gateway_ips: Dict[str, set] = defaultdict(set)  # ip -> subnets
        for key, node in self.nodes.items():
            if not node.is_internal:
                continue
            parts = node.ip.split('.')
            if len(parts) != 4:
                continue
            last_octet = int(parts[3])
            if last_octet not in (1, 254):
                continue
            subnet = '.'.join(parts[:3]) + '.0/24'
            # Check: does this IP have many clients from its own subnet?
            same_subnet_clients = 0
            for src_ip in node.connections_from:
                src_parts = src_ip.split('.')
                if len(src_parts) == 4 and src_parts[:3] == parts[:3]:
                    same_subnet_clients += 1
            if same_subnet_clients >= 3:
                subnet_gateway_ips[node.ip].add(subnet)

        # Phase 4: Cross-subnet traffic analysis
        # Devices that communicate with many DIFFERENT subnets (≥4) and have
        # high bidirectional traffic are likely routers/firewalls
        cross_subnet_ips: Dict[str, set] = defaultdict(set)  # ip -> set of /24 subnets
        for key, node in self.nodes.items():
            if not node.is_internal:
                continue
            subnets_seen = set()
            own_parts = node.ip.split('.')
            if len(own_parts) != 4:
                continue
            own_subnet = '.'.join(own_parts[:3])
            for peer_ip in list(node.connections_to.keys())[:500]:
                p = peer_ip.split('.')
                if len(p) == 4:
                    peer_sub = '.'.join(p[:3])
                    if peer_sub != own_subnet:
                        subnets_seen.add(peer_sub + '.0/24')
            for peer_ip in list(node.connections_from.keys())[:500]:
                p = peer_ip.split('.')
                if len(p) == 4:
                    peer_sub = '.'.join(p[:3])
                    if peer_sub != own_subnet:
                        subnets_seen.add(peer_sub + '.0/24')
            if len(subnets_seen) >= 4:
                cross_subnet_ips[node.ip] = subnets_seen

        # Phase 5: MAC vendor-based infrastructure detection
        mac_infra_ips: Dict[str, str] = {}  # ip -> infra hint
        for key, node in self.nodes.items():
            if not node.is_internal or not node.vendor:
                continue
            hint = self._detect_network_infra(node.vendor)
            if hint:
                mac_infra_ips[node.ip] = hint

        # Combine all gateway/router/firewall evidence
        all_infra_candidates = set()
        all_infra_candidates.update(dhcp_gateway_ips.keys())
        all_infra_candidates.update(snmp_infra_ips.keys())
        all_infra_candidates.update(subnet_gateway_ips.keys())
        all_infra_candidates.update(cross_subnet_ips.keys())
        all_infra_candidates.update(mac_infra_ips.keys())

        # Annotate nodes with gateway evidence and is_gateway_for subnets
        for ip in all_infra_candidates:
            for key in ip_to_keys.get(ip, []):
                node = self.nodes[key]
                evidence = []
                gw_subnets = set()
                if ip in dhcp_gateway_ips:
                    subs = dhcp_gateway_ips[ip]
                    gw_subnets.update(subs)
                    evidence.append(f"DHCP Option 3 gateway for {', '.join(sorted(subs))}")
                if ip in snmp_infra_ips:
                    evidence.append(f"SNMP OID: {node.device_model} ({snmp_infra_ips[ip]})")
                if ip in subnet_gateway_ips:
                    subs = subnet_gateway_ips[ip]
                    gw_subnets.update(subs)
                    evidence.append(f"Subnet gateway (.1/.254) for {', '.join(sorted(subs))}")
                if ip in cross_subnet_ips:
                    subs = cross_subnet_ips[ip]
                    gw_subnets.update(subs)
                    evidence.append(f"Cross-subnet traffic to {len(subs)} subnets")
                if ip in mac_infra_ips:
                    evidence.append(f"Network vendor: {node.vendor} ({mac_infra_ips[ip]})")
                # Merge with any existing gateway data from previous runs
                node.is_gateway_for = (node.is_gateway_for or set()) | gw_subnets
                for ev in evidence:
                    if ev not in node.gateway_evidence:
                        node.gateway_evidence.append(ev)

        logger.info(
            f"Router/firewall detection: "
            f"{len(dhcp_gateway_ips)} DHCP gateways, "
            f"{len(snmp_infra_ips)} SNMP infra, "
            f"{len(subnet_gateway_ips)} subnet gateways (.1/.254), "
            f"{len(cross_subnet_ips)} cross-subnet forwarders, "
            f"{len(mac_infra_ips)} vendor-identified infra"
        )

        # Classify each node in the network map
        _progress('profile',
                  f'Classifying {internal_count} internal devices '
                  f'({len(server_data)} server profiles, {len(client_data)} client profiles)...',
                  85)
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

            # Router/firewall override: use multi-signal evidence when
            # the port-based classifier returned gateway or no match
            if not device_type or device_type in ('gateway', 'iot_device', 'workstation'):
                infra_evidence_count = 0
                inferred_infra_type = ''

                if ip in snmp_infra_ips:
                    inferred_infra_type = snmp_infra_ips[ip]
                    infra_evidence_count += 2  # SNMP OID is strong evidence

                if ip in dhcp_gateway_ips:
                    infra_evidence_count += 2  # DHCP Option 3 is strong evidence
                    if not inferred_infra_type:
                        inferred_infra_type = 'router'

                if ip in mac_infra_ips:
                    hint = mac_infra_ips[ip]
                    infra_evidence_count += 1
                    if not inferred_infra_type:
                        if 'firewall' in hint:
                            inferred_infra_type = 'firewall'
                        else:
                            inferred_infra_type = 'router'

                if ip in subnet_gateway_ips:
                    infra_evidence_count += 1
                    if not inferred_infra_type:
                        inferred_infra_type = 'router'

                if ip in cross_subnet_ips:
                    n_subs = len(cross_subnet_ips[ip])
                    infra_evidence_count += 1 if n_subs < 8 else 2
                    if not inferred_infra_type:
                        inferred_infra_type = 'router'

                # Require at least 2 evidence points to override, or
                # 1 strong signal (SNMP OID or DHCP gateway)
                if infra_evidence_count >= 2 and inferred_infra_type:
                    device_type = inferred_infra_type

            # Protect existing specific classifications from being
            # downgraded to generic fallback types on short profiling runs.
            # A short time window may not see enough clients to re-confirm a
            # profile match, causing the fallback heuristics (gateway,
            # workstation, iot_device) to mis-classify.
            _FALLBACK_TYPES = {'gateway', 'workstation', 'iot_device'}
            _SPECIFIC_TYPES = {
                'domain_controller', 'dns_server', 'web_server',
                'database_server', 'mail_server', 'file_server',
                'dhcp_server', 'ssh_server', 'vpn_gateway',
                'router', 'firewall', 'print_server',
                'syslog_server', 'monitoring',
            }

            if device_type:
                old_type = node.device_type
                # Never downgrade a specific type to a generic fallback
                if old_type in _SPECIFIC_TYPES and device_type in _FALLBACK_TYPES:
                    # Keep old classification; still count it
                    type_counts[old_type] += 1
                    classified += 1
                else:
                    node.device_type = device_type
                    classified += 1
                    type_counts[device_type] += 1
            elif node.device_type:
                # No new classification but old one exists — preserve it
                type_counts[node.device_type] += 1
                classified += 1

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

        # Persist MAC history alongside the map
        self._save_mac_history()

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

    def get_mac_tracking(self) -> Dict:
        """Get MAC-to-IP tracking summary for the UI.

        Returns MACs that have been seen with multiple IPs (device mobility)
        and a full listing for drill-down.
        """
        multi_ip_macs = []
        all_macs = []

        for mac, bindings in self.mac_history.items():
            unique_ips = {b.ip for b in bindings}
            vendor = self._lookup_oui(mac)
            entry = {
                'mac': mac,
                'vendor': vendor,
                'ip_count': len(unique_ips),
                'ips': sorted(unique_ips),
                'bindings': [b.to_dict() for b in sorted(
                    bindings, key=lambda x: x.last_seen, reverse=True
                )],
            }
            all_macs.append(entry)
            if len(unique_ips) > 1:
                multi_ip_macs.append(entry)

        # Sort: devices with most IPs first (likely DHCP / mobile)
        multi_ip_macs.sort(key=lambda x: x['ip_count'], reverse=True)
        all_macs.sort(key=lambda x: x['ip_count'], reverse=True)

        return {
            'total_macs': len(self.mac_history),
            'multi_ip_count': len(multi_ip_macs),
            'multi_ip_devices': multi_ip_macs[:100],
            'all_devices': all_macs[:500],
        }

    def get_mac_history_detail(self, mac: str) -> Optional[Dict]:
        """Get detailed MAC history for a single MAC address."""
        mac = mac.strip().upper().replace('-', ':')
        bindings = self.mac_history.get(mac)
        if not bindings:
            return None
        unique_ips = {b.ip for b in bindings}
        vendor = self._lookup_oui(mac)

        # Find all nodes associated with this MAC
        associated_nodes = []
        for key, node in self.nodes.items():
            if node.mac_address == mac or node.ip in unique_ips:
                associated_nodes.append({
                    'ip': node.ip,
                    'sensor_id': node.sensor_id,
                    'vlan': node.vlan,
                    'hostnames': sorted(node.hostnames)[:5],
                    'netbios_names': sorted(node.netbios_names)[:5],
                    'device_type': node.device_type,
                    'domain': node.domain,
                })

        return {
            'mac': mac,
            'vendor': vendor,
            'ip_count': len(unique_ips),
            'bindings': [b.to_dict() for b in sorted(
                bindings, key=lambda x: x.last_seen, reverse=True
            )],
            'associated_nodes': associated_nodes,
        }

    def get_device_identity(self, ip: str) -> Optional[Dict]:
        """Given an IP, find all MACs associated with it and their other IPs.

        This helps answer: "What other IPs has this device used?"
        """
        result_macs = []
        for mac, bindings in self.mac_history.items():
            ip_match = any(b.ip == ip for b in bindings)
            if ip_match:
                unique_ips = {b.ip for b in bindings}
                vendor = self._lookup_oui(mac)
                result_macs.append({
                    'mac': mac,
                    'vendor': vendor,
                    'ip_count': len(unique_ips),
                    'bindings': [b.to_dict() for b in sorted(
                        bindings, key=lambda x: x.last_seen, reverse=True
                    )],
                })
        if not result_macs:
            return None
        return {
            'ip': ip,
            'macs': result_macs,
        }

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
                    'is_virtual': n.is_virtual,
                    'virtual_platform': n.virtual_platform,
                    'os_info': n.os_info,
                    'device_model': n.device_model,
                    'software': n.software[:5],
                    'services': svcs,
                    'connections': n.total_connections,
                    'sensor_id': n.sensor_id,
                    # Deep fingerprint data
                    'dhcp_vendor_class': n.dhcp_vendor_class,
                    'ja3_count': len(n.ja3_fingerprints),
                    'tls_versions': n.tls_versions_seen[:3],
                    'dns_query_count': n.dns_profile.get('query_count', 0),
                    'dns_nxdomain_ratio': n.dns_profile.get('nxdomain_ratio', 0),
                    'rdp_info': n.rdp_info if n.rdp_info else None,
                    'cert_subjects': n.cert_subjects[:3],
                    'file_types': n.file_mime_types[:5],
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
            'virtual_machines': sum(1 for n in nodes if n.is_internal and n.is_virtual),
            'routers': sum(1 for n in nodes if n.is_internal and n.device_type == 'router'),
            'firewalls': sum(1 for n in nodes if n.is_internal and n.device_type == 'firewall'),
            'gateways': sum(1 for n in nodes if n.is_internal and n.device_type in ('gateway', 'router', 'firewall') and n.is_gateway_for),
            'mac_tracking': {
                'total_macs': len(self.mac_history),
                'multi_ip_count': sum(
                    1 for bindings in self.mac_history.values()
                    if len({b.ip for b in bindings}) > 1
                ),
            },
            'fingerprint_coverage': {
                'ja3_fingerprinted': sum(
                    1 for n in nodes if n.is_internal and n.ja3_fingerprints
                ),
                'dns_profiled': sum(
                    1 for n in nodes if n.is_internal and n.dns_profile
                ),
                'rdp_fingerprinted': sum(
                    1 for n in nodes if n.is_internal and n.rdp_info
                ),
                'dhcp_vendor_identified': sum(
                    1 for n in nodes if n.is_internal and n.dhcp_vendor_class
                ),
                'cert_identified': sum(
                    1 for n in nodes if n.is_internal and n.cert_subjects
                ),
                'file_types_tracked': sum(
                    1 for n in nodes if n.is_internal and n.file_mime_types
                ),
                'os_identified': sum(
                    1 for n in nodes if n.is_internal and n.os_info
                ),
                'host_identified': sum(
                    1 for n in nodes if n.is_internal and n.host_id
                ),
            },
        }

        self._stats_cache = summary
        self._stats_cache_time = now
        return summary

    def get_network_graph(
        self,
        sensor_id: Optional[str] = None,
        max_nodes: int = 5000,
    ) -> Dict:
        """
        Get network graph suitable for visualization.

        External IPs are collapsed into a single "Internet" cloud node.
        Each internal node includes its external connection details so the
        UI can display them on click.

        Args:
            sensor_id: Optional sensor filter
            max_nodes: Maximum nodes to return (default 5000)

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

        # Compute VLAN distribution from ALL internal nodes (not just top-N)
        all_vlan_counts: Dict[str, int] = {}
        for n in internal_nodes:
            all_vlan_counts[n.vlan] = all_vlan_counts.get(n.vlan, 0) + 1

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
            # Build label: prefer NetBIOS name, then hostname, fall back to IP
            # Format:  NAME \n IP \n hostname (if different from name)
            nb_name = next(iter(sorted(node.netbios_names)), '')
            hostname = next(iter(sorted(node.hostnames)), '')

            if nb_name:
                label = f"{nb_name}\n{node.ip}"
                # Add hostname below if it's different from the NetBIOS name
                if hostname and hostname.lower().split('.')[0] != nb_name.lower():
                    label += f"\n{hostname}"
            elif hostname:
                label = f"{hostname}\n{node.ip}"
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

            # Collect internal peer connections for click details.
            # Include ALL internal peers (both directions) regardless
            # of whether the peer is in the current graph view.
            int_conns_out = []
            own_key = self._node_key(node.sensor_id, node.vlan, node.ip)
            for dst_ip, count in sorted(
                node.connections_to.items(),
                key=lambda x: x[1], reverse=True,
            )[:30]:
                dst_key = self._node_key(node.sensor_id, node.vlan, dst_ip)
                if dst_key != own_key and dst_key not in external_keys:
                    int_conns_out.append({'ip': dst_ip, 'count': count})
            int_conns_in = []
            for src_ip, count in sorted(
                node.connections_from.items(),
                key=lambda x: x[1], reverse=True,
            )[:30]:
                src_key = self._node_key(node.sensor_id, node.vlan, src_ip)
                if src_key != own_key and src_key not in external_keys:
                    int_conns_in.append({'ip': src_ip, 'count': count})

            # Count how many IPs this MAC has been seen with
            mac_ip_count = 0
            if node.mac_address and node.mac_address in self.mac_history:
                mac_ip_count = len({b.ip for b in self.mac_history[node.mac_address]})

            # Compute /24 subnet from IP
            ip_parts = node.ip.split('.')
            subnet = (
                '.'.join(ip_parts[:3]) + '.0/24'
                if len(ip_parts) == 4 else ''
            )

            nodes.append({
                'id': self._node_key(node.sensor_id, node.vlan, node.ip),
                'label': label,
                'sensor_id': node.sensor_id,
                'vlan': node.vlan,
                'subnet': subnet,
                'group': 'internal',
                'size': min(node.total_connections / 10, 50),
                'roles': list(node.roles),
                'services': len(node.services),
                'services_list': sorted(
                    [f"{port}/{proto}" for port, proto in node.services],
                    key=lambda s: int(s.split('/')[0]) if s.split('/')[0].isdigit() else 0,
                )[:50],
                'device_type': node.device_type,
                'device_label': self._device_label(node.device_type),
                'tier': self._device_tier(node.device_type, node.is_internal),
                'netbios_names': sorted(node.netbios_names)[:3],
                'domain': node.domain,
                'hostnames': sorted(node.hostnames)[:3],
                'mac_address': node.mac_address,
                'mac_ip_count': mac_ip_count,
                'is_virtual': node.is_virtual,
                'virtual_platform': node.virtual_platform,
                'os_info': node.os_info,
                'device_model': node.device_model,
                'software': node.software[:5],
                'user_agents': node.user_agents[:10],
                'vendor': node.vendor,
                # Deep fingerprint data
                'dhcp_client_fqdn': node.dhcp_client_fqdn,
                'dhcp_vendor_class': node.dhcp_vendor_class,
                'ja3_fingerprints': node.ja3_fingerprints[:5],
                'ja3s_fingerprints': node.ja3s_fingerprints[:5],
                'tls_server_names': node.tls_server_names[:10],
                'tls_versions_seen': node.tls_versions_seen[:5],
                'dns_profile': node.dns_profile,
                'rdp_info': node.rdp_info,
                'cert_subjects': node.cert_subjects[:5],
                'cert_issuers': node.cert_issuers[:5],
                'file_mime_types': node.file_mime_types[:10],
                'external_connections_out': ext_conns_out[:50],
                'external_connections_in': ext_conns_in[:50],
                'internal_connections_out': int_conns_out,
                'internal_connections_in': int_conns_in,
                'is_gateway_for': sorted(node.is_gateway_for) if node.is_gateway_for else [],
                'gateway_evidence': node.gateway_evidence[:10] if node.gateway_evidence else [],
                # Host identification
                'host_id': node.host_id if node.host_id else None,
                'known_services_names': node.known_services_names[:20] if node.known_services_names else [],
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
            'all_vlans': all_vlan_counts,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def cleanup(self):
        """Clean up plugin resources."""
        self.save_map()
        logger.info("Network Mapper cleaned up")
        self.enabled = False
