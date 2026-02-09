"""
Network Mapper Plugin

Builds and maintains a network topology map from observed traffic.
Tracks hosts, connections, services, and communication patterns.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Set, Any
from collections import defaultdict
from pathlib import Path

from artemis.plugins import ArtemisPlugin


logger = logging.getLogger("artemis.plugins.network_mapper")


class NetworkNode:
    """Represents a network host."""

    def __init__(self, ip: str):
        self.ip = ip
        self.hostnames = set()
        self.services = set()  # (port, protocol) tuples
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.total_connections = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections_to = defaultdict(int)  # IP -> count
        self.connections_from = defaultdict(int)  # IP -> count
        self.is_internal = self._is_internal_ip(ip)
        self.roles = set()  # server, client, scanner, etc.

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal (RFC1918)."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True

            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True

            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

        except ValueError:
            pass

        return False

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'ip': self.ip,
            'hostnames': list(self.hostnames),
            'services': [f"{port}/{proto}" for port, proto in self.services],
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'total_connections': self.total_connections,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'is_internal': self.is_internal,
            'roles': list(self.roles),
            'top_destinations': dict(sorted(
                self.connections_to.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_sources': dict(sorted(
                self.connections_from.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }


class NetworkMapperPlugin(ArtemisPlugin):
    """Plugin that builds network topology maps."""

    DESCRIPTION = "Builds and visualizes network topology from observed traffic"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.nodes: Dict[str, NetworkNode] = {}
        self.output_dir = Path(config.get('output_dir', 'network_maps'))
        self.auto_save_interval = config.get('auto_save_interval', 300)  # 5 minutes
        self.last_save = datetime.now()

    def initialize(self):
        """Initialize network mapper."""
        self.output_dir.mkdir(exist_ok=True)
        logger.info(f"Network Mapper initialized. Output: {self.output_dir}")
        self.enabled = True

        # Load existing map if available
        self._load_existing_map()

    def _load_existing_map(self):
        """Load existing network map from disk."""
        map_file = self.output_dir / "current_map.json"
        if map_file.exists():
            try:
                with open(map_file) as f:
                    data = json.load(f)

                for node_data in data.get('nodes', []):
                    node = NetworkNode(node_data['ip'])
                    node.hostnames = set(node_data.get('hostnames', []))
                    node.services = {
                        tuple(s.split('/'))
                        for s in node_data.get('services', [])
                    }
                    node.total_connections = node_data.get('total_connections', 0)
                    node.bytes_sent = node_data.get('bytes_sent', 0)
                    node.bytes_received = node_data.get('bytes_received', 0)
                    node.roles = set(node_data.get('roles', []))

                    self.nodes[node.ip] = node

                logger.info(f"Loaded existing map with {len(self.nodes)} nodes")

            except Exception as e:
                logger.error(f"Error loading existing map: {e}")

    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Process network data and update map.

        Expected kwargs:
            network_connections: List of connection records
            dns_queries: List of DNS query records
        """
        connections = kwargs.get('network_connections', [])
        dns_queries = kwargs.get('dns_queries', [])

        logger.info(f"Processing {len(connections)} connections and {len(dns_queries)} DNS queries")

        # Process connections
        for conn in connections:
            self._process_connection(conn)

        # Process DNS queries
        for dns in dns_queries:
            self._process_dns(dns)

        # Infer roles
        self._infer_roles()

        # Auto-save if needed
        if (datetime.now() - self.last_save).total_seconds() > self.auto_save_interval:
            self.save_map()

        return {
            'total_nodes': len(self.nodes),
            'internal_nodes': sum(1 for n in self.nodes.values() if n.is_internal),
            'external_nodes': sum(1 for n in self.nodes.values() if not n.is_internal),
            'total_services': sum(len(n.services) for n in self.nodes.values()),
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

        if not src_ip or not dst_ip:
            return

        # Get or create nodes
        if src_ip not in self.nodes:
            self.nodes[src_ip] = NetworkNode(src_ip)

        if dst_ip not in self.nodes:
            self.nodes[dst_ip] = NetworkNode(dst_ip)

        src_node = self.nodes[src_ip]
        dst_node = self.nodes[dst_ip]

        # Update timestamps
        now = datetime.now()
        src_node.last_seen = now
        dst_node.last_seen = now

        # Update connection counts
        src_node.total_connections += 1
        dst_node.total_connections += 1

        src_node.connections_to[dst_ip] += 1
        dst_node.connections_from[src_ip] += 1

        # Update bytes
        src_node.bytes_sent += bytes_out
        src_node.bytes_received += bytes_in
        dst_node.bytes_sent += bytes_in
        dst_node.bytes_received += bytes_out

        # Track services (destination port)
        if dst_port:
            dst_node.services.add((dst_port, protocol))

    def _process_dns(self, dns: Dict):
        """Process a DNS query."""
        src_ip = dns.get('source_ip')
        domain = dns.get('domain')
        answer = dns.get('answer')

        if not src_ip:
            return

        # Get or create source node
        if src_ip not in self.nodes:
            self.nodes[src_ip] = NetworkNode(src_ip)

        src_node = self.nodes[src_ip]
        src_node.last_seen = datetime.now()

        # If we have an answer IP, link hostname
        if answer and domain:
            # Check if answer is an IP
            if '.' in answer and all(p.isdigit() for p in answer.split('.')):
                if answer not in self.nodes:
                    self.nodes[answer] = NetworkNode(answer)

                self.nodes[answer].hostnames.add(domain)

    def _infer_roles(self):
        """Infer host roles based on behavior."""
        for node in self.nodes.values():
            # Server: has many incoming connections
            if len(node.connections_from) > 10:
                node.roles.add('server')

            # Client: primarily initiates connections
            if len(node.connections_to) > len(node.connections_from) * 2:
                node.roles.add('client')

            # Scanner: connects to many different hosts
            if len(node.connections_to) > 50:
                node.roles.add('scanner')

            # Popular: many sources connect to it
            if len(node.connections_from) > 50:
                node.roles.add('popular')

            # DNS Server: listening on port 53
            if (53, 'udp') in node.services or (53, 'tcp') in node.services:
                node.roles.add('dns_server')

            # Web Server: listening on ports 80/443
            if (80, 'tcp') in node.services or (443, 'tcp') in node.services:
                node.roles.add('web_server')

            # Mail Server: listening on ports 25/587/993
            if any(p in node.services for p in [(25, 'tcp'), (587, 'tcp'), (993, 'tcp')]):
                node.roles.add('mail_server')

    def save_map(self) -> str:
        """Save current network map to disk."""
        map_file = self.output_dir / "current_map.json"

        map_data = {
            'timestamp': datetime.now().isoformat(),
            'total_nodes': len(self.nodes),
            'nodes': [node.to_dict() for node in self.nodes.values()]
        }

        with open(map_file, 'w') as f:
            json.dump(map_data, f, indent=2)

        self.last_save = datetime.now()
        logger.info(f"Saved network map with {len(self.nodes)} nodes to {map_file}")

        # Also generate summary
        self._generate_summary()

        return str(map_file)

    def _generate_summary(self):
        """Generate human-readable network summary."""
        summary_file = self.output_dir / "network_summary.txt"

        internal_nodes = [n for n in self.nodes.values() if n.is_internal]
        external_nodes = [n for n in self.nodes.values() if not n.is_internal]

        with open(summary_file, 'w') as f:
            f.write("ARTEMIS NETWORK MAP SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write(f"Total Nodes: {len(self.nodes)}\n")
            f.write(f"  - Internal: {len(internal_nodes)}\n")
            f.write(f"  - External: {len(external_nodes)}\n\n")

            # Top internal hosts by connections
            f.write("TOP INTERNAL HOSTS (by connection count):\n")
            f.write("-" * 80 + "\n")
            for node in sorted(internal_nodes, key=lambda n: n.total_connections, reverse=True)[:10]:
                roles_str = ", ".join(node.roles) if node.roles else "unknown"
                f.write(f"  {node.ip:15s} | {node.total_connections:6d} conns | Roles: {roles_str}\n")
                if node.services:
                    services = ", ".join(f"{p}/{pr}" for p, pr in sorted(node.services)[:5])
                    f.write(f"                   Services: {services}\n")

            # Top external destinations
            f.write("\nTOP EXTERNAL DESTINATIONS:\n")
            f.write("-" * 80 + "\n")
            for node in sorted(external_nodes, key=lambda n: n.total_connections, reverse=True)[:10]:
                hostname = list(node.hostnames)[0] if node.hostnames else "unknown"
                f.write(f"  {node.ip:15s} | {node.total_connections:6d} conns | {hostname}\n")

            # Servers identified
            servers = [n for n in internal_nodes if 'server' in n.roles or n.services]
            f.write(f"\nIDENTIFIED SERVERS ({len(servers)}):\n")
            f.write("-" * 80 + "\n")
            for node in sorted(servers, key=lambda n: len(n.services), reverse=True)[:20]:
                services = ", ".join(f"{p}/{pr}" for p, pr in sorted(node.services)[:8])
                f.write(f"  {node.ip:15s} | Services: {services or 'none detected'}\n")

        logger.info(f"Generated network summary: {summary_file}")

    def get_network_graph(self) -> Dict:
        """
        Get network graph in format suitable for visualization.

        Returns:
            Dict with nodes and edges for graph visualization
        """
        nodes = []
        edges = []

        # Build nodes
        for ip, node in self.nodes.items():
            nodes.append({
                'id': ip,
                'label': ip,
                'group': 'internal' if node.is_internal else 'external',
                'size': min(node.total_connections / 10, 50),
                'roles': list(node.roles),
                'services': len(node.services)
            })

        # Build edges (top connections only to avoid clutter)
        seen_edges = set()
        for src_ip, src_node in self.nodes.items():
            for dst_ip, count in sorted(
                src_node.connections_to.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]:  # Top 5 connections per node
                edge_key = tuple(sorted([src_ip, dst_ip]))
                if edge_key not in seen_edges:
                    edges.append({
                        'from': src_ip,
                        'to': dst_ip,
                        'value': count,
                        'title': f"{count} connections"
                    })
                    seen_edges.add(edge_key)

        return {
            'nodes': nodes,
            'edges': edges
        }

    def cleanup(self):
        """Clean up plugin resources."""
        self.save_map()
        logger.info("Network Mapper cleaned up")
        self.enabled = False
