"""
PCAP analyzer for extracting threat hunting features from packet captures.

Uses scapy for deep packet inspection to extract IOCs and behavioral patterns.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict, Counter
import struct

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from artemis.utils.logging_config import ArtemisLogger


class PCAPAnalyzer:
    """
    Analyzes PCAP files to extract threat hunting features.

    Extracts:
    - Network connections and flow statistics
    - DNS queries and responses
    - HTTP requests and suspicious patterns
    - Beaconing behavior
    - Port scanning indicators
    - Data exfiltration patterns
    """

    def __init__(self):
        """Initialize PCAP analyzer."""
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy is not installed. "
                "Install with: pip install scapy"
            )

        self.logger = ArtemisLogger.setup_logger("artemis.integrations.pcap_analyzer")

    def analyze_pcap(
        self,
        pcap_path: str,
        max_packets: Optional[int] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Comprehensive PCAP analysis.

        Args:
            pcap_path: Path to PCAP file
            max_packets: Maximum packets to analyze (None = all)

        Returns:
            Dictionary with extracted features for Artemis agents
        """
        self.logger.info(f"Analyzing PCAP: {pcap_path}")

        try:
            packets = rdpcap(pcap_path)

            if max_packets:
                packets = packets[:max_packets]

            self.logger.info(f"Loaded {len(packets)} packets")

        except Exception as e:
            self.logger.error(f"Failed to read PCAP: {e}")
            return {}

        # Extract various features
        analysis = {
            "network_connections": self._extract_connections(packets),
            "dns_queries": self._extract_dns(packets),
            "http_requests": self._extract_http(packets),
            "port_scan_indicators": self._detect_port_scans(packets),
            "beaconing_candidates": self._detect_beaconing(packets),
            "data_transfers": self._analyze_data_transfers(packets),
            "suspicious_protocols": self._detect_suspicious_protocols(packets)
        }

        total_features = sum(len(v) for v in analysis.values())
        self.logger.info(f"Extracted {total_features} features from PCAP")

        return analysis

    def _extract_connections(self, packets) -> List[Dict[str, Any]]:
        """
        Extract network connection information.

        Returns:
            List of connection dictionaries
        """
        connections = {}

        for pkt in packets:
            if IP not in pkt:
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Get port information
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                protocol = "tcp"
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                protocol = "udp"
            else:
                src_port = dst_port = 0
                protocol = "other"

            # Create connection tuple
            conn_tuple = (src_ip, dst_ip, dst_port, protocol)

            if conn_tuple not in connections:
                connections[conn_tuple] = {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "protocol": protocol,
                    "packet_count": 0,
                    "bytes_transferred": 0,
                    "first_seen": pkt.time,
                    "last_seen": pkt.time
                }

            # Update statistics
            connections[conn_tuple]["packet_count"] += 1
            connections[conn_tuple]["bytes_transferred"] += len(pkt)
            connections[conn_tuple]["last_seen"] = pkt.time

        # Convert to list with timestamps
        conn_list = []
        for conn in connections.values():
            conn["timestamp"] = datetime.fromtimestamp(conn["first_seen"])
            conn["duration"] = conn["last_seen"] - conn["first_seen"]
            conn_list.append(conn)

        return conn_list

    def _extract_dns(self, packets) -> List[Dict[str, Any]]:
        """
        Extract DNS queries and responses.

        Returns:
            List of DNS query dictionaries
        """
        dns_queries = []

        for pkt in packets:
            if DNS in pkt:
                if pkt[DNS].qr == 0:  # Query
                    query = {
                        "source_ip": pkt[IP].src if IP in pkt else None,
                        "domain": pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.'),
                        "query_type": pkt[DNS].qd.qtype,
                        "timestamp": datetime.fromtimestamp(pkt.time)
                    }
                    dns_queries.append(query)

                elif pkt[DNS].qr == 1:  # Response
                    # Match with query if needed
                    response_code = pkt[DNS].rcode
                    if response_code == 3:
                        # NXDOMAIN
                        if dns_queries:
                            dns_queries[-1]["response_code"] = "NXDOMAIN"

        return dns_queries

    def _extract_http(self, packets) -> List[Dict[str, Any]]:
        """
        Extract HTTP requests.

        Returns:
            List of HTTP request dictionaries
        """
        http_requests = []

        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                payload = pkt[Raw].load

                try:
                    # Check for HTTP request
                    if payload.startswith(b'GET ') or payload.startswith(b'POST '):
                        lines = payload.decode('utf-8', errors='ignore').split('\r\n')
                        request_line = lines[0]
                        method, uri, _ = request_line.split(' ', 2)

                        # Extract headers
                        headers = {}
                        for line in lines[1:]:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                headers[key.strip()] = value.strip()

                        http_requests.append({
                            "source_ip": pkt[IP].src if IP in pkt else None,
                            "destination_ip": pkt[IP].dst if IP in pkt else None,
                            "method": method,
                            "uri": uri,
                            "host": headers.get('Host', ''),
                            "user_agent": headers.get('User-Agent', ''),
                            "timestamp": datetime.fromtimestamp(pkt.time)
                        })
                except:
                    continue

        return http_requests

    def _detect_port_scans(self, packets) -> List[Dict[str, Any]]:
        """
        Detect port scanning patterns.

        Returns:
            List of potential port scan indicators
        """
        # Track SYN packets per source IP
        syn_packets = defaultdict(set)

        for pkt in packets:
            if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN flag
                src_ip = pkt[IP].src
                dst_port = pkt[TCP].dport

                syn_packets[src_ip].add(dst_port)

        # Identify scanners
        port_scans = []
        for src_ip, ports in syn_packets.items():
            if len(ports) >= 20:  # Threshold for port scan
                port_scans.append({
                    "source_ip": src_ip,
                    "ports_scanned": len(ports),
                    "scan_type": "SYN scan",
                    "ports": list(ports)[:50]  # Sample of ports
                })

        return port_scans

    def _detect_beaconing(self, packets) -> List[Dict[str, Any]]:
        """
        Detect potential C2 beaconing patterns.

        Returns:
            List of beaconing candidates
        """
        # Group packets by destination
        connections = defaultdict(list)

        for pkt in packets:
            if IP in pkt and TCP in pkt:
                dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
                connections[dst].append(pkt.time)

        # Analyze intervals for regularity
        beaconing_candidates = []

        for dst, timestamps in connections.items():
            if len(timestamps) < 5:
                continue

            # Calculate intervals
            sorted_times = sorted(timestamps)
            intervals = [
                sorted_times[i+1] - sorted_times[i]
                for i in range(len(sorted_times)-1)
            ]

            if not intervals:
                continue

            # Calculate coefficient of variation
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            cv = std_dev / mean_interval

            # Low CV indicates regular beaconing
            if cv < 0.3 and len(timestamps) >= 10:
                ip, port = dst.split(':')
                beaconing_candidates.append({
                    "destination_ip": ip,
                    "destination_port": int(port),
                    "beacon_count": len(timestamps),
                    "mean_interval": mean_interval,
                    "regularity": 1.0 - cv,
                    "confidence": min(0.5 + (1.0 - cv) * 0.5, 0.95)
                })

        return beaconing_candidates

    def _analyze_data_transfers(self, packets) -> List[Dict[str, Any]]:
        """
        Analyze data transfer patterns for potential exfiltration.

        Returns:
            List of large data transfers
        """
        # Track bytes transferred per connection
        transfers = defaultdict(lambda: {"bytes": 0, "packets": 0, "first": None, "last": None})

        for pkt in packets:
            if IP not in pkt:
                continue

            key = (pkt[IP].src, pkt[IP].dst)
            transfers[key]["bytes"] += len(pkt)
            transfers[key]["packets"] += 1

            if transfers[key]["first"] is None:
                transfers[key]["first"] = pkt.time
            transfers[key]["last"] = pkt.time

        # Identify large transfers
        large_transfers = []
        threshold = 10 * 1024 * 1024  # 10 MB

        for (src, dst), data in transfers.items():
            if data["bytes"] >= threshold:
                large_transfers.append({
                    "source_ip": src,
                    "destination_ip": dst,
                    "bytes_transferred": data["bytes"],
                    "packet_count": data["packets"],
                    "duration": data["last"] - data["first"],
                    "timestamp": datetime.fromtimestamp(data["first"])
                })

        return large_transfers

    def _detect_suspicious_protocols(self, packets) -> List[Dict[str, Any]]:
        """
        Detect suspicious protocol usage.

        Returns:
            List of suspicious protocol indicators
        """
        suspicious = []

        # Track protocol/port mismatches
        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                dst_port = pkt[TCP].dport
                payload = pkt[Raw].load[:100]  # First 100 bytes

                # HTTP on non-standard port
                if dst_port not in [80, 443, 8080, 8443]:
                    if b'HTTP/' in payload or b'GET ' in payload:
                        suspicious.append({
                            "type": "http_on_unusual_port",
                            "source_ip": pkt[IP].src,
                            "destination_ip": pkt[IP].dst,
                            "port": dst_port,
                            "timestamp": datetime.fromtimestamp(pkt.time)
                        })

                # DNS on TCP (often used for tunneling)
                if dst_port == 53 and TCP in pkt:
                    suspicious.append({
                        "type": "dns_over_tcp",
                        "source_ip": pkt[IP].src,
                        "destination_ip": pkt[IP].dst,
                        "timestamp": datetime.fromtimestamp(pkt.time)
                    })

        return suspicious

    def extract_for_agent(
        self,
        pcap_path: str,
        agent_name: str
    ) -> Dict[str, Any]:
        """
        Extract features relevant to a specific agent.

        Args:
            pcap_path: Path to PCAP file
            agent_name: Name of Artemis agent

        Returns:
            Agent-specific feature dictionary
        """
        analysis = self.analyze_pcap(pcap_path)

        # Map features to agents
        agent_mappings = {
            "reconnaissance_hunter": ["network_connections", "dns_queries", "port_scan_indicators"],
            "c2_hunter": ["beaconing_candidates", "network_connections"],
            "collection_exfiltration_hunter": ["data_transfers"],
            "initial_access_hunter": ["http_requests"],
        }

        relevant_features = agent_mappings.get(agent_name, [])

        return {
            feature: analysis.get(feature, [])
            for feature in relevant_features
        }
