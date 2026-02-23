"""
Agent: Reconnaissance & Discovery Hunter

Network-observable reconnaissance using Zeek conn/dns data:
- Port scanning (vertical scan, host sweep, aggressive scan)
- DNS reconnaissance (high NXDOMAIN ratio, zone transfer attempts)
- Service enumeration (rapid probing of multiple services)
- Network mapping (ICMP sweeps, ARP scans via connection patterns)
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import defaultdict

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class ReconnaissanceHunter(BaseAgent):
    """Detects reconnaissance and network discovery using Zeek telemetry."""

    def __init__(self):
        super().__init__(
            name="reconnaissance_hunter",
            tactics=[KillChainStage.RECONNAISSANCE, KillChainStage.DISCOVERY],
            description="Detects network scanning, enumeration, and discovery activities"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "port_scan_unique_ports": 25,
            "host_sweep_unique_hosts": 15,
            "aggressive_scan_ports_per_min": 100,
            "dns_query_volume_threshold": 200,
            "dns_nxdomain_ratio_threshold": 0.3,
            "service_enum_threshold": 10,
            "rejected_conn_ratio": 0.6,
            "time_window_seconds": 300,
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        connections = data.get("network_connections", [])
        dns_queries = data.get("dns_queries", [])

        # 1. Port scanning detection
        for result in self._detect_port_scanning(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 2. DNS reconnaissance
        for result in self._detect_dns_reconnaissance(dns_queries):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 3. Service enumeration via connection state analysis
        for result in self._detect_service_enumeration(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = self._determine_severity(overall_confidence, findings)

        return AgentOutput(
            agent_name=self.name,
            confidence=overall_confidence,
            findings=findings,
            evidence=all_evidence,
            severity=severity,
            mitre_tactics=[t.value for t in self.tactics],
            mitre_techniques=self._collect_techniques(findings),
            recommended_actions=self._generate_recommendations(findings),
        )

    # ------------------------------------------------------------------
    # Detection 1: Port scanning
    # ------------------------------------------------------------------

    def _detect_port_scanning(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect port scanning via unique port/host counts per source IP."""
        if not connections:
            return []

        # Aggregate per source IP
        sources: Dict[str, Dict] = defaultdict(lambda: {
            "ports": set(),
            "hosts": set(),
            "timestamps": [],
            "rejected": 0,
            "total": 0,
        })
        for conn in connections:
            src = conn.get("source_ip")
            if not src:
                continue
            info = sources[src]
            info["ports"].add(conn.get("destination_port"))
            info["hosts"].add(conn.get("destination_ip"))
            info["total"] += 1
            ts = self._parse_timestamp(conn.get("timestamp"))
            if ts:
                info["timestamps"].append(ts)
            # Zeek conn_state: REJ = rejected, S0 = SYN with no reply
            state = conn.get("conn_state", "")
            if state in ("REJ", "S0", "RSTOS0", "RSTRH"):
                info["rejected"] += 1

        port_thresh = self.config["port_scan_unique_ports"]
        host_thresh = self.config["host_sweep_unique_hosts"]

        results = []
        for src_ip, info in sources.items():
            port_count = len(info["ports"])
            host_count = len(info["hosts"])

            if port_count < port_thresh and host_count < host_thresh:
                continue

            # Calculate velocity
            ports_per_min = 0.0
            hosts_per_min = 0.0
            if len(info["timestamps"]) >= 2:
                span = (max(info["timestamps"]) - min(info["timestamps"])).total_seconds() / 60
                if span > 0:
                    ports_per_min = port_count / span
                    hosts_per_min = host_count / span

            # Classify scan type
            if ports_per_min > self.config["aggressive_scan_ports_per_min"]:
                scan_type = "Aggressive scan"
            elif host_count > port_count:
                scan_type = "Host sweep"
            elif port_count > host_count * 5:
                scan_type = "Vertical port scan"
            else:
                scan_type = "Network scan"

            # Rejection ratio increases confidence
            reject_ratio = info["rejected"] / info["total"] if info["total"] > 0 else 0
            velocity_factor = min(ports_per_min / 100, 0.15) if ports_per_min > 0 else 0
            volume_factor = min(port_count / 200, 0.15)
            reject_factor = reject_ratio * 0.15

            confidence = min(0.55 + velocity_factor + volume_factor + reject_factor, 0.95)

            finding = Finding(
                activity_type="port_scanning",
                description=(
                    f"{scan_type} from {src_ip}: {port_count} ports, "
                    f"{host_count} hosts, {reject_ratio:.0%} rejected "
                    f"({ports_per_min:.0f} ports/min)"
                ),
                indicators=[src_ip, f"ports:{port_count}", f"hosts:{host_count}"],
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": src_ip,
                        "unique_ports": port_count,
                        "unique_hosts": host_count,
                        "ports_per_min": round(ports_per_min, 1),
                        "hosts_per_min": round(hosts_per_min, 1),
                        "rejection_ratio": round(reject_ratio, 3),
                        "total_connections": info["total"],
                        "scan_type": scan_type,
                    },
                    description=f"{scan_type} detected from {src_ip}",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1595", "T1046"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 2: DNS reconnaissance
    # ------------------------------------------------------------------

    def _detect_dns_reconnaissance(self, dns_queries: List[Dict]) -> List[Dict[str, Any]]:
        """Detect DNS-based recon: high query volume, high NXDOMAIN ratio."""
        if not dns_queries:
            return []

        # Group by source IP
        sources: Dict[str, Dict] = defaultdict(lambda: {
            "total": 0, "nxdomain": 0, "domains": set(),
        })
        for q in dns_queries:
            src = q.get("source_ip")
            if not src:
                continue
            info = sources[src]
            info["total"] += 1
            info["domains"].add(q.get("domain", ""))
            if q.get("response_code") == "NXDOMAIN":
                info["nxdomain"] += 1

        vol_threshold = self.config["dns_query_volume_threshold"]
        nx_threshold = self.config["dns_nxdomain_ratio_threshold"]

        results = []
        for src_ip, info in sources.items():
            total = info["total"]
            nx_ratio = info["nxdomain"] / total if total > 0 else 0
            unique = len(info["domains"])

            if total < vol_threshold and nx_ratio < nx_threshold:
                continue

            # Scale confidence
            vol_factor = min(total / vol_threshold, 1.0) * 0.3
            nx_factor = min(nx_ratio / nx_threshold, 1.0) * 0.4
            diversity_factor = min(unique / 100, 0.2)
            confidence = min(0.40 + vol_factor + nx_factor + diversity_factor, 0.93)

            finding = Finding(
                activity_type="dns_reconnaissance",
                description=(
                    f"DNS recon from {src_ip}: {total} queries, "
                    f"{nx_ratio:.0%} NXDOMAIN, {unique} unique domains"
                ),
                indicators=[src_ip, f"dns_queries:{total}", f"nxdomain_ratio:{nx_ratio:.2f}"],
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="dns_queries",
                    data={
                        "source_ip": src_ip,
                        "total_queries": total,
                        "nxdomain_count": info["nxdomain"],
                        "nxdomain_ratio": round(nx_ratio, 3),
                        "unique_domains": unique,
                    },
                    description=f"Unusual DNS query pattern from {src_ip}",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1595.002"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 3: Service enumeration via failed connections
    # ------------------------------------------------------------------

    def _detect_service_enumeration(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect service enumeration: single source probing many ports on one host with rejects."""
        if not connections:
            return []

        reject_states = {"REJ", "S0", "RSTOS0", "RSTRH"}
        enum_threshold = self.config["service_enum_threshold"]
        reject_ratio_threshold = self.config["rejected_conn_ratio"]

        # Group by (source, destination) pair
        pairs: Dict[str, Dict] = defaultdict(lambda: {
            "ports": set(), "rejected": 0, "total": 0, "src": "", "dst": "",
        })
        for conn in connections:
            src = conn.get("source_ip")
            dst = conn.get("destination_ip")
            if not (src and dst):
                continue
            key = f"{src}|{dst}"
            info = pairs[key]
            info["src"] = src
            info["dst"] = dst
            info["ports"].add(conn.get("destination_port"))
            info["total"] += 1
            if conn.get("conn_state", "") in reject_states:
                info["rejected"] += 1

        results = []
        for key, info in pairs.items():
            port_count = len(info["ports"])
            if port_count < enum_threshold:
                continue
            reject_ratio = info["rejected"] / info["total"] if info["total"] > 0 else 0
            if reject_ratio < reject_ratio_threshold:
                continue

            confidence = min(0.55 + port_count * 0.01 + reject_ratio * 0.15, 0.90)

            finding = Finding(
                activity_type="service_enumeration",
                description=(
                    f"Service enumeration: {info['src']} probed {port_count} ports "
                    f"on {info['dst']} ({reject_ratio:.0%} rejected)"
                ),
                indicators=[info["src"], info["dst"], f"ports_probed:{port_count}"],
                affected_assets=[info["dst"]],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": info["src"],
                        "target_ip": info["dst"],
                        "ports_probed": port_count,
                        "rejection_ratio": round(reject_ratio, 3),
                        "total_connections": info["total"],
                    },
                    description=f"Service enumeration against {info['dst']}",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1046"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_severity(confidence: float, findings: List[Finding]) -> Severity:
        if confidence >= 0.8 or len(findings) >= 3:
            return Severity.HIGH
        elif confidence >= 0.6 or len(findings) >= 2:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _collect_techniques(findings: List[Finding]) -> List[str]:
        techniques: set = set()
        for f in findings:
            techniques.update(f.mitre_techniques)
        return sorted(techniques)

    @staticmethod
    def _generate_recommendations(findings: List[Finding]) -> List[str]:
        if not findings:
            return []
        types = {f.activity_type for f in findings}
        recs = []
        if "port_scanning" in types:
            recs.append("Block scanning source at firewall if external")
            recs.append("Review network segmentation — limit internal scan surface")
        if "dns_reconnaissance" in types:
            recs.append("Investigate DNS query patterns for data exfiltration or recon")
            recs.append("Consider DNS sinkholing for high-NXDOMAIN sources")
        if "service_enumeration" in types:
            recs.append("Harden exposed services and restrict unnecessary ports")
        recs.append("Check threat intelligence for source IPs")
        return recs
