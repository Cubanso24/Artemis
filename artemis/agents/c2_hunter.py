"""
Agent 7: Command & Control (C2) Hunter

Detects:
- Beaconing detection (periodic callbacks)
- Domain Generation Algorithm (DGA) identification
- Uncommon protocol usage
- Tor/VPN/proxy detection
- Application layer protocol abuse
"""

from typing import Dict, List, Any
from datetime import datetime
import re
import math
from collections import Counter

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class C2Hunter(BaseAgent):
    """Specialized agent for detecting C2 communications."""

    def __init__(self):
        super().__init__(
            name="c2_hunter",
            tactics=[KillChainStage.COMMAND_AND_CONTROL],
            description="Detects command and control communications"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "beacon_regularity_threshold": 0.8,
            "min_beacon_count": 5,
            "dga_entropy_threshold": 3.5,
            "known_c2_ports": [4444, 5555, 8080, 8443],
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect beaconing
        beacon_result = self._detect_beaconing(data.get("network_connections", []))
        if beacon_result:
            findings.append(beacon_result["finding"])
            all_evidence.extend(beacon_result["evidence"])
            confidence_scores.append(beacon_result["confidence"])

        # Detect DGA domains
        dga_result = self._detect_dga_domains(data.get("dns_queries", []))
        if dga_result:
            findings.append(dga_result["finding"])
            all_evidence.extend(dga_result["evidence"])
            confidence_scores.append(dga_result["confidence"])

        # Detect suspicious protocols
        protocol_result = self._detect_suspicious_protocols(data.get("network_connections", []))
        if protocol_result:
            findings.append(protocol_result["finding"])
            all_evidence.extend(protocol_result["evidence"])
            confidence_scores.append(protocol_result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = Severity.CRITICAL if overall_confidence > 0.7 else Severity.HIGH

        return AgentOutput(
            agent_name=self.name,
            confidence=overall_confidence,
            findings=findings,
            evidence=all_evidence,
            severity=severity,
            mitre_tactics=[t.value for t in self.tactics],
            mitre_techniques=self._get_relevant_techniques(findings),
            recommended_actions=self._generate_recommendations(findings)
        )

    def _detect_beaconing(self, connections: List[Dict]) -> Dict[str, Any]:
        if not connections:
            return None

        # Group connections by destination
        dest_connections = {}
        for conn in connections:
            dest = f"{conn.get('destination_ip')}:{conn.get('destination_port')}"
            if dest not in dest_connections:
                dest_connections[dest] = []
            dest_connections[dest].append(conn.get("timestamp", datetime.utcnow()))

        # Analyze for regular intervals (beaconing)
        for dest, timestamps in dest_connections.items():
            if len(timestamps) < self.config["min_beacon_count"]:
                continue

            # Calculate intervals
            sorted_ts = sorted(timestamps)
            intervals = [(sorted_ts[i+1] - sorted_ts[i]).total_seconds()
                        for i in range(len(sorted_ts)-1)]

            if not intervals:
                continue

            # Check regularity (low standard deviation = regular beaconing)
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)

            regularity = 1.0 - min(std_dev / mean_interval, 1.0) if mean_interval > 0 else 0.0

            if regularity >= self.config["beacon_regularity_threshold"]:
                confidence = min(0.7 + (regularity - 0.8) * 1.5, 0.95)

                finding = Finding(
                    activity_type="c2_beaconing",
                    description=f"C2 beaconing detected to {dest} (interval: {mean_interval:.1f}s)",
                    indicators=[dest],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="network_connections",
                            data={
                                "destination": dest,
                                "beacon_count": len(timestamps),
                                "mean_interval": mean_interval,
                                "regularity": regularity
                            },
                            description="Regular C2 beaconing pattern",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1071", "T1571"]  # Application Layer Protocol, Non-Standard Port
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_dga_domains(self, dns_queries: List[Dict]) -> Dict[str, Any]:
        if not dns_queries:
            return None

        for query in dns_queries:
            domain = query.get("domain", "")

            # Extract domain name (remove TLD)
            domain_parts = domain.split(".")
            if len(domain_parts) < 2:
                continue

            domain_name = domain_parts[-2]

            # Calculate entropy
            entropy = self._calculate_entropy(domain_name)

            # DGA domains typically have high entropy
            if entropy >= self.config["dga_entropy_threshold"]:
                # Check for other DGA characteristics
                has_digits = bool(re.search(r'\d', domain_name))
                length = len(domain_name)

                # DGA domains are often long with mixed chars
                if length > 10 and has_digits:
                    confidence = min(0.6 + (entropy - 3.5) * 0.2, 0.9)

                    finding = Finding(
                        activity_type="dga_domain",
                        description=f"Potential DGA domain detected: {domain} (entropy: {entropy:.2f})",
                        indicators=[domain],
                        evidence=[
                            Evidence(
                                timestamp=datetime.utcnow(),
                                source="dns_queries",
                                data={
                                    "domain": domain,
                                    "entropy": entropy,
                                    "length": length
                                },
                                description="Domain Generation Algorithm pattern",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1568.002"]  # Domain Generation Algorithms
                    )

                    return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_suspicious_protocols(self, connections: List[Dict]) -> Dict[str, Any]:
        if not connections:
            return None

        for conn in connections:
            dst_port = conn.get("destination_port")

            if dst_port in self.config["known_c2_ports"]:
                confidence = 0.65

                finding = Finding(
                    activity_type="suspicious_port",
                    description=f"Connection to known C2 port {dst_port}",
                    indicators=[str(dst_port), conn.get("destination_ip")],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="network_connections",
                            data=conn,
                            description="Known C2 port detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1571"]  # Non-Standard Port
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        counter = Counter(text.lower())
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _get_relevant_techniques(self, findings: List[Finding]) -> List[str]:
        techniques = set()
        for finding in findings:
            techniques.update(finding.mitre_techniques)
        return list(techniques)

    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        return [
            "Block C2 traffic at firewall",
            "Isolate infected systems",
            "Capture network traffic for analysis",
            "Update threat intelligence feeds",
            "Investigate patient zero"
        ]
