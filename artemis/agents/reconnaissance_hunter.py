"""
Agent 1: Reconnaissance & Discovery Hunter

Detects:
- Network scanning (port sweeps, host enumeration)
- Active Directory enumeration
- Cloud resource discovery
- DNS query patterns indicating reconnaissance
- LDAP queries for domain mapping
- Service discovery attempts
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
import re

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage, MITREAttack


class ReconnaissanceHunter(BaseAgent):
    """
    Specialized agent for detecting reconnaissance and discovery activities.

    Focuses on MITRE ATT&CK Tactics:
    - TA0043 (Reconnaissance)
    - TA0007 (Discovery)
    """

    def __init__(self):
        super().__init__(
            name="reconnaissance_hunter",
            tactics=[KillChainStage.RECONNAISSANCE, KillChainStage.DISCOVERY],
            description="Detects network scanning, enumeration, and discovery activities"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        """Default configuration for reconnaissance detection."""
        return {
            # Port scan thresholds
            "port_scan_threshold": 50,  # ports per minute
            "host_scan_threshold": 20,  # hosts per minute
            "aggressive_scan_threshold": 100,  # very fast scanning

            # DNS query thresholds
            "dns_query_threshold": 100,  # queries per minute
            "dns_nxdomain_ratio": 0.3,  # ratio of failed lookups

            # AD enumeration
            "ldap_query_threshold": 50,  # LDAP queries per session
            "ad_object_enum_threshold": 100,  # AD objects queried

            # Time window for pattern detection (seconds)
            "time_window": 300,  # 5 minutes

            # Confidence scoring weights
            "weights": {
                "volume": 0.3,
                "velocity": 0.25,
                "pattern": 0.25,
                "timing": 0.2
            }
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        """
        Analyze data for reconnaissance activities.

        Expected data format:
        {
            "network_connections": [...],
            "dns_queries": [...],
            "ldap_queries": [...],
            "service_queries": [...],
            "cloud_api_calls": [...]
        }
        """
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect port scanning
        port_scan_result = self._detect_port_scanning(data.get("network_connections", []))
        if port_scan_result:
            findings.append(port_scan_result["finding"])
            all_evidence.extend(port_scan_result["evidence"])
            confidence_scores.append(port_scan_result["confidence"])

        # Detect DNS reconnaissance
        dns_recon_result = self._detect_dns_reconnaissance(data.get("dns_queries", []))
        if dns_recon_result:
            findings.append(dns_recon_result["finding"])
            all_evidence.extend(dns_recon_result["evidence"])
            confidence_scores.append(dns_recon_result["confidence"])

        # Detect AD enumeration
        ad_enum_result = self._detect_ad_enumeration(data.get("ldap_queries", []))
        if ad_enum_result:
            findings.append(ad_enum_result["finding"])
            all_evidence.extend(ad_enum_result["evidence"])
            confidence_scores.append(ad_enum_result["confidence"])

        # Detect cloud resource discovery
        cloud_disco_result = self._detect_cloud_discovery(data.get("cloud_api_calls", []))
        if cloud_disco_result:
            findings.append(cloud_disco_result["finding"])
            all_evidence.extend(cloud_disco_result["evidence"])
            confidence_scores.append(cloud_disco_result["confidence"])

        # Calculate overall confidence
        overall_confidence = max(confidence_scores) if confidence_scores else 0.0

        # Determine severity
        severity = self._determine_severity(overall_confidence, findings)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, context)

        return AgentOutput(
            agent_name=self.name,
            confidence=overall_confidence,
            findings=findings,
            evidence=all_evidence,
            severity=severity,
            mitre_tactics=[t.value for t in self.tactics],
            mitre_techniques=self._get_relevant_techniques(findings),
            recommended_actions=recommendations,
            metadata={
                "detection_count": len(findings),
                "context": context.get_context_summary()
            }
        )

    def _detect_port_scanning(self, connections: List[Dict]) -> Dict[str, Any]:
        """Detect port scanning patterns."""
        if not connections:
            return None

        # Analyze connection patterns
        source_ips = {}
        for conn in connections:
            src_ip = conn.get("source_ip")
            dst_port = conn.get("destination_port")
            timestamp = conn.get("timestamp", datetime.utcnow())

            if src_ip not in source_ips:
                source_ips[src_ip] = {
                    "ports": set(),
                    "hosts": set(),
                    "timestamps": [],
                    "connections": []
                }

            source_ips[src_ip]["ports"].add(dst_port)
            source_ips[src_ip]["hosts"].add(conn.get("destination_ip"))
            source_ips[src_ip]["timestamps"].append(timestamp)
            source_ips[src_ip]["connections"].append(conn)

        # Identify scanners
        for src_ip, data in source_ips.items():
            port_count = len(data["ports"])
            host_count = len(data["hosts"])

            # Calculate velocity (ports/hosts per minute)
            if len(data["timestamps"]) >= 2:
                time_span = (max(data["timestamps"]) - min(data["timestamps"])).total_seconds() / 60
                if time_span > 0:
                    ports_per_min = port_count / time_span
                    hosts_per_min = host_count / time_span

                    # Check thresholds
                    if ports_per_min > self.config["port_scan_threshold"] or \
                       hosts_per_min > self.config["host_scan_threshold"]:

                        # Determine scan type
                        scan_type = self._classify_scan_type(port_count, host_count, ports_per_min)

                        confidence = self._calculate_scan_confidence(
                            ports_per_min,
                            hosts_per_min,
                            port_count,
                            host_count
                        )

                        finding = Finding(
                            activity_type="port_scanning",
                            description=f"{scan_type} detected from {src_ip}: {port_count} ports, {host_count} hosts",
                            indicators=[src_ip, f"ports_scanned:{port_count}", f"hosts_scanned:{host_count}"],
                            evidence=[
                                Evidence(
                                    timestamp=datetime.utcnow(),
                                    source="network_connections",
                                    data={
                                        "source_ip": src_ip,
                                        "port_count": port_count,
                                        "host_count": host_count,
                                        "ports_per_min": ports_per_min,
                                        "scan_type": scan_type
                                    },
                                    description=f"Detected {scan_type} from {src_ip}",
                                    confidence_contribution=confidence
                                )
                            ],
                            mitre_techniques=["T1595", "T1046"]  # Active Scanning, Network Service Discovery
                        )

                        return {
                            "finding": finding,
                            "evidence": finding.evidence,
                            "confidence": confidence
                        }

        return None

    def _detect_dns_reconnaissance(self, dns_queries: List[Dict]) -> Dict[str, Any]:
        """Detect DNS-based reconnaissance."""
        if not dns_queries:
            return None

        # Group queries by source
        source_queries = {}
        for query in dns_queries:
            src = query.get("source_ip")
            if src not in source_queries:
                source_queries[src] = {
                    "queries": [],
                    "domains": set(),
                    "nxdomain": 0,
                    "total": 0
                }

            source_queries[src]["queries"].append(query)
            source_queries[src]["domains"].add(query.get("domain", ""))
            source_queries[src]["total"] += 1

            if query.get("response_code") == "NXDOMAIN":
                source_queries[src]["nxdomain"] += 1

        # Analyze patterns
        for src, data in source_queries.items():
            query_count = data["total"]
            unique_domains = len(data["domains"])
            nxdomain_ratio = data["nxdomain"] / query_count if query_count > 0 else 0

            # High volume or high NXDOMAIN ratio indicates reconnaissance
            if query_count > self.config["dns_query_threshold"] or \
               nxdomain_ratio > self.config["dns_nxdomain_ratio"]:

                confidence = min(
                    (query_count / self.config["dns_query_threshold"]) * 0.5 +
                    (nxdomain_ratio / self.config["dns_nxdomain_ratio"]) * 0.5,
                    1.0
                )

                finding = Finding(
                    activity_type="dns_reconnaissance",
                    description=f"DNS reconnaissance from {src}: {query_count} queries, {nxdomain_ratio:.1%} NXDOMAIN",
                    indicators=[src, f"dns_queries:{query_count}", f"nxdomain_ratio:{nxdomain_ratio:.2f}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="dns_queries",
                            data={
                                "source_ip": src,
                                "query_count": query_count,
                                "unique_domains": unique_domains,
                                "nxdomain_ratio": nxdomain_ratio
                            },
                            description=f"Unusual DNS query pattern from {src}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1595.002"]  # Active Scanning: Vulnerability Scanning
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_ad_enumeration(self, ldap_queries: List[Dict]) -> Dict[str, Any]:
        """Detect Active Directory enumeration."""
        if not ldap_queries:
            return None

        # Group by source account
        account_queries = {}
        for query in ldap_queries:
            account = query.get("account")
            if account not in account_queries:
                account_queries[account] = {
                    "queries": [],
                    "objects_queried": set(),
                    "query_types": set()
                }

            account_queries[account]["queries"].append(query)
            account_queries[account]["objects_queried"].add(query.get("object_dn", ""))
            account_queries[account]["query_types"].add(query.get("query_type", ""))

        # Analyze for enumeration
        for account, data in account_queries.items():
            object_count = len(data["objects_queried"])
            query_count = len(data["queries"])

            if object_count > self.config["ad_object_enum_threshold"] or \
               query_count > self.config["ldap_query_threshold"]:

                confidence = min(object_count / self.config["ad_object_enum_threshold"], 1.0)

                finding = Finding(
                    activity_type="ad_enumeration",
                    description=f"Active Directory enumeration by {account}: {object_count} objects queried",
                    indicators=[account, f"ad_objects:{object_count}", f"ldap_queries:{query_count}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="ldap_queries",
                            data={
                                "account": account,
                                "object_count": object_count,
                                "query_count": query_count,
                                "query_types": list(data["query_types"])
                            },
                            description=f"Extensive AD enumeration by {account}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1087", "T1069"]  # Account Discovery, Permission Groups Discovery
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_cloud_discovery(self, api_calls: List[Dict]) -> Dict[str, Any]:
        """Detect cloud resource discovery attempts."""
        if not api_calls:
            return None

        # Discovery API patterns
        discovery_apis = [
            "List", "Describe", "Get", "Enumerate",
            "ec2:Describe", "s3:List", "iam:List", "lambda:List"
        ]

        # Group by account/role
        account_calls = {}
        for call in api_calls:
            account = call.get("account_id")
            api_name = call.get("api_name", "")

            # Check if it's a discovery API
            if any(pattern in api_name for pattern in discovery_apis):
                if account not in account_calls:
                    account_calls[account] = {
                        "calls": [],
                        "api_types": set(),
                        "resources": set()
                    }

                account_calls[account]["calls"].append(call)
                account_calls[account]["api_types"].add(api_name)
                account_calls[account]["resources"].add(call.get("resource_type", ""))

        # Analyze for suspicious discovery
        for account, data in account_calls.items():
            call_count = len(data["calls"])
            api_diversity = len(data["api_types"])

            # High volume or diverse discovery indicates reconnaissance
            if call_count > 20 and api_diversity > 5:
                confidence = min(call_count / 100.0, 0.9)

                finding = Finding(
                    activity_type="cloud_discovery",
                    description=f"Cloud resource discovery by {account}: {call_count} API calls, {api_diversity} different APIs",
                    indicators=[account, f"api_calls:{call_count}", f"api_diversity:{api_diversity}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="cloud_api_calls",
                            data={
                                "account": account,
                                "call_count": call_count,
                                "api_diversity": api_diversity,
                                "apis": list(data["api_types"])[:10]  # First 10
                            },
                            description=f"Extensive cloud resource enumeration by {account}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1580", "T1526"]  # Cloud Infrastructure Discovery, Cloud Service Discovery
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _classify_scan_type(self, port_count: int, host_count: int, velocity: float) -> str:
        """Classify the type of scanning detected."""
        if velocity > self.config["aggressive_scan_threshold"]:
            return "Aggressive port scan"
        elif host_count > port_count:
            return "Host sweep"
        elif port_count > host_count * 10:
            return "Vertical port scan"
        else:
            return "Network scan"

    def _calculate_scan_confidence(
        self,
        ports_per_min: float,
        hosts_per_min: float,
        total_ports: int,
        total_hosts: int
    ) -> float:
        """Calculate confidence score for port scanning detection."""
        # Weight different factors
        velocity_score = min(
            (ports_per_min / self.config["port_scan_threshold"]) * 0.5 +
            (hosts_per_min / self.config["host_scan_threshold"]) * 0.5,
            1.0
        )

        volume_score = min(
            (total_ports / 100.0) * 0.5 + (total_hosts / 50.0) * 0.5,
            1.0
        )

        return min((velocity_score * 0.6 + volume_score * 0.4), 1.0)

    def _determine_severity(self, confidence: float, findings: List[Finding]) -> Severity:
        """Determine overall severity based on confidence and findings."""
        if confidence >= 0.8 or len(findings) >= 3:
            return Severity.HIGH
        elif confidence >= 0.6 or len(findings) >= 2:
            return Severity.MEDIUM
        elif confidence >= 0.4:
            return Severity.LOW
        else:
            return Severity.LOW

    def _get_relevant_techniques(self, findings: List[Finding]) -> List[str]:
        """Extract all MITRE techniques from findings."""
        techniques = set()
        for finding in findings:
            techniques.update(finding.mitre_techniques)
        return list(techniques)

    def _generate_recommendations(self, findings: List[Finding], context: NetworkState) -> List[str]:
        """Generate recommended actions based on findings."""
        if not findings:
            return []

        recommendations = []

        # Check for specific activity types
        activity_types = {f.activity_type for f in findings}

        if "port_scanning" in activity_types:
            recommendations.append("Block source IP at firewall")
            recommendations.append("Review network segmentation controls")
            recommendations.append("Enable IDS/IPS signatures for port scanning")

        if "dns_reconnaissance" in activity_types:
            recommendations.append("Investigate DNS query patterns")
            recommendations.append("Review DNS sinkhole configuration")
            recommendations.append("Check for data exfiltration via DNS tunneling")

        if "ad_enumeration" in activity_types:
            recommendations.append("Review account permissions")
            recommendations.append("Enable advanced AD auditing")
            recommendations.append("Investigate account for compromise")

        if "cloud_discovery" in activity_types:
            recommendations.append("Review cloud IAM permissions")
            recommendations.append("Enable CloudTrail/Azure Activity Log analysis")
            recommendations.append("Check for compromised credentials")

        # General recommendations
        recommendations.append("Correlate with other security events")
        recommendations.append("Check threat intelligence for source IPs")

        return recommendations
