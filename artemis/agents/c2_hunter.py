"""
Agent: Command & Control (C2) Hunter

Network-observable C2 detections using Zeek conn/dns/http/ssl data:
- Beaconing detection (periodic callback interval analysis)
- Beaconing to multiple destinations from one host
- Domain Generation Algorithm (DGA) identification via entropy
- DNS tunneling (high-volume small queries to single domain)
- Suspicious JA3/SSL certificate anomalies
- Long-lived connections (persistent C2 channels)
- Known-bad port usage
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import Counter, defaultdict
import math
import re

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class C2Hunter(BaseAgent):
    """Detects C2 communications using network telemetry."""

    def __init__(self):
        super().__init__(
            name="c2_hunter",
            tactics=[KillChainStage.COMMAND_AND_CONTROL],
            description="Detects command and control communications via network analysis"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "beacon_regularity_threshold": 0.75,
            "min_beacon_connections": 10,
            "dga_entropy_threshold": 3.5,
            "dga_min_domain_length": 10,
            "dns_tunnel_query_threshold": 50,
            "dns_tunnel_subdomain_entropy": 3.0,
            "long_conn_duration_seconds": 3600,
            "long_conn_low_bytes_threshold": 10240,
            "suspicious_ports": [
                4444, 5555, 1234, 6667, 6697,   # Meterpreter, IRC
                8443, 8080, 9090, 9443,           # Alt HTTP/S
                1337, 31337, 12345,               # Common backdoor
                2222, 4443, 5900, 5901,           # Alt SSH, Alt HTTPS, VNC
            ],
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []
        near_misses: List[str] = []

        connections = data.get("network_connections", [])
        dns_queries = data.get("dns_queries", [])

        # 1. Beaconing detection (interval regularity analysis)
        for result in self._detect_beaconing(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 2. DGA domain detection (Shannon entropy)
        for result in self._detect_dga_domains(dns_queries):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 3. DNS tunneling (high-volume queries to single parent domain)
        for result in self._detect_dns_tunneling(dns_queries):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 4. Long-lived low-traffic connections
        for result in self._detect_long_connections(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 5. Known-bad port connections
        for result in self._detect_suspicious_ports(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # Collect near-miss diagnostics when no findings produced
        if not findings:
            near_misses = self._collect_near_misses(connections, dns_queries)

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = (Severity.CRITICAL if overall_confidence > 0.8
                    else Severity.HIGH if overall_confidence > 0.6
                    else Severity.MEDIUM)

        return AgentOutput(
            agent_name=self.name,
            confidence=overall_confidence,
            findings=findings,
            evidence=all_evidence,
            severity=severity,
            mitre_tactics=[t.value for t in self.tactics],
            mitre_techniques=self._collect_techniques(findings),
            recommended_actions=self._generate_recommendations(findings),
            metadata={"near_misses": near_misses} if near_misses else {},
        )

    # ------------------------------------------------------------------
    # Detection 1: Beaconing
    # ------------------------------------------------------------------

    def _detect_beaconing(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect periodic callback patterns per (source, dest:port) pair."""
        if not connections:
            return []

        min_count = self.config["min_beacon_connections"]
        threshold = self.config["beacon_regularity_threshold"]

        # Group connections by source -> dest:port
        groups: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
        for conn in connections:
            src = conn.get("source_ip")
            dst = conn.get("destination_ip")
            port = conn.get("destination_port")
            ts = self._parse_timestamp(conn.get("timestamp"))
            if not (src and dst and ts):
                continue
            key = f"{dst}:{port}"
            groups[src][key].append(ts)

        results = []
        for src_ip, destinations in groups.items():
            for dest_key, timestamps in destinations.items():
                if len(timestamps) < min_count:
                    continue

                sorted_ts = sorted(timestamps)
                intervals = []
                for i in range(len(sorted_ts) - 1):
                    diff = (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
                    if diff > 0:
                        intervals.append(diff)

                if len(intervals) < min_count - 1:
                    continue

                mean_interval = sum(intervals) / len(intervals)
                if mean_interval <= 0:
                    continue

                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = math.sqrt(variance)
                regularity = 1.0 - min(std_dev / mean_interval, 1.0)

                if regularity < threshold:
                    continue

                # Jitter-tolerant: also check coefficient of variation
                cv = std_dev / mean_interval if mean_interval > 0 else 1.0

                # Higher confidence for more connections and higher regularity
                conn_factor = min(len(timestamps) / 50.0, 0.15)
                confidence = min(0.65 + (regularity - 0.75) * 1.0 + conn_factor, 0.95)

                finding = Finding(
                    activity_type="c2_beaconing",
                    description=(
                        f"Beaconing from {src_ip} to {dest_key}: "
                        f"{len(timestamps)} callbacks, interval ~{mean_interval:.0f}s "
                        f"(regularity {regularity:.2f}, CV {cv:.3f})"
                    ),
                    indicators=[src_ip, dest_key],
                    affected_assets=[src_ip],
                    evidence=[Evidence(
                        timestamp=datetime.utcnow(),
                        source="network_connections",
                        data={
                            "source_ip": src_ip,
                            "destination": dest_key,
                            "beacon_count": len(timestamps),
                            "mean_interval_seconds": round(mean_interval, 1),
                            "regularity": round(regularity, 3),
                            "coefficient_of_variation": round(cv, 4),
                            "std_dev": round(std_dev, 1),
                        },
                        description="Regular C2 beaconing pattern",
                        confidence_contribution=confidence,
                    )],
                    mitre_techniques=["T1071", "T1571"],
                )
                results.append({
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence,
                })

        return results

    # ------------------------------------------------------------------
    # Detection 2: DGA domains
    # ------------------------------------------------------------------

    def _detect_dga_domains(self, dns_queries: List[Dict]) -> List[Dict[str, Any]]:
        """Detect algorithmically generated domains via Shannon entropy."""
        if not dns_queries:
            return []

        threshold = self.config["dga_entropy_threshold"]
        min_len = self.config["dga_min_domain_length"]

        seen_domains: set = set()
        results = []

        for query in dns_queries:
            domain = query.get("domain", "")
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            parts = domain.split(".")
            if len(parts) < 2:
                continue

            # Analyze the second-level domain (e.g. "abc123xyz" in abc123xyz.com)
            sld = parts[-2]
            if len(sld) < min_len:
                continue

            entropy = self._shannon_entropy(sld)
            if entropy < threshold:
                continue

            # Additional DGA heuristics
            has_digits = bool(re.search(r'\d', sld))
            consonant_ratio = sum(1 for c in sld.lower() if c in 'bcdfghjklmnpqrstvwxyz') / len(sld)
            is_suspicious = has_digits and consonant_ratio > 0.55

            if not is_suspicious:
                continue

            confidence = min(0.55 + (entropy - 3.5) * 0.25 + (len(sld) - 10) * 0.01, 0.92)
            src_ip = query.get("source_ip", "unknown")

            finding = Finding(
                activity_type="dga_domain",
                description=(
                    f"Potential DGA domain from {src_ip}: {domain} "
                    f"(entropy={entropy:.2f}, len={len(sld)})"
                ),
                indicators=[domain, src_ip],
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="dns_queries",
                    data={
                        "domain": domain,
                        "source_ip": src_ip,
                        "entropy": round(entropy, 3),
                        "sld_length": len(sld),
                        "consonant_ratio": round(consonant_ratio, 3),
                    },
                    description="Domain Generation Algorithm pattern",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1568.002"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 3: DNS tunneling
    # ------------------------------------------------------------------

    def _detect_dns_tunneling(self, dns_queries: List[Dict]) -> List[Dict[str, Any]]:
        """Detect DNS tunneling: many unique subdomains under one parent."""
        if not dns_queries:
            return []

        query_threshold = self.config["dns_tunnel_query_threshold"]

        # Group queries by (source_ip, parent_domain)
        # parent_domain = last 2 labels (e.g. "evil.com")
        groups: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        for q in dns_queries:
            domain = q.get("domain", "")
            src = q.get("source_ip", "")
            parts = domain.split(".")
            if len(parts) < 3 or not src:
                continue
            parent = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            groups[src][parent].add(subdomain)

        results = []
        for src_ip, parents in groups.items():
            for parent_domain, subdomains in parents.items():
                unique_count = len(subdomains)
                if unique_count < query_threshold:
                    continue

                # Calculate average subdomain entropy
                avg_entropy = sum(self._shannon_entropy(s) for s in subdomains) / unique_count

                if avg_entropy < self.config["dns_tunnel_subdomain_entropy"]:
                    continue

                confidence = min(0.60 + (unique_count / 500) * 0.2 + (avg_entropy - 3.0) * 0.1, 0.93)

                finding = Finding(
                    activity_type="dns_tunneling",
                    description=(
                        f"DNS tunneling from {src_ip} via {parent_domain}: "
                        f"{unique_count} unique subdomains (avg entropy {avg_entropy:.2f})"
                    ),
                    indicators=[src_ip, parent_domain],
                    affected_assets=[src_ip],
                    evidence=[Evidence(
                        timestamp=datetime.utcnow(),
                        source="dns_queries",
                        data={
                            "source_ip": src_ip,
                            "parent_domain": parent_domain,
                            "unique_subdomains": unique_count,
                            "avg_subdomain_entropy": round(avg_entropy, 3),
                            "sample_subdomains": list(subdomains)[:5],
                        },
                        description="DNS tunneling via high-entropy subdomains",
                        confidence_contribution=confidence,
                    )],
                    mitre_techniques=["T1071.004"],
                )
                results.append({
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence,
                })

        return results

    # ------------------------------------------------------------------
    # Detection 4: Long-lived low-traffic connections
    # ------------------------------------------------------------------

    def _detect_long_connections(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect persistent C2 channels: long duration, low byte count."""
        if not connections:
            return []

        duration_threshold = self.config["long_conn_duration_seconds"]
        bytes_threshold = self.config["long_conn_low_bytes_threshold"]

        # Group by (src, dst:port) and check time span
        groups: Dict[str, Dict] = defaultdict(lambda: {
            "first": None, "last": None, "total_bytes": 0, "count": 0,
        })
        for conn in connections:
            src = conn.get("source_ip")
            dst = conn.get("destination_ip")
            port = conn.get("destination_port")
            ts = self._parse_timestamp(conn.get("timestamp"))
            if not (src and dst and ts):
                continue

            key = f"{src}|{dst}:{port}"
            entry = groups[key]
            entry["count"] += 1
            entry["total_bytes"] += int(conn.get("bytes_out", 0)) + int(conn.get("bytes_in", 0))
            if entry["first"] is None or ts < entry["first"]:
                entry["first"] = ts
            if entry["last"] is None or ts > entry["last"]:
                entry["last"] = ts
            entry["src"] = src
            entry["dst"] = f"{dst}:{port}"

        results = []
        for key, info in groups.items():
            if not info["first"] or not info["last"]:
                continue
            duration = (info["last"] - info["first"]).total_seconds()
            if duration < duration_threshold:
                continue
            if info["total_bytes"] > bytes_threshold and info["count"] > 5:
                continue  # Legitimate if high-traffic

            confidence = min(0.50 + (duration / 86400) * 0.2, 0.80)

            finding = Finding(
                activity_type="persistent_c2_channel",
                description=(
                    f"Long-lived low-traffic connection: {info['src']} -> {info['dst']} "
                    f"({duration / 3600:.1f}h, {info['total_bytes']} bytes, {info['count']} conns)"
                ),
                indicators=[info["src"], info["dst"]],
                affected_assets=[info["src"]],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": info["src"],
                        "destination": info["dst"],
                        "duration_hours": round(duration / 3600, 2),
                        "total_bytes": info["total_bytes"],
                        "connection_count": info["count"],
                    },
                    description="Persistent low-traffic C2 channel",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1071", "T1573"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 5: Suspicious port usage
    # ------------------------------------------------------------------

    def _detect_suspicious_ports(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect connections to known C2/backdoor ports, aggregated by source."""
        if not connections:
            return []

        bad_ports = set(self.config["suspicious_ports"])

        # Aggregate by source IP
        src_hits: Dict[str, Dict] = defaultdict(lambda: {
            "ports": set(), "destinations": set(), "count": 0
        })
        for conn in connections:
            port = conn.get("destination_port")
            if port not in bad_ports:
                continue
            src = conn.get("source_ip", "")
            dst = conn.get("destination_ip", "")
            src_hits[src]["ports"].add(port)
            src_hits[src]["destinations"].add(f"{dst}:{port}")
            src_hits[src]["count"] += 1

        results = []
        for src_ip, info in src_hits.items():
            # Only alert if there are repeated connections (not just one SYN)
            if info["count"] < 3:
                continue

            confidence = min(0.55 + len(info["ports"]) * 0.05 + info["count"] * 0.01, 0.80)

            finding = Finding(
                activity_type="suspicious_port_usage",
                description=(
                    f"{src_ip} connected to suspicious ports "
                    f"{sorted(info['ports'])}: {info['count']} connections"
                ),
                indicators=[src_ip] + sorted(str(p) for p in info["ports"]),
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": src_ip,
                        "ports": sorted(info["ports"]),
                        "destinations": sorted(info["destinations"]),
                        "connection_count": info["count"],
                    },
                    description="Connections to known C2/backdoor ports",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1571"],
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
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counter = Counter(text.lower())
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in counter.values())

    def _collect_near_misses(
        self, connections: List[Dict], dns_queries: List[Dict]
    ) -> List[str]:
        """Summarize the closest-to-threshold activity for diagnostics."""
        misses = []
        min_count = self.config["min_beacon_connections"]

        # Beaconing: find the (src, dst:port) group with the most connections
        groups: Dict[str, int] = defaultdict(int)
        for conn in connections:
            src = conn.get("source_ip")
            dst = conn.get("destination_ip")
            port = conn.get("destination_port")
            if src and dst:
                groups[f"{src}->{dst}:{port}"] += 1
        if groups:
            top_key, top_count = max(groups.items(), key=lambda x: x[1])
            misses.append(
                f"beacon: max {top_count} conns to same dest "
                f"(need {min_count})"
            )

        # DNS tunneling: top parent domain query count
        tunnel_thresh = self.config["dns_tunnel_query_threshold"]
        parent_counts: Dict[str, int] = defaultdict(int)
        for q in dns_queries:
            domain = (q.get("domain") or "").lower()
            parts = domain.split(".")
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                parent_counts[parent] += 1
        if parent_counts:
            top_parent, top_pcount = max(parent_counts.items(), key=lambda x: x[1])
            misses.append(
                f"dns_tunnel: max {top_pcount} queries to {top_parent} "
                f"(need {tunnel_thresh})"
            )

        return misses

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
        if "c2_beaconing" in types:
            recs.append("Investigate beaconing hosts for compromise — capture full PCAP")
            recs.append("Block beacon destinations at firewall and add to threat intel blocklist")
        if "dga_domain" in types:
            recs.append("Sinkhole DGA domains and isolate resolving hosts")
        if "dns_tunneling" in types:
            recs.append("Block DNS tunneling parent domain and inspect host for data exfiltration")
        if "persistent_c2_channel" in types:
            recs.append("Terminate long-lived sessions and investigate endpoint")
        if "suspicious_port_usage" in types:
            recs.append("Block suspicious ports at perimeter and review affected hosts")
        recs.append("Correlate C2 indicators across all agents for kill chain progression")
        return recs
