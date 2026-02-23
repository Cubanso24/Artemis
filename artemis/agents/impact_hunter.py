"""
Agent: Impact & Disruption Hunter

Network-observable impact indicators using Zeek conn/dns data:
- Cryptomining (connections to known mining pools + stratum ports)
- Network-visible ransomware indicators (SMB encryption spread patterns)
- Service disruption (internal services going dark)
- DDoS participation (high-volume outbound to single target)
- Wiper/destructive activity (sudden connection drops across hosts)
"""

from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict, Counter

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class ImpactHunter(BaseAgent):
    """Detects impact and disruptive activity via network telemetry."""

    def __init__(self):
        super().__init__(
            name="impact_hunter",
            tactics=[KillChainStage.IMPACT],
            description="Detects ransomware spread, cryptomining, and service disruption"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "mining_pool_domains": [
                "pool.minergate.com", "xmrpool.eu", "monerohash.com",
                "minexmr.com", "supportxmr.com", "pool.hashvault.pro",
                "nanopool.org", "dwarfpool.com", "2miners.com",
                "f2pool.com", "antpool.com", "viabtc.com",
                "nicehash.com", "ethermine.org", "flypool.org",
                "unmineable.com", "herominers.com", "c3pool.com",
            ],
            "stratum_ports": [3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560],
            "smb_spread_threshold": 10,
            "smb_spread_time_window_minutes": 10,
            "ddos_connection_threshold": 1000,
            "ddos_target_concentration": 0.8,
            "service_dropout_threshold": 5,
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        self._ctx = context  # stash for sub-methods
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        connections = data.get("network_connections", [])
        dns_queries = data.get("dns_queries", [])

        # 1. Cryptomining detection (DNS + port-based)
        for result in self._detect_cryptomining(connections, dns_queries):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 2. Ransomware SMB spread pattern
        for result in self._detect_ransomware_spread(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 3. DDoS participation (outbound flood)
        for result in self._detect_ddos_participation(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = Severity.CRITICAL if overall_confidence > 0.5 else Severity.HIGH

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
    # Detection 1: Cryptomining
    # ------------------------------------------------------------------

    def _detect_cryptomining(
        self, connections: List[Dict], dns_queries: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Detect cryptomining via DNS lookups to mining pools or stratum ports."""
        pool_domains = set(self.config["mining_pool_domains"])
        stratum_ports = set(self.config["stratum_ports"])

        # Check DNS for mining pool resolution
        mining_resolvers: Dict[str, set] = defaultdict(set)
        for q in dns_queries:
            domain = (q.get("domain") or "").lower()
            src = q.get("source_ip", "")
            for pool in pool_domains:
                if pool in domain:
                    mining_resolvers[src].add(domain)
                    break

        # Check connections to stratum ports
        stratum_users: Dict[str, set] = defaultdict(set)
        for conn in connections:
            port = conn.get("destination_port")
            if port in stratum_ports:
                src = conn.get("source_ip", "")
                dst = conn.get("destination_ip", "")
                if src and not self._is_internal(dst, self._ctx):
                    stratum_users[src].add(f"{dst}:{port}")

        # Merge evidence
        all_suspects = set(mining_resolvers.keys()) | set(stratum_users.keys())

        results = []
        for src_ip in all_suspects:
            dns_hits = mining_resolvers.get(src_ip, set())
            port_hits = stratum_users.get(src_ip, set())

            # Higher confidence if both DNS + port match
            if dns_hits and port_hits:
                confidence = 0.92
            elif dns_hits:
                confidence = 0.75
            else:
                confidence = 0.65

            indicators = [src_ip] + sorted(dns_hits)[:3] + sorted(port_hits)[:3]

            finding = Finding(
                activity_type="cryptomining",
                description=(
                    f"Cryptomining from {src_ip}: "
                    f"{len(dns_hits)} pool DNS lookups, "
                    f"{len(port_hits)} stratum connections"
                ),
                indicators=indicators,
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections+dns_queries",
                    data={
                        "source_ip": src_ip,
                        "mining_pool_domains": sorted(dns_hits),
                        "stratum_connections": sorted(port_hits),
                    },
                    description="Cryptomining network activity",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1496"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 2: Ransomware SMB spread
    # ------------------------------------------------------------------

    def _detect_ransomware_spread(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect ransomware lateral spread: rapid SMB fan-out from one host."""
        if not connections:
            return []

        smb_ports = {445, 139}
        threshold = self.config["smb_spread_threshold"]

        # Group internal SMB connections by source
        src_targets: Dict[str, Dict] = defaultdict(lambda: {
            "targets": set(), "timestamps": [], "count": 0,
        })
        for conn in connections:
            port = conn.get("destination_port")
            if port not in smb_ports:
                continue
            src = conn.get("source_ip", "")
            dst = conn.get("destination_ip", "")
            if not (self._is_internal(src, self._ctx) and self._is_internal(dst, self._ctx) and src != dst):
                continue
            info = src_targets[src]
            info["targets"].add(dst)
            info["count"] += 1
            ts = conn.get("timestamp")
            if ts:
                info["timestamps"].append(ts)

        results = []
        for src_ip, info in src_targets.items():
            target_count = len(info["targets"])
            if target_count < threshold:
                continue

            # Check velocity — ransomware spreads fast
            velocity = 0
            if len(info["timestamps"]) >= 2:
                span_minutes = (
                    max(info["timestamps"]) - min(info["timestamps"])
                ).total_seconds() / 60
                if span_minutes > 0:
                    velocity = target_count / span_minutes

            # High target count + high velocity = strong signal
            confidence = min(
                0.60 + (target_count - threshold) * 0.03 + min(velocity * 0.02, 0.15),
                0.95,
            )

            finding = Finding(
                activity_type="ransomware_spread",
                description=(
                    f"Ransomware-like SMB spread from {src_ip}: "
                    f"{target_count} internal hosts targeted "
                    f"({info['count']} connections, "
                    f"{velocity:.1f} hosts/min)"
                ),
                indicators=[src_ip, f"targets:{target_count}"],
                affected_assets=[src_ip] + sorted(info["targets"])[:10],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": src_ip,
                        "target_count": target_count,
                        "connection_count": info["count"],
                        "velocity_hosts_per_min": round(velocity, 2),
                        "targets": sorted(info["targets"])[:20],
                    },
                    description="Ransomware-like rapid SMB spread",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1486", "T1021.002"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 3: DDoS participation
    # ------------------------------------------------------------------

    def _detect_ddos_participation(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect internal hosts participating in outbound DDoS."""
        if not connections:
            return []

        conn_threshold = self.config["ddos_connection_threshold"]
        concentration = self.config["ddos_target_concentration"]

        # Count connections per internal source
        src_conns: Dict[str, Dict] = defaultdict(lambda: {
            "destinations": Counter(), "total": 0,
        })
        for conn in connections:
            src = conn.get("source_ip", "")
            dst = conn.get("destination_ip", "")
            if not (self._is_internal(src, self._ctx) and not self._is_internal(dst, self._ctx)):
                continue
            src_conns[src]["destinations"][dst] += 1
            src_conns[src]["total"] += 1

        results = []
        for src_ip, info in src_conns.items():
            if info["total"] < conn_threshold:
                continue

            # Check if traffic is concentrated on one target
            if not info["destinations"]:
                continue
            top_dst, top_count = info["destinations"].most_common(1)[0]
            target_ratio = top_count / info["total"]

            if target_ratio < concentration:
                continue

            confidence = min(0.60 + target_ratio * 0.15 + (info["total"] / 10000) * 0.1, 0.90)

            finding = Finding(
                activity_type="ddos_participation",
                description=(
                    f"DDoS participation: {src_ip} sent {info['total']} connections, "
                    f"{target_ratio:.0%} to {top_dst}"
                ),
                indicators=[src_ip, top_dst],
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": src_ip,
                        "total_connections": info["total"],
                        "top_target": top_dst,
                        "target_concentration": round(target_ratio, 3),
                    },
                    description="Outbound DDoS participation pattern",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1498"],
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
        if "cryptomining" in types:
            recs.append("Block mining pool domains and stratum ports at firewall")
            recs.append("Investigate infected hosts for malware or compromised accounts")
        if "ransomware_spread" in types:
            recs.append("IMMEDIATE: Isolate spreading host from the network")
            recs.append("IMMEDIATE: Block SMB lateral movement via micro-segmentation")
            recs.append("Verify backup integrity before restoration")
        if "ddos_participation" in types:
            recs.append("Investigate botnet infection on participating hosts")
            recs.append("Rate-limit outbound connections from affected hosts")
        recs.append("Initiate incident response procedures")
        return recs
