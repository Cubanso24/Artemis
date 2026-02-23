"""
Agent: Collection & Exfiltration Hunter

Network-observable exfiltration using Zeek conn/dns/http data:
- Large outbound data transfers (bytes_out anomaly per destination)
- DNS tunneling for data exfiltration (long encoded subdomains)
- Cloud storage uploads (POST to known cloud storage via HTTP logs)
- Asymmetric traffic patterns (far more bytes out than in)
- Unusual outbound connections to rare destinations
"""

from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict, Counter
import math

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class CollectionExfiltrationHunter(BaseAgent):
    """Detects data collection and exfiltration via network analysis."""

    def __init__(self):
        super().__init__(
            name="collection_exfiltration_hunter",
            tactics=[KillChainStage.COLLECTION, KillChainStage.EXFILTRATION],
            description="Detects data exfiltration and collection via network patterns"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "large_transfer_bytes": 100 * 1024 * 1024,   # 100 MB
            "asymmetric_ratio_threshold": 10.0,           # 10:1 out:in
            "asymmetric_min_bytes_out": 50 * 1024 * 1024, # 50 MB minimum
            "dns_exfil_subdomain_length": 30,             # chars
            "dns_exfil_unique_threshold": 30,             # unique long subdomains
            "cloud_storage_domains": [
                "dropbox.com", "dl.dropboxusercontent.com",
                "drive.google.com", "storage.googleapis.com",
                "onedrive.live.com", "1drv.ms",
                "s3.amazonaws.com", "blob.core.windows.net",
                "mega.nz", "mega.co.nz",
                "file.io", "transfer.sh", "wetransfer.com",
                "pastebin.com", "hastebin.com",
                "anonfiles.com", "gofile.io",
            ],
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        self._ctx = context  # stash for sub-methods
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        connections = data.get("network_connections", [])
        dns_queries = data.get("dns_queries", [])
        http_requests = data.get("http_requests", [])

        # 1. Large outbound transfers
        for result in self._detect_large_transfers(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 2. Asymmetric traffic (exfiltration indicator)
        for result in self._detect_asymmetric_traffic(connections):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 3. DNS data exfiltration (long encoded subdomains)
        for result in self._detect_dns_exfiltration(dns_queries):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 4. Cloud storage uploads (HTTP POST to cloud providers)
        for result in self._detect_cloud_uploads(http_requests):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = Severity.HIGH if overall_confidence > 0.6 else Severity.MEDIUM

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
    # Detection 1: Large outbound transfers
    # ------------------------------------------------------------------

    def _detect_large_transfers(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect large cumulative outbound byte transfers per (src, dst) pair."""
        if not connections:
            return []

        threshold = self.config["large_transfer_bytes"]

        # Aggregate bytes_out per (internal_src -> external_dst)
        transfers: Dict[str, Dict] = defaultdict(lambda: {
            "bytes_out": 0, "bytes_in": 0, "count": 0, "src": "", "dst": "",
        })
        for conn in connections:
            src = conn.get("source_ip", "")
            dst = conn.get("destination_ip", "")
            if not (src and dst):
                continue
            if not self._is_internal(src, self._ctx) or self._is_internal(dst, self._ctx):
                continue  # Only internal -> external

            key = f"{src}|{dst}"
            info = transfers[key]
            info["src"] = src
            info["dst"] = dst
            info["bytes_out"] += int(conn.get("bytes_out", 0))
            info["bytes_in"] += int(conn.get("bytes_in", 0))
            info["count"] += 1

        results = []
        for key, info in transfers.items():
            if info["bytes_out"] < threshold:
                continue

            mb_out = info["bytes_out"] / (1024 * 1024)
            confidence = min(0.55 + (mb_out / 1000) * 0.25, 0.90)

            finding = Finding(
                activity_type="large_data_transfer",
                description=(
                    f"Large outbound transfer: {info['src']} -> {info['dst']}: "
                    f"{mb_out:.1f} MB out ({info['count']} connections)"
                ),
                indicators=[info["src"], info["dst"]],
                affected_assets=[info["src"]],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": info["src"],
                        "destination_ip": info["dst"],
                        "bytes_out": info["bytes_out"],
                        "bytes_in": info["bytes_in"],
                        "mb_transferred": round(mb_out, 1),
                        "connection_count": info["count"],
                    },
                    description="Large outbound data transfer",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1041"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 2: Asymmetric traffic
    # ------------------------------------------------------------------

    def _detect_asymmetric_traffic(self, connections: List[Dict]) -> List[Dict[str, Any]]:
        """Detect hosts with significantly more outbound than inbound bytes."""
        if not connections:
            return []

        ratio_threshold = self.config["asymmetric_ratio_threshold"]
        min_out = self.config["asymmetric_min_bytes_out"]

        # Aggregate per internal source -> all external destinations
        host_traffic: Dict[str, Dict] = defaultdict(lambda: {
            "bytes_out": 0, "bytes_in": 0, "destinations": set(), "count": 0,
        })
        for conn in connections:
            src = conn.get("source_ip", "")
            dst = conn.get("destination_ip", "")
            if not self._is_internal(src, self._ctx) or self._is_internal(dst, self._ctx):
                continue
            info = host_traffic[src]
            info["bytes_out"] += int(conn.get("bytes_out", 0))
            info["bytes_in"] += int(conn.get("bytes_in", 0))
            info["destinations"].add(dst)
            info["count"] += 1

        results = []
        for src_ip, info in host_traffic.items():
            if info["bytes_out"] < min_out:
                continue
            ratio = info["bytes_out"] / max(info["bytes_in"], 1)
            if ratio < ratio_threshold:
                continue

            mb_out = info["bytes_out"] / (1024 * 1024)
            confidence = min(0.50 + (ratio / 50) * 0.2 + (mb_out / 500) * 0.15, 0.85)

            finding = Finding(
                activity_type="asymmetric_traffic",
                description=(
                    f"Asymmetric traffic from {src_ip}: {mb_out:.1f} MB out, "
                    f"ratio {ratio:.1f}:1 to {len(info['destinations'])} destinations"
                ),
                indicators=[src_ip, f"ratio:{ratio:.1f}"],
                affected_assets=[src_ip],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": src_ip,
                        "bytes_out": info["bytes_out"],
                        "bytes_in": info["bytes_in"],
                        "out_in_ratio": round(ratio, 2),
                        "unique_destinations": len(info["destinations"]),
                    },
                    description="Asymmetric outbound traffic pattern",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1048"],
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Detection 3: DNS exfiltration
    # ------------------------------------------------------------------

    def _detect_dns_exfiltration(self, dns_queries: List[Dict]) -> List[Dict[str, Any]]:
        """Detect DNS exfiltration: many long-encoded subdomains under one parent."""
        if not dns_queries:
            return []

        length_threshold = self.config["dns_exfil_subdomain_length"]
        unique_threshold = self.config["dns_exfil_unique_threshold"]

        # Group by (source, parent_domain)
        groups: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
        for q in dns_queries:
            domain = q.get("domain", "")
            src = q.get("source_ip", "")
            parts = domain.split(".")
            if len(parts) < 3 or not src:
                continue
            parent = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            if len(subdomain) >= length_threshold:
                groups[src][parent].append(subdomain)

        results = []
        for src_ip, parents in groups.items():
            for parent_domain, subdomains in parents.items():
                unique_subs = set(subdomains)
                if len(unique_subs) < unique_threshold:
                    continue

                # Calculate total encoded data volume estimate
                total_chars = sum(len(s) for s in subdomains)
                est_bytes = total_chars * 0.75  # base64-like encoding

                confidence = min(0.60 + len(unique_subs) * 0.002 + (total_chars / 10000) * 0.1, 0.92)

                finding = Finding(
                    activity_type="dns_exfiltration",
                    description=(
                        f"DNS exfiltration from {src_ip} via {parent_domain}: "
                        f"{len(unique_subs)} unique long subdomains "
                        f"(~{est_bytes / 1024:.1f} KB encoded)"
                    ),
                    indicators=[src_ip, parent_domain],
                    affected_assets=[src_ip],
                    evidence=[Evidence(
                        timestamp=datetime.utcnow(),
                        source="dns_queries",
                        data={
                            "source_ip": src_ip,
                            "parent_domain": parent_domain,
                            "unique_long_subdomains": len(unique_subs),
                            "total_query_count": len(subdomains),
                            "estimated_exfil_bytes": round(est_bytes),
                            "sample_subdomains": sorted(unique_subs)[:3],
                        },
                        description="DNS-based data exfiltration",
                        confidence_contribution=confidence,
                    )],
                    mitre_techniques=["T1048.003"],
                )
                results.append({
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence,
                })

        return results

    # ------------------------------------------------------------------
    # Detection 4: Cloud storage uploads
    # ------------------------------------------------------------------

    def _detect_cloud_uploads(self, http_requests: List[Dict]) -> List[Dict[str, Any]]:
        """Detect uploads to cloud storage services via HTTP POST/PUT."""
        if not http_requests:
            return []

        cloud_domains = self.config["cloud_storage_domains"]

        # Group by source -> cloud service
        uploads: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for req in http_requests:
            method = (req.get("method") or "").upper()
            if method not in ("POST", "PUT"):
                continue

            host = (req.get("host") or "").lower()
            uri = (req.get("uri") or "").lower()
            url_combined = host + uri

            for cloud in cloud_domains:
                if cloud in host or cloud in url_combined:
                    src = req.get("source_ip", "unknown")
                    uploads[src][cloud] += 1
                    break

        results = []
        for src_ip, services in uploads.items():
            for service, count in services.items():
                confidence = min(0.60 + count * 0.05, 0.88)

                finding = Finding(
                    activity_type="cloud_exfiltration",
                    description=(
                        f"Cloud upload from {src_ip} to {service}: "
                        f"{count} POST/PUT requests"
                    ),
                    indicators=[src_ip, service],
                    affected_assets=[src_ip],
                    evidence=[Evidence(
                        timestamp=datetime.utcnow(),
                        source="http_requests",
                        data={
                            "source_ip": src_ip,
                            "cloud_service": service,
                            "upload_count": count,
                        },
                        description=f"Upload to cloud storage: {service}",
                        confidence_contribution=confidence,
                    )],
                    mitre_techniques=["T1567"],
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
        if "large_data_transfer" in types:
            recs.append("Investigate large outbound transfers — capture PCAP for content analysis")
        if "asymmetric_traffic" in types:
            recs.append("Review asymmetric hosts for unauthorized data movement")
        if "dns_exfiltration" in types:
            recs.append("Block DNS exfiltration parent domain and inspect host for malware")
        if "cloud_exfiltration" in types:
            recs.append("Review DLP policies for cloud storage uploads")
            recs.append("Block unauthorized cloud storage at web proxy")
        recs.append("Preserve evidence and assess data sensitivity")
        return recs
