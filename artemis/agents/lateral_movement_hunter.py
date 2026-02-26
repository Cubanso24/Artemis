"""
Agent: Lateral Movement Hunter

Network-observable lateral movement using Zeek conn/dns/ntlm data:
- Internal RDP fan-out (one source -> many internal hosts on 3389)
- Internal SMB fan-out (one source -> many internal hosts on 445)
- SSH lateral movement (internal-to-internal SSH connections)
- WinRM/DCOM lateral movement (port 5985/5986/135)
- NTLM relay patterns (from ntlm_logs)
- Unusual internal-to-internal traffic spikes
"""

from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


# Ports associated with remote access / lateral movement
_RDP_PORTS = {3389}
_SMB_PORTS = {445, 139}
_SSH_PORTS = {22}
_WINRM_PORTS = {5985, 5986}
_DCOM_PORTS = {135}


class LateralMovementHunter(BaseAgent):
    """Detects lateral movement through network connection analysis."""

    def __init__(self):
        super().__init__(
            name="lateral_movement_hunter",
            tactics=[KillChainStage.LATERAL_MOVEMENT],
            description="Detects lateral movement and pivoting via network patterns"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "rdp_fan_out_threshold": 5,
            "smb_fan_out_threshold": 5,
            "ssh_fan_out_threshold": 4,
            "winrm_fan_out_threshold": 3,
            "ntlm_relay_threshold": 3,
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        connections = data.get("network_connections", [])
        ntlm_logs = data.get("ntlm_logs", [])

        # Only internal-to-internal connections for lateral movement
        internal_conns = [
            c for c in connections
            if self._is_internal(c.get("source_ip", ""), context)
            and self._is_internal(c.get("destination_ip", ""), context)
        ]

        # 1. RDP fan-out
        for result in self._detect_fan_out(
            internal_conns, _RDP_PORTS,
            "rdp_lateral_movement", "RDP",
            self.config["rdp_fan_out_threshold"],
            ["T1021.001"],
        ):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 2. SMB fan-out
        for result in self._detect_fan_out(
            internal_conns, _SMB_PORTS,
            "smb_lateral_movement", "SMB",
            self.config["smb_fan_out_threshold"],
            ["T1021.002"],
        ):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 3. SSH fan-out
        for result in self._detect_fan_out(
            internal_conns, _SSH_PORTS,
            "ssh_lateral_movement", "SSH",
            self.config["ssh_fan_out_threshold"],
            ["T1021.004"],
        ):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 4. WinRM/DCOM fan-out
        winrm_dcom_ports = _WINRM_PORTS | _DCOM_PORTS
        for result in self._detect_fan_out(
            internal_conns, winrm_dcom_ports,
            "winrm_lateral_movement", "WinRM/DCOM",
            self.config["winrm_fan_out_threshold"],
            ["T1021.006", "T1021.003"],
        ):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # 5. NTLM relay patterns
        for result in self._detect_ntlm_relay(ntlm_logs):
            findings.append(result["finding"])
            all_evidence.extend(result["evidence"])
            confidence_scores.append(result["confidence"])

        # Collect near-miss diagnostics when no findings produced
        near_misses = []
        if not findings:
            near_misses = self._collect_near_misses(internal_conns, connections)

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
            metadata={"near_misses": near_misses} if near_misses else {},
        )

    # ------------------------------------------------------------------
    # Generic fan-out detection
    # ------------------------------------------------------------------

    def _detect_fan_out(
        self,
        connections: List[Dict],
        target_ports: set,
        activity_type: str,
        protocol_label: str,
        threshold: int,
        techniques: List[str],
    ) -> List[Dict[str, Any]]:
        """Detect one source connecting to many internal hosts on specific ports."""
        # Group by source IP
        src_targets: Dict[str, set] = defaultdict(set)
        src_counts: Dict[str, int] = defaultdict(int)
        for conn in connections:
            port = conn.get("destination_port")
            if port not in target_ports:
                continue
            src = conn.get("source_ip", "")
            dst = conn.get("destination_ip", "")
            if src and dst and src != dst:
                src_targets[src].add(dst)
                src_counts[src] += 1

        results = []
        for src_ip, targets in src_targets.items():
            target_count = len(targets)
            if target_count < threshold:
                continue

            conn_count = src_counts[src_ip]
            confidence = min(0.55 + (target_count - threshold) * 0.05 + conn_count * 0.002, 0.93)

            finding = Finding(
                activity_type=activity_type,
                description=(
                    f"{protocol_label} lateral movement from {src_ip}: "
                    f"connected to {target_count} internal hosts "
                    f"({conn_count} total connections)"
                ),
                indicators=[src_ip, f"targets:{target_count}"],
                affected_assets=[src_ip] + sorted(targets)[:10],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="network_connections",
                    data={
                        "source_ip": src_ip,
                        "target_count": target_count,
                        "connection_count": conn_count,
                        "targets": sorted(targets)[:20],
                        "protocol": protocol_label,
                    },
                    description=f"{protocol_label} fan-out from {src_ip}",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=techniques,
            )
            results.append({
                "finding": finding,
                "evidence": finding.evidence,
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # NTLM relay detection
    # ------------------------------------------------------------------

    def _detect_ntlm_relay(self, ntlm_logs: List[Dict]) -> List[Dict[str, Any]]:
        """Detect NTLM relay: same hostname authenticating to many targets rapidly."""
        if not ntlm_logs:
            return []

        threshold = self.config["ntlm_relay_threshold"]

        # Group by hostname -> destination IPs
        host_targets: Dict[str, set] = defaultdict(set)
        host_counts: Dict[str, int] = defaultdict(int)
        for log in ntlm_logs:
            hostname = log.get("hostname", "")
            dest = log.get("dest_ip", "")
            if hostname and dest:
                host_targets[hostname].add(dest)
                host_counts[hostname] += 1

        results = []
        for hostname, targets in host_targets.items():
            if len(targets) < threshold:
                continue

            confidence = min(0.60 + len(targets) * 0.05, 0.88)

            finding = Finding(
                activity_type="ntlm_relay",
                description=(
                    f"Possible NTLM relay: {hostname} authenticated to "
                    f"{len(targets)} different targets"
                ),
                indicators=[hostname] + sorted(targets)[:5],
                affected_assets=[hostname],
                evidence=[Evidence(
                    timestamp=datetime.utcnow(),
                    source="ntlm_logs",
                    data={
                        "hostname": hostname,
                        "target_count": len(targets),
                        "targets": sorted(targets)[:10],
                        "auth_count": host_counts[hostname],
                    },
                    description=f"NTLM relay pattern from {hostname}",
                    confidence_contribution=confidence,
                )],
                mitre_techniques=["T1557.001"],
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

    def _collect_near_misses(
        self, internal_conns: List[Dict], all_conns: List[Dict]
    ) -> List[str]:
        """Summarize closest-to-threshold lateral movement for diagnostics."""
        misses = [f"{len(internal_conns)}/{len(all_conns)} conns are internal-to-internal"]

        for label, ports, thresh_key in [
            ("RDP", _RDP_PORTS, "rdp_fan_out_threshold"),
            ("SMB", _SMB_PORTS, "smb_fan_out_threshold"),
            ("SSH", _SSH_PORTS, "ssh_fan_out_threshold"),
        ]:
            src_targets: Dict[str, set] = defaultdict(set)
            for conn in internal_conns:
                if conn.get("destination_port") in ports:
                    src = conn.get("source_ip", "")
                    dst = conn.get("destination_ip", "")
                    if src and dst and src != dst:
                        src_targets[src].add(dst)
            if src_targets:
                top_src = max(src_targets, key=lambda s: len(src_targets[s]))
                top_count = len(src_targets[top_src])
                thresh = self.config[thresh_key]
                misses.append(
                    f"{label}: max {top_count} targets from {top_src} "
                    f"(need {thresh})"
                )
            else:
                misses.append(f"{label}: 0 connections")

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
        if "rdp_lateral_movement" in types:
            recs.append("Restrict RDP access via network segmentation and MFA")
        if "smb_lateral_movement" in types:
            recs.append("Limit SMB lateral movement — disable SMBv1, restrict admin shares")
        if "ssh_lateral_movement" in types:
            recs.append("Review SSH key distribution and restrict internal SSH access")
        if "winrm_lateral_movement" in types:
            recs.append("Restrict WinRM/DCOM to management workstations only")
        if "ntlm_relay" in types:
            recs.append("Enable SMB signing and LDAP signing to prevent NTLM relay")
        recs.append("Isolate affected hosts and investigate for compromised credentials")
        return recs
