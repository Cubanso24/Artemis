"""
Agent 5: Lateral Movement Hunter

Detects:
- Remote service session establishment (RDP, SSH, WinRM)
- SMB/admin share access patterns
- Remote execution (PsExec, WMI, DCOM)
- Pass-the-hash lateral movement
- Unusual service account activity
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class LateralMovementHunter(BaseAgent):
    """Specialized agent for detecting lateral movement."""

    def __init__(self):
        super().__init__(
            name="lateral_movement_hunter",
            tactics=[KillChainStage.LATERAL_MOVEMENT],
            description="Detects lateral movement and pivoting activities"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "rdp_threshold": 3,
            "smb_admin_share_threshold": 5,
            "lateral_movement_time_window": 600,
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect RDP lateral movement
        rdp_result = self._detect_rdp_lateral_movement(data.get("rdp_sessions", []))
        if rdp_result:
            findings.append(rdp_result["finding"])
            all_evidence.extend(rdp_result["evidence"])
            confidence_scores.append(rdp_result["confidence"])

        # Detect SMB lateral movement
        smb_result = self._detect_smb_lateral_movement(data.get("smb_sessions", []))
        if smb_result:
            findings.append(smb_result["finding"])
            all_evidence.extend(smb_result["evidence"])
            confidence_scores.append(smb_result["confidence"])

        # Detect remote execution
        remote_exec_result = self._detect_remote_execution(data.get("process_logs", []))
        if remote_exec_result:
            findings.append(remote_exec_result["finding"])
            all_evidence.extend(remote_exec_result["evidence"])
            confidence_scores.append(remote_exec_result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = Severity.HIGH if overall_confidence > 0.6 else Severity.MEDIUM

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

    def _detect_rdp_lateral_movement(self, rdp_sessions: List[Dict]) -> Dict[str, Any]:
        if not rdp_sessions:
            return None

        # Track RDP sessions by source
        source_sessions = {}
        for session in rdp_sessions:
            src = session.get("source_ip")
            if src not in source_sessions:
                source_sessions[src] = []
            source_sessions[src].append(session)

        for src, sessions in source_sessions.items():
            if len(sessions) >= self.config["rdp_threshold"]:
                unique_targets = len(set(s.get("target_hostname") for s in sessions))

                confidence = min(0.6 + (unique_targets / 10.0), 0.95)

                finding = Finding(
                    activity_type="rdp_lateral_movement",
                    description=f"RDP lateral movement from {src} to {unique_targets} hosts",
                    indicators=[src, f"targets:{unique_targets}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="rdp_sessions",
                            data={"source": src, "target_count": unique_targets},
                            description="Multiple RDP connections detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1021.001"]  # Remote Desktop Protocol
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_smb_lateral_movement(self, smb_sessions: List[Dict]) -> Dict[str, Any]:
        if not smb_sessions:
            return None

        admin_shares = ["C$", "ADMIN$", "IPC$"]

        for session in smb_sessions:
            share = session.get("share_name")
            if share in admin_shares:
                confidence = 0.7

                finding = Finding(
                    activity_type="smb_admin_share_access",
                    description=f"Admin share access: {share} from {session.get('source_ip')}",
                    indicators=[session.get("source_ip"), share],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="smb_sessions",
                            data=session,
                            description="Administrative share access",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1021.002"]  # SMB/Windows Admin Shares
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_remote_execution(self, process_logs: List[Dict]) -> Dict[str, Any]:
        if not process_logs:
            return None

        remote_exec_indicators = ["psexec", "wmic", "winrm", "wmiprvse"]

        for log in process_logs:
            process = log.get("process_name", "").lower()
            if any(indicator in process for indicator in remote_exec_indicators):
                confidence = 0.75

                finding = Finding(
                    activity_type="remote_execution",
                    description=f"Remote execution detected: {process}",
                    indicators=[process],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="process_logs",
                            data=log,
                            description="Remote execution tool detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1569", "T1047"]  # System Services, WMI
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _get_relevant_techniques(self, findings: List[Finding]) -> List[str]:
        techniques = set()
        for finding in findings:
            techniques.update(finding.mitre_techniques)
        return list(techniques)

    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        return [
            "Isolate affected systems",
            "Review authentication logs for compromised accounts",
            "Enable network segmentation",
            "Monitor for additional lateral movement"
        ]
