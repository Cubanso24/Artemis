"""
Agent 8: Defense Evasion Hunter

Detects:
- Log deletion/modification
- Security tool disabling
- Process injection/hollowing
- Masquerading
- Timestomping
"""

from typing import Dict, List, Any
from datetime import datetime

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class DefenseEvasionHunter(BaseAgent):
    """Specialized agent for detecting defense evasion techniques."""

    def __init__(self):
        super().__init__(
            name="defense_evasion_hunter",
            tactics=[KillChainStage.DEFENSE_EVASION],
            description="Detects defense evasion and anti-forensics techniques"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "security_tools": ["antivirus", "edr", "firewall", "sysmon"],
            "critical_logs": ["Security", "System", "Application"],
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect log clearing
        log_clear_result = self._detect_log_clearing(data.get("event_logs", []))
        if log_clear_result:
            findings.append(log_clear_result["finding"])
            all_evidence.extend(log_clear_result["evidence"])
            confidence_scores.append(log_clear_result["confidence"])

        # Detect security tool tampering
        tool_tamper_result = self._detect_security_tool_tampering(data.get("service_logs", []))
        if tool_tamper_result:
            findings.append(tool_tamper_result["finding"])
            all_evidence.extend(tool_tamper_result["evidence"])
            confidence_scores.append(tool_tamper_result["confidence"])

        # Detect process injection
        injection_result = self._detect_process_injection(data.get("process_logs", []))
        if injection_result:
            findings.append(injection_result["finding"])
            all_evidence.extend(injection_result["evidence"])
            confidence_scores.append(injection_result["confidence"])

        # Detect masquerading
        masquerade_result = self._detect_masquerading(data.get("process_logs", []))
        if masquerade_result:
            findings.append(masquerade_result["finding"])
            all_evidence.extend(masquerade_result["evidence"])
            confidence_scores.append(masquerade_result["confidence"])

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

    def _detect_log_clearing(self, event_logs: List[Dict]) -> Dict[str, Any]:
        if not event_logs:
            return None

        for log in event_logs:
            event_id = log.get("event_id")
            log_name = log.get("log_name")

            # Event ID 1102 = Security log cleared
            # Event ID 104 = System log cleared
            if event_id in [1102, 104] and log_name in self.config["critical_logs"]:
                confidence = 0.9

                finding = Finding(
                    activity_type="log_clearing",
                    description=f"Security log cleared: {log_name} on {log.get('hostname')}",
                    indicators=[log_name, str(event_id)],
                    evidence=[
                        Evidence(
                            timestamp=log.get("timestamp", datetime.utcnow()),
                            source="event_logs",
                            data=log,
                            description="Critical log clearing detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1070.001"]  # Clear Windows Event Logs
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_security_tool_tampering(self, service_logs: List[Dict]) -> Dict[str, Any]:
        if not service_logs:
            return None

        for log in service_logs:
            service_name = log.get("service_name", "").lower()
            action = log.get("action", "").lower()

            # Check for security tool services being stopped
            if any(tool in service_name for tool in self.config["security_tools"]):
                if action in ["stopped", "disabled"]:
                    confidence = 0.85

                    finding = Finding(
                        activity_type="security_tool_tampering",
                        description=f"Security service {service_name} was {action}",
                        indicators=[service_name, action],
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="service_logs",
                                data=log,
                                description="Security tool disabled",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1562.001"]  # Disable or Modify Tools
                    )

                    return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_process_injection(self, process_logs: List[Dict]) -> Dict[str, Any]:
        if not process_logs:
            return None

        for log in process_logs:
            # Look for indicators of process injection
            indicators = log.get("indicators", [])

            if "process_injection" in indicators or "remote_thread" in indicators:
                confidence = 0.8

                finding = Finding(
                    activity_type="process_injection",
                    description=f"Process injection detected on {log.get('hostname')}",
                    indicators=indicators,
                    evidence=[
                        Evidence(
                            timestamp=log.get("timestamp", datetime.utcnow()),
                            source="process_logs",
                            data=log,
                            description="Process injection technique detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1055"]  # Process Injection
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_masquerading(self, process_logs: List[Dict]) -> Dict[str, Any]:
        if not process_logs:
            return None

        # Known system processes that should only run from specific paths
        system_processes = {
            "svchost.exe": "C:\\Windows\\System32",
            "lsass.exe": "C:\\Windows\\System32",
            "csrss.exe": "C:\\Windows\\System32",
        }

        for log in process_logs:
            process_name = log.get("process_name", "").lower()
            process_path = log.get("process_path", "").lower()

            for sys_proc, expected_path in system_processes.items():
                if sys_proc in process_name and expected_path.lower() not in process_path:
                    confidence = 0.85

                    finding = Finding(
                        activity_type="masquerading",
                        description=f"Process masquerading: {process_name} running from {process_path}",
                        indicators=[process_name, process_path],
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="process_logs",
                                data=log,
                                description="Process running from unexpected location",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1036"]  # Masquerading
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
            "Enable enhanced logging",
            "Protect log integrity with forwarding",
            "Investigate for additional evasion techniques",
            "Review security tool configurations",
            "Implement application whitelisting"
        ]
