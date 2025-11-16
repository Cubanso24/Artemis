"""
Agent 9: Impact & Destruction Hunter

Detects:
- Ransomware behavior
- Data destruction patterns
- Service/resource disruption
- Cryptomining activity
- Resource hijacking
"""

from typing import Dict, List, Any
from datetime import datetime

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class ImpactHunter(BaseAgent):
    """Specialized agent for detecting impact and destructive activities."""

    def __init__(self):
        super().__init__(
            name="impact_hunter",
            tactics=[KillChainStage.IMPACT],
            description="Detects ransomware, data destruction, and resource hijacking"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "rapid_file_change_threshold": 100,
            "rapid_file_change_window": 60,
            "ransomware_extensions": [".encrypted", ".locked", ".crypto", ".crypt"],
            "cryptominer_processes": ["xmrig", "cryptonight", "ethminer"],
            "cpu_threshold": 90,
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect ransomware
        ransomware_result = self._detect_ransomware(data.get("file_operations", []))
        if ransomware_result:
            findings.append(ransomware_result["finding"])
            all_evidence.extend(ransomware_result["evidence"])
            confidence_scores.append(ransomware_result["confidence"])

        # Detect data destruction
        destruction_result = self._detect_data_destruction(data.get("file_operations", []))
        if destruction_result:
            findings.append(destruction_result["finding"])
            all_evidence.extend(destruction_result["evidence"])
            confidence_scores.append(destruction_result["confidence"])

        # Detect cryptomining
        cryptominer_result = self._detect_cryptomining(data.get("process_logs", []))
        if cryptominer_result:
            findings.append(cryptominer_result["finding"])
            all_evidence.extend(cryptominer_result["evidence"])
            confidence_scores.append(cryptominer_result["confidence"])

        # Detect service disruption
        disruption_result = self._detect_service_disruption(data.get("service_logs", []))
        if disruption_result:
            findings.append(disruption_result["finding"])
            all_evidence.extend(disruption_result["evidence"])
            confidence_scores.append(disruption_result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = Severity.CRITICAL  # Impact events are always critical

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

    def _detect_ransomware(self, file_ops: List[Dict]) -> Dict[str, Any]:
        if not file_ops:
            return None

        # Count file modifications
        modifications = [op for op in file_ops if op.get("operation") in ["modify", "rename"]]

        # Check for rapid file changes
        if len(modifications) >= self.config["rapid_file_change_threshold"]:
            # Check for extension changes
            extension_changes = 0
            for op in modifications:
                old_name = op.get("old_filename", "")
                new_name = op.get("filename", "")

                if old_name and new_name:
                    old_ext = old_name.split(".")[-1] if "." in old_name else ""
                    new_ext = new_name.split(".")[-1] if "." in new_name else ""

                    if old_ext != new_ext:
                        extension_changes += 1

                    # Check for known ransomware extensions
                    if any(ext in new_name.lower() for ext in self.config["ransomware_extensions"]):
                        extension_changes += 10  # Strong indicator

            # High confidence if many extension changes
            if extension_changes > len(modifications) * 0.3:
                confidence = 0.95

                finding = Finding(
                    activity_type="ransomware",
                    description=f"Ransomware activity detected: {len(modifications)} files modified, {extension_changes} extension changes",
                    indicators=["rapid_encryption", "extension_changes"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="file_operations",
                            data={
                                "modification_count": len(modifications),
                                "extension_changes": extension_changes,
                                "sample_files": [m.get("filename") for m in modifications[:10]]
                            },
                            description="Ransomware encryption pattern detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1486"]  # Data Encrypted for Impact
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_data_destruction(self, file_ops: List[Dict]) -> Dict[str, Any]:
        if not file_ops:
            return None

        # Count file deletions
        deletions = [op for op in file_ops if op.get("operation") == "delete"]

        # Mass deletion indicates data destruction
        if len(deletions) >= 50:
            confidence = min(0.7 + (len(deletions) / 500), 0.95)

            finding = Finding(
                activity_type="data_destruction",
                description=f"Mass file deletion detected: {len(deletions)} files deleted",
                indicators=["mass_deletion"],
                evidence=[
                    Evidence(
                        timestamp=datetime.utcnow(),
                        source="file_operations",
                        data={
                            "deletion_count": len(deletions),
                            "sample_files": [d.get("filename") for d in deletions[:10]]
                        },
                        description="Mass file deletion pattern",
                        confidence_contribution=confidence
                    )
                ],
                mitre_techniques=["T1485"]  # Data Destruction
            )

            return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_cryptomining(self, process_logs: List[Dict]) -> Dict[str, Any]:
        if not process_logs:
            return None

        for log in process_logs:
            process_name = log.get("process_name", "").lower()
            command_line = log.get("command_line", "").lower()
            cpu_usage = log.get("cpu_usage", 0)

            # Check for known cryptominer processes
            for miner in self.config["cryptominer_processes"]:
                if miner in process_name or miner in command_line:
                    confidence = 0.9

                    finding = Finding(
                        activity_type="cryptomining",
                        description=f"Cryptomining activity detected: {process_name}",
                        indicators=[process_name],
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="process_logs",
                                data=log,
                                description="Cryptomining process detected",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1496"]  # Resource Hijacking
                    )

                    return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

            # High CPU usage from unknown process
            if cpu_usage >= self.config["cpu_threshold"]:
                # Check for mining-related command line arguments
                mining_keywords = ["pool", "wallet", "stratum", "algo", "hashrate"]
                if any(keyword in command_line for keyword in mining_keywords):
                    confidence = 0.75

                    finding = Finding(
                        activity_type="cryptomining",
                        description=f"Suspected cryptomining: high CPU process {process_name}",
                        indicators=[process_name, f"cpu:{cpu_usage}%"],
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="process_logs",
                                data=log,
                                description="High CPU usage with mining indicators",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1496"]  # Resource Hijacking
                    )

                    return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_service_disruption(self, service_logs: List[Dict]) -> Dict[str, Any]:
        if not service_logs:
            return None

        # Count critical services being stopped
        stopped_services = [
            log for log in service_logs
            if log.get("action") == "stopped" and log.get("criticality") == "high"
        ]

        if len(stopped_services) >= 3:
            confidence = 0.8

            finding = Finding(
                activity_type="service_disruption",
                description=f"Multiple critical services stopped: {len(stopped_services)} services",
                indicators=[s.get("service_name") for s in stopped_services],
                evidence=[
                    Evidence(
                        timestamp=datetime.utcnow(),
                        source="service_logs",
                        data={
                            "stopped_count": len(stopped_services),
                            "services": [s.get("service_name") for s in stopped_services]
                        },
                        description="Critical service disruption",
                        confidence_contribution=confidence
                    )
                ],
                mitre_techniques=["T1489"]  # Service Stop
            )

            return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _get_relevant_techniques(self, findings: List[Finding]) -> List[str]:
        techniques = set()
        for finding in findings:
            techniques.update(finding.mitre_techniques)
        return list(techniques)

    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        recommendations = []
        activity_types = {f.activity_type for f in findings}

        if "ransomware" in activity_types:
            recommendations.extend([
                "IMMEDIATE: Isolate all affected systems",
                "IMMEDIATE: Disconnect from network",
                "Restore from backups (verify backup integrity first)",
                "Do NOT pay ransom",
                "Initiate ransomware incident response playbook"
            ])

        if "data_destruction" in activity_types:
            recommendations.extend([
                "Isolate affected systems immediately",
                "Capture forensic images",
                "Assess backup integrity",
                "Initiate disaster recovery procedures"
            ])

        if "cryptomining" in activity_types:
            recommendations.extend([
                "Terminate cryptomining processes",
                "Investigate infection vector",
                "Review network egress to mining pools",
                "Scan for additional malware"
            ])

        if "service_disruption" in activity_types:
            recommendations.extend([
                "Restore critical services",
                "Investigate cause of disruption",
                "Review service dependencies",
                "Implement service monitoring"
            ])

        return recommendations if recommendations else ["Initiate incident response procedures"]
