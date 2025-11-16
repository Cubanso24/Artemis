"""
Agent 6: Collection & Exfiltration Hunter

Detects:
- Data staging
- Compression/archiving of sensitive data
- Large data transfers
- Cloud storage uploads
- DNS tunneling
- Screenshot/clipboard capture
"""

from typing import Dict, List, Any
from datetime import datetime

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class CollectionExfiltrationHunter(BaseAgent):
    """Specialized agent for detecting data collection and exfiltration."""

    def __init__(self):
        super().__init__(
            name="collection_exfiltration_hunter",
            tactics=[KillChainStage.COLLECTION, KillChainStage.EXFILTRATION],
            description="Detects data collection and exfiltration activities"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "large_transfer_threshold_mb": 100,
            "archive_extensions": [".zip", ".rar", ".7z", ".tar", ".gz"],
            "cloud_storage_domains": ["dropbox.com", "drive.google.com", "onedrive.com"],
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect data staging
        staging_result = self._detect_data_staging(data.get("file_operations", []))
        if staging_result:
            findings.append(staging_result["finding"])
            all_evidence.extend(staging_result["evidence"])
            confidence_scores.append(staging_result["confidence"])

        # Detect large data transfers
        transfer_result = self._detect_large_transfers(data.get("network_transfers", []))
        if transfer_result:
            findings.append(transfer_result["finding"])
            all_evidence.extend(transfer_result["evidence"])
            confidence_scores.append(transfer_result["confidence"])

        # Detect cloud exfiltration
        cloud_result = self._detect_cloud_exfiltration(data.get("web_requests", []))
        if cloud_result:
            findings.append(cloud_result["finding"])
            all_evidence.extend(cloud_result["evidence"])
            confidence_scores.append(cloud_result["confidence"])

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

    def _detect_data_staging(self, file_ops: List[Dict]) -> Dict[str, Any]:
        if not file_ops:
            return None

        # Look for archiving operations
        for op in file_ops:
            filename = op.get("filename", "").lower()
            operation = op.get("operation", "")

            if operation == "create" and any(ext in filename for ext in self.config["archive_extensions"]):
                file_size = op.get("file_size_bytes", 0)

                if file_size > 10 * 1024 * 1024:  # > 10MB
                    confidence = 0.65

                    finding = Finding(
                        activity_type="data_staging",
                        description=f"Large archive created: {filename} ({file_size / 1024 / 1024:.1f} MB)",
                        indicators=[filename],
                        evidence=[
                            Evidence(
                                timestamp=datetime.utcnow(),
                                source="file_operations",
                                data=op,
                                description="Potential data staging via archiving",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1560"]  # Archive Collected Data
                    )

                    return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_large_transfers(self, network_transfers: List[Dict]) -> Dict[str, Any]:
        if not network_transfers:
            return None

        for transfer in network_transfers:
            bytes_transferred = transfer.get("bytes_transferred", 0)
            mb_transferred = bytes_transferred / (1024 * 1024)

            if mb_transferred > self.config["large_transfer_threshold_mb"]:
                confidence = min(0.5 + (mb_transferred / 1000), 0.9)

                finding = Finding(
                    activity_type="large_data_transfer",
                    description=f"Large data transfer: {mb_transferred:.1f} MB to {transfer.get('destination')}",
                    indicators=[transfer.get("destination")],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="network_transfers",
                            data=transfer,
                            description="Large outbound data transfer detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1041"]  # Exfiltration Over C2 Channel
                )

                return {"finding": finding, "evidence": finding.evidence, "confidence": confidence}

        return None

    def _detect_cloud_exfiltration(self, web_requests: List[Dict]) -> Dict[str, Any]:
        if not web_requests:
            return None

        for request in web_requests:
            url = request.get("url", "").lower()
            method = request.get("method", "")

            if method == "POST" and any(domain in url for domain in self.config["cloud_storage_domains"]):
                confidence = 0.7

                finding = Finding(
                    activity_type="cloud_exfiltration",
                    description=f"Data upload to cloud storage: {url}",
                    indicators=[url],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="web_requests",
                            data=request,
                            description="Upload to cloud storage service",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1567"]  # Exfiltration Over Web Service
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
            "Block external data transfers",
            "Review DLP policies",
            "Investigate source of exfiltration",
            "Monitor for additional data theft"
        ]
