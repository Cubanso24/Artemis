"""
Agent 3: Execution & Persistence Hunter

Detects:
- PowerShell/command-line abuse
- Living-off-the-land binaries (LOLBins)
- Scheduled task/cron job creation
- Registry modifications for persistence
- WMI event subscriptions
- Service creation/modification
"""

from typing import Dict, List, Any
from datetime import datetime
import re
import base64

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class ExecutionPersistenceHunter(BaseAgent):
    """
    Specialized agent for detecting execution and persistence mechanisms.

    Focuses on MITRE ATT&CK Tactics:
    - TA0002 (Execution)
    - TA0003 (Persistence)
    """

    def __init__(self):
        super().__init__(
            name="execution_persistence_hunter",
            tactics=[KillChainStage.EXECUTION, KillChainStage.PERSISTENCE],
            description="Detects malicious execution and persistence mechanisms"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        """Default configuration."""
        return {
            # Suspicious processes
            "lolbins": [
                "powershell.exe", "cmd.exe", "wmic.exe", "mshta.exe",
                "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
                "wscript.exe", "cscript.exe", "msiexec.exe"
            ],

            # Obfuscation indicators
            "min_base64_length": 50,
            "max_command_length": 1000,

            # Persistence locations
            "persistence_registry_keys": [
                "Run", "RunOnce", "RunServices", "RunServicesOnce",
                "Winlogon", "Shell", "Userinit"
            ],

            "persistence_directories": [
                "Startup", "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            ]
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        """Analyze data for execution and persistence."""
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect suspicious PowerShell
        ps_result = self._detect_powershell_abuse(data.get("powershell_logs", []))
        if ps_result:
            findings.append(ps_result["finding"])
            all_evidence.extend(ps_result["evidence"])
            confidence_scores.append(ps_result["confidence"])

        # Detect LOLBin abuse
        lolbin_result = self._detect_lolbin_usage(data.get("process_logs", []))
        if lolbin_result:
            findings.append(lolbin_result["finding"])
            all_evidence.extend(lolbin_result["evidence"])
            confidence_scores.append(lolbin_result["confidence"])

        # Detect scheduled tasks
        schtask_result = self._detect_scheduled_task_abuse(data.get("scheduled_tasks", []))
        if schtask_result:
            findings.append(schtask_result["finding"])
            all_evidence.extend(schtask_result["evidence"])
            confidence_scores.append(schtask_result["confidence"])

        # Detect registry persistence
        reg_result = self._detect_registry_persistence(data.get("registry_changes", []))
        if reg_result:
            findings.append(reg_result["finding"])
            all_evidence.extend(reg_result["evidence"])
            confidence_scores.append(reg_result["confidence"])

        # Detect WMI abuse
        wmi_result = self._detect_wmi_abuse(data.get("wmi_events", []))
        if wmi_result:
            findings.append(wmi_result["finding"])
            all_evidence.extend(wmi_result["evidence"])
            confidence_scores.append(wmi_result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = self._determine_severity(overall_confidence, findings)

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

    def _detect_powershell_abuse(self, ps_logs: List[Dict]) -> Dict[str, Any]:
        """Detect suspicious PowerShell usage."""
        if not ps_logs:
            return None

        for log in ps_logs:
            command = log.get("command_line", "")
            risk_score = 0.0
            indicators = []

            # Check for base64 encoding
            if re.search(r'-enc(oded(command)?)?', command, re.IGNORECASE):
                risk_score += 0.3
                indicators.append("base64_encoded")

                # Try to decode and analyze
                base64_match = re.search(r'-enc\w*\s+([A-Za-z0-9+/=]+)', command, re.IGNORECASE)
                if base64_match:
                    try:
                        decoded = base64.b64decode(base64_match.group(1)).decode('utf-16-le', errors='ignore')
                        if any(susp in decoded.lower() for susp in ['invoke', 'downloadstring', 'iex', 'webclient']):
                            risk_score += 0.3
                            indicators.append("suspicious_decoded_content")
                    except:
                        pass

            # Check for download cradles
            download_patterns = [
                r'(invoke-webrequest|iwr|wget|curl)',
                r'downloadstring',
                r'net\.webclient',
                r'bitstransfer'
            ]
            for pattern in download_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    risk_score += 0.4
                    indicators.append(f"download_cradle:{pattern}")

            # Check for obfuscation
            if re.search(r'[`\^]', command) or command.count('.') > 10:
                risk_score += 0.2
                indicators.append("obfuscation_detected")

            # Check for bypasses
            bypass_patterns = ['-nop', '-w hidden', '-ep bypass', '-noni']
            for pattern in bypass_patterns:
                if pattern in command.lower():
                    risk_score += 0.15
                    indicators.append(f"bypass_flag:{pattern}")

            # Check command length (very long commands are suspicious)
            if len(command) > self.config["max_command_length"]:
                risk_score += 0.1
                indicators.append("excessive_length")

            if risk_score >= 0.5:
                confidence = min(risk_score, 1.0)

                finding = Finding(
                    activity_type="powershell_abuse",
                    description=f"Suspicious PowerShell execution on {log.get('hostname')}",
                    indicators=indicators,
                    evidence=[
                        Evidence(
                            timestamp=log.get("timestamp", datetime.utcnow()),
                            source="powershell_logs",
                            data={
                                "hostname": log.get("hostname"),
                                "user": log.get("user"),
                                "command": command[:500],  # Truncate
                                "risk_score": risk_score
                            },
                            description="Malicious PowerShell pattern detected",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1059.001", "T1027"]  # PowerShell, Obfuscated Files or Information
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_lolbin_usage(self, process_logs: List[Dict]) -> Dict[str, Any]:
        """Detect living-off-the-land binaries abuse."""
        if not process_logs:
            return None

        for log in process_logs:
            process_name = log.get("process_name", "").lower()
            command_line = log.get("command_line", "")
            parent_process = log.get("parent_process", "").lower()

            # Check if it's a LOLBin
            if any(lolbin.lower() in process_name for lolbin in self.config["lolbins"]):
                risk_score = 0.0
                indicators = [process_name]

                # Certutil abuse (download/decode)
                if "certutil" in process_name and any(flag in command_line.lower() for flag in ['-urlcache', '-decode']):
                    risk_score += 0.7
                    indicators.append("certutil_download")

                # Regsvr32 abuse (Squiblydoo)
                if "regsvr32" in process_name and "scrobj.dll" in command_line.lower():
                    risk_score += 0.8
                    indicators.append("regsvr32_squiblydoo")

                # Rundll32 abuse
                if "rundll32" in process_name and ("javascript:" in command_line.lower() or "http" in command_line.lower()):
                    risk_score += 0.7
                    indicators.append("rundll32_abuse")

                # WMIC abuse
                if "wmic" in process_name and any(term in command_line.lower() for term in ["process call create", "node:", "/format"]):
                    risk_score += 0.7
                    indicators.append("wmic_abuse")

                # Mshta abuse
                if "mshta" in process_name and ("http" in command_line.lower() or "javascript:" in command_line.lower()):
                    risk_score += 0.8
                    indicators.append("mshta_abuse")

                # Suspicious parent process
                if parent_process in ["excel.exe", "winword.exe", "outlook.exe", "acrobat.exe"]:
                    risk_score += 0.3
                    indicators.append(f"suspicious_parent:{parent_process}")

                if risk_score >= 0.6:
                    confidence = min(risk_score, 1.0)

                    finding = Finding(
                        activity_type="lolbin_abuse",
                        description=f"Living-off-the-land binary abuse: {process_name} on {log.get('hostname')}",
                        indicators=indicators,
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="process_logs",
                                data={
                                    "hostname": log.get("hostname"),
                                    "process": process_name,
                                    "parent_process": parent_process,
                                    "command_line": command_line[:500]
                                },
                                description=f"LOLBin abuse detected: {process_name}",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1218"]  # System Binary Proxy Execution
                    )

                    return {
                        "finding": finding,
                        "evidence": finding.evidence,
                        "confidence": confidence
                    }

        return None

    def _detect_scheduled_task_abuse(self, schtasks: List[Dict]) -> Dict[str, Any]:
        """Detect malicious scheduled task creation."""
        if not schtasks:
            return None

        for task in schtasks:
            if task.get("event_type") != "created":
                continue

            risk_score = 0.0
            indicators = []

            task_name = task.get("task_name", "")
            command = task.get("command", "")
            trigger = task.get("trigger", "")

            # Check for suspicious names (random/mimicking)
            if re.search(r'[a-f0-9]{8,}', task_name) or len(task_name) > 30:
                risk_score += 0.2
                indicators.append("suspicious_name")

            # Check command for suspicious patterns
            if any(term in command.lower() for term in ["powershell", "cmd.exe", "wscript", "mshta"]):
                risk_score += 0.3
                indicators.append("suspicious_command")

            # Check for unusual triggers
            if trigger and ("on logon" in trigger.lower() or "at startup" in trigger.lower()):
                risk_score += 0.2
                indicators.append("persistence_trigger")

            # Check if running as SYSTEM
            if task.get("run_as") == "SYSTEM":
                risk_score += 0.2
                indicators.append("system_context")

            if risk_score >= 0.5:
                confidence = min(risk_score, 1.0)

                finding = Finding(
                    activity_type="scheduled_task_persistence",
                    description=f"Suspicious scheduled task created: {task_name}",
                    indicators=indicators,
                    evidence=[
                        Evidence(
                            timestamp=task.get("timestamp", datetime.utcnow()),
                            source="scheduled_tasks",
                            data={
                                "task_name": task_name,
                                "command": command,
                                "trigger": trigger,
                                "creator": task.get("creator")
                            },
                            description=f"Malicious scheduled task: {task_name}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1053.005"]  # Scheduled Task
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_registry_persistence(self, reg_changes: List[Dict]) -> Dict[str, Any]:
        """Detect registry-based persistence."""
        if not reg_changes:
            return None

        for change in reg_changes:
            key_path = change.get("key_path", "")
            value_name = change.get("value_name", "")
            value_data = change.get("value_data", "")

            # Check for persistence locations
            for persist_key in self.config["persistence_registry_keys"]:
                if persist_key.lower() in key_path.lower():
                    risk_score = 0.6
                    indicators = [f"persistence_key:{persist_key}"]

                    # Check value data for suspicious content
                    if any(term in value_data.lower() for term in ["powershell", "cmd", "wscript", "http"]):
                        risk_score += 0.3
                        indicators.append("suspicious_value_data")

                    confidence = min(risk_score, 1.0)

                    finding = Finding(
                        activity_type="registry_persistence",
                        description=f"Registry persistence mechanism detected: {key_path}\\{value_name}",
                        indicators=indicators,
                        evidence=[
                            Evidence(
                                timestamp=change.get("timestamp", datetime.utcnow()),
                                source="registry_changes",
                                data={
                                    "key_path": key_path,
                                    "value_name": value_name,
                                    "value_data": value_data[:200],
                                    "user": change.get("user")
                                },
                                description="Registry persistence detected",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1547.001"]  # Registry Run Keys
                    )

                    return {
                        "finding": finding,
                        "evidence": finding.evidence,
                        "confidence": confidence
                    }

        return None

    def _detect_wmi_abuse(self, wmi_events: List[Dict]) -> Dict[str, Any]:
        """Detect WMI abuse for execution/persistence."""
        if not wmi_events:
            return None

        for event in wmi_events:
            event_type = event.get("event_type", "")

            # WMI event subscription for persistence
            if any(term in event_type.lower() for term in ["eventconsumer", "eventfilter", "filtertoconsumer"]):
                confidence = 0.75

                finding = Finding(
                    activity_type="wmi_persistence",
                    description=f"WMI event subscription detected: {event_type}",
                    indicators=[event_type],
                    evidence=[
                        Evidence(
                            timestamp=event.get("timestamp", datetime.utcnow()),
                            source="wmi_events",
                            data={
                                "event_type": event_type,
                                "consumer": event.get("consumer"),
                                "filter": event.get("filter")
                            },
                            description="WMI persistence mechanism",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1047"]  # Windows Management Instrumentation
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _determine_severity(self, confidence: float, findings: List[Finding]) -> Severity:
        """Determine severity."""
        if confidence >= 0.8:
            return Severity.CRITICAL
        elif confidence >= 0.6:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _get_relevant_techniques(self, findings: List[Finding]) -> List[str]:
        """Extract MITRE techniques."""
        techniques = set()
        for finding in findings:
            techniques.update(finding.mitre_techniques)
        return list(techniques)

    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate recommendations."""
        recommendations = []
        activity_types = {f.activity_type for f in findings}

        if "powershell_abuse" in activity_types:
            recommendations.append("Enable PowerShell script block logging")
            recommendations.append("Implement PowerShell constrained language mode")
            recommendations.append("Review and remove malicious scripts")

        if "lolbin_abuse" in activity_types:
            recommendations.append("Block execution via AppLocker/WDAC")
            recommendations.append("Investigate parent process chain")
            recommendations.append("Isolate affected system")

        if "scheduled_task_persistence" in activity_types:
            recommendations.append("Delete malicious scheduled task")
            recommendations.append("Review all scheduled tasks on system")
            recommendations.append("Investigate task creator account")

        if "registry_persistence" in activity_types:
            recommendations.append("Remove malicious registry key")
            recommendations.append("Scan system for additional persistence")
            recommendations.append("Enable Sysmon registry monitoring")

        if "wmi_persistence" in activity_types:
            recommendations.append("Remove WMI event subscription")
            recommendations.append("Enable WMI auditing")
            recommendations.append("Investigate for additional backdoors")

        return recommendations
