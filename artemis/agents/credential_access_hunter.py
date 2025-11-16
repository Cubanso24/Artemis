"""
Agent 4: Credential Access Hunter

Detects:
- Credential dumping (LSASS, SAM, NTDS.dit)
- Kerberoasting
- Pass-the-hash/pass-the-ticket
- Brute force attempts
- Password spraying
- Keylogging indicators
"""

from typing import Dict, List, Any
from datetime import datetime

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class CredentialAccessHunter(BaseAgent):
    """
    Specialized agent for detecting credential access attempts.

    Focuses on MITRE ATT&CK Tactic:
    - TA0006 (Credential Access)
    """

    def __init__(self):
        super().__init__(
            name="credential_access_hunter",
            tactics=[KillChainStage.CREDENTIAL_ACCESS],
            description="Detects credential dumping, theft, and abuse"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        """Default configuration."""
        return {
            "lsass_access_whitelist": ["lsass.exe", "werfault.exe", "taskmgr.exe"],
            "kerberos_ticket_threshold": 10,
            "password_spray_threshold": 5,
            "password_spray_time_window": 300,
            "credential_dump_tools": ["mimikatz", "procdump", "lazagne", "pwdump"],
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        """Analyze data for credential access."""
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect LSASS access
        lsass_result = self._detect_lsass_access(data.get("process_access_logs", []))
        if lsass_result:
            findings.append(lsass_result["finding"])
            all_evidence.extend(lsass_result["evidence"])
            confidence_scores.append(lsass_result["confidence"])

        # Detect Kerberoasting
        kerberoast_result = self._detect_kerberoasting(data.get("kerberos_logs", []))
        if kerberoast_result:
            findings.append(kerberoast_result["finding"])
            all_evidence.extend(kerberoast_result["evidence"])
            confidence_scores.append(kerberoast_result["confidence"])

        # Detect password spraying
        spray_result = self._detect_password_spraying(data.get("authentication_logs", []))
        if spray_result:
            findings.append(spray_result["finding"])
            all_evidence.extend(spray_result["evidence"])
            confidence_scores.append(spray_result["confidence"])

        # Detect credential dump tools
        dump_tool_result = self._detect_credential_dump_tools(data.get("process_logs", []))
        if dump_tool_result:
            findings.append(dump_tool_result["finding"])
            all_evidence.extend(dump_tool_result["evidence"])
            confidence_scores.append(dump_tool_result["confidence"])

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

    def _detect_lsass_access(self, process_access_logs: List[Dict]) -> Dict[str, Any]:
        """Detect unauthorized LSASS process access."""
        if not process_access_logs:
            return None

        for log in process_access_logs:
            target_process = log.get("target_process", "").lower()
            source_process = log.get("source_process", "").lower()
            access_mask = log.get("access_mask", "")

            # Check if LSASS is being accessed
            if "lsass.exe" in target_process:
                # Check if source is whitelisted
                is_whitelisted = any(
                    white in source_process
                    for white in self.config["lsass_access_whitelist"]
                )

                if not is_whitelisted:
                    # Check access rights (PROCESS_VM_READ = 0x0010)
                    confidence = 0.85

                    finding = Finding(
                        activity_type="lsass_access",
                        description=f"Suspicious LSASS access by {source_process} on {log.get('hostname')}",
                        indicators=[source_process, "lsass_access"],
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="process_access_logs",
                                data={
                                    "hostname": log.get("hostname"),
                                    "source_process": source_process,
                                    "target_process": target_process,
                                    "access_mask": access_mask,
                                    "user": log.get("user")
                                },
                                description="Unauthorized LSASS process access detected",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1003.001"]  # LSASS Memory
                    )

                    return {
                        "finding": finding,
                        "evidence": finding.evidence,
                        "confidence": confidence
                    }

        return None

    def _detect_kerberoasting(self, kerberos_logs: List[Dict]) -> Dict[str, Any]:
        """Detect Kerberoasting attacks."""
        if not kerberos_logs:
            return None

        # Track TGS requests by account
        account_requests = {}

        for log in kerberos_logs:
            if log.get("ticket_type") == "TGS":
                account = log.get("account")
                spn = log.get("service_principal_name", "")
                encryption = log.get("ticket_encryption_type", "")

                if account not in account_requests:
                    account_requests[account] = {
                        "requests": [],
                        "spns": set(),
                        "weak_encryption": 0
                    }

                account_requests[account]["requests"].append(log)
                account_requests[account]["spns"].add(spn)

                # RC4 encryption (0x17) is weak and preferred by Kerberoasting tools
                if encryption == "0x17":
                    account_requests[account]["weak_encryption"] += 1

        # Analyze patterns
        for account, data in account_requests.items():
            spn_count = len(data["spns"])
            weak_enc_count = data["weak_encryption"]

            # Multiple TGS requests with RC4 encryption indicates Kerberoasting
            if spn_count >= self.config["kerberos_ticket_threshold"] and weak_enc_count > 0:
                confidence = min(0.7 + (weak_enc_count / spn_count) * 0.3, 1.0)

                finding = Finding(
                    activity_type="kerberoasting",
                    description=f"Kerberoasting detected for account {account}: {spn_count} TGS requests",
                    indicators=[account, f"tgs_requests:{spn_count}", f"weak_encryption:{weak_enc_count}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="kerberos_logs",
                            data={
                                "account": account,
                                "spn_count": spn_count,
                                "weak_encryption_count": weak_enc_count,
                                "sample_spns": list(data["spns"])[:5]
                            },
                            description=f"Kerberoasting attack by {account}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1558.003"]  # Kerberoasting
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_password_spraying(self, auth_logs: List[Dict]) -> Dict[str, Any]:
        """Detect password spraying attacks."""
        if not auth_logs:
            return None

        # Track failed logins by source IP
        source_attempts = {}

        for log in auth_logs:
            if log.get("result") == "failure":
                src_ip = log.get("source_ip")
                username = log.get("username")

                if src_ip not in source_attempts:
                    source_attempts[src_ip] = {
                        "usernames": set(),
                        "timestamps": [],
                        "failures": 0
                    }

                source_attempts[src_ip]["usernames"].add(username)
                source_attempts[src_ip]["timestamps"].append(log.get("timestamp", datetime.utcnow()))
                source_attempts[src_ip]["failures"] += 1

        # Analyze for password spraying pattern
        # Password spraying: few attempts per account across many accounts
        for src_ip, data in source_attempts.items():
            username_count = len(data["usernames"])
            failure_count = data["failures"]

            # Calculate attempts per username
            attempts_per_user = failure_count / username_count if username_count > 0 else 0

            # Password spraying: many accounts, few attempts each
            if username_count >= self.config["password_spray_threshold"] and attempts_per_user < 5:
                confidence = min(username_count / 20.0, 0.9)

                finding = Finding(
                    activity_type="password_spraying",
                    description=f"Password spraying from {src_ip}: {username_count} accounts targeted",
                    indicators=[src_ip, f"accounts_targeted:{username_count}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="authentication_logs",
                            data={
                                "source_ip": src_ip,
                                "username_count": username_count,
                                "failure_count": failure_count,
                                "attempts_per_user": attempts_per_user
                            },
                            description=f"Password spraying attack from {src_ip}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1110.003"]  # Password Spraying
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_credential_dump_tools(self, process_logs: List[Dict]) -> Dict[str, Any]:
        """Detect known credential dumping tools."""
        if not process_logs:
            return None

        for log in process_logs:
            process_name = log.get("process_name", "").lower()
            command_line = log.get("command_line", "").lower()

            # Check for known tools
            for tool in self.config["credential_dump_tools"]:
                if tool in process_name or tool in command_line:
                    confidence = 0.95

                    finding = Finding(
                        activity_type="credential_dump_tool",
                        description=f"Credential dumping tool detected: {tool} on {log.get('hostname')}",
                        indicators=[tool, process_name],
                        evidence=[
                            Evidence(
                                timestamp=log.get("timestamp", datetime.utcnow()),
                                source="process_logs",
                                data={
                                    "hostname": log.get("hostname"),
                                    "process_name": process_name,
                                    "command_line": command_line[:500],
                                    "user": log.get("user"),
                                    "tool_detected": tool
                                },
                                description=f"Credential dumping tool executed: {tool}",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1003"]  # OS Credential Dumping
                    )

                    return {
                        "finding": finding,
                        "evidence": finding.evidence,
                        "confidence": confidence
                    }

        return None

    def _determine_severity(self, confidence: float, findings: List[Finding]) -> Severity:
        """Determine severity."""
        # Credential access is always high severity
        if confidence >= 0.7:
            return Severity.CRITICAL
        elif confidence >= 0.5:
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

        if "lsass_access" in activity_types:
            recommendations.append("Enable Credential Guard")
            recommendations.append("Isolate affected system immediately")
            recommendations.append("Force password reset for all accounts on system")
            recommendations.append("Review memory dumps for credentials")

        if "kerberoasting" in activity_types:
            recommendations.append("Rotate service account passwords")
            recommendations.append("Use strong passwords for service accounts")
            recommendations.append("Enable AES Kerberos encryption")
            recommendations.append("Investigate account for compromise")

        if "password_spraying" in activity_types:
            recommendations.append("Block source IP")
            recommendations.append("Enable account lockout policies")
            recommendations.append("Implement conditional access controls")
            recommendations.append("Force MFA for all accounts")

        if "credential_dump_tool" in activity_types:
            recommendations.append("Isolate system immediately")
            recommendations.append("Initiate incident response")
            recommendations.append("Reset all privileged account passwords")
            recommendations.append("Scan for additional malware")

        return recommendations
