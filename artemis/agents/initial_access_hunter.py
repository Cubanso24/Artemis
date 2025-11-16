"""
Agent 2: Initial Access & Delivery Hunter

Detects:
- Phishing email detection (attachments, links)
- Exploit delivery mechanisms
- Drive-by download patterns
- Supply chain compromise indicators
- Valid account abuse for initial entry
- External remote service exploitation
"""

from typing import Dict, List, Any
from datetime import datetime
import re

from artemis.agents.base_agent import BaseAgent
from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage


class InitialAccessHunter(BaseAgent):
    """
    Specialized agent for detecting initial access attempts.

    Focuses on MITRE ATT&CK Tactic:
    - TA0001 (Initial Access)
    """

    def __init__(self):
        super().__init__(
            name="initial_access_hunter",
            tactics=[KillChainStage.INITIAL_ACCESS],
            description="Detects phishing, exploits, and initial access attempts"
        )

    def _get_default_config(self) -> Dict[str, Any]:
        """Default configuration."""
        return {
            # Email analysis
            "suspicious_file_extensions": [
                ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1",
                ".js", ".jar", ".hta", ".lnk", ".iso", ".img"
            ],
            "suspicious_keywords": [
                "urgent", "verify account", "click here", "suspended",
                "password reset", "confirm identity", "unusual activity"
            ],

            # Authentication patterns
            "failed_login_threshold": 5,
            "geographic_anomaly_distance_km": 500,
            "impossible_travel_hours": 2,

            # External access
            "known_vpn_ranges": [],
            "blacklisted_countries": [],

            "time_window": 300
        }

    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        """Analyze data for initial access attempts."""
        findings: List[Finding] = []
        all_evidence: List[Evidence] = []
        confidence_scores: List[float] = []

        # Detect phishing emails
        phishing_result = self._detect_phishing(data.get("emails", []))
        if phishing_result:
            findings.append(phishing_result["finding"])
            all_evidence.extend(phishing_result["evidence"])
            confidence_scores.append(phishing_result["confidence"])

        # Detect credential stuffing
        cred_stuffing_result = self._detect_credential_stuffing(data.get("authentication_logs", []))
        if cred_stuffing_result:
            findings.append(cred_stuffing_result["finding"])
            all_evidence.extend(cred_stuffing_result["evidence"])
            confidence_scores.append(cred_stuffing_result["confidence"])

        # Detect geographic anomalies
        geo_anomaly_result = self._detect_geographic_anomaly(data.get("authentication_logs", []))
        if geo_anomaly_result:
            findings.append(geo_anomaly_result["finding"])
            all_evidence.extend(geo_anomaly_result["evidence"])
            confidence_scores.append(geo_anomaly_result["confidence"])

        # Detect exploitation attempts
        exploit_result = self._detect_exploitation(data.get("web_logs", []))
        if exploit_result:
            findings.append(exploit_result["finding"])
            all_evidence.extend(exploit_result["evidence"])
            confidence_scores.append(exploit_result["confidence"])

        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        severity = self._determine_severity(overall_confidence, findings)
        recommendations = self._generate_recommendations(findings)

        return AgentOutput(
            agent_name=self.name,
            confidence=overall_confidence,
            findings=findings,
            evidence=all_evidence,
            severity=severity,
            mitre_tactics=[t.value for t in self.tactics],
            mitre_techniques=self._get_relevant_techniques(findings),
            recommended_actions=recommendations
        )

    def _detect_phishing(self, emails: List[Dict]) -> Dict[str, Any]:
        """Detect phishing emails."""
        if not emails:
            return None

        for email in emails:
            risk_score = 0.0
            indicators = []

            # Check attachments
            attachments = email.get("attachments", [])
            for attachment in attachments:
                ext = attachment.get("extension", "").lower()
                if ext in self.config["suspicious_file_extensions"]:
                    risk_score += 0.3
                    indicators.append(f"suspicious_attachment:{attachment.get('filename')}")

            # Check subject/body for suspicious keywords
            subject = email.get("subject", "").lower()
            body = email.get("body", "").lower()
            for keyword in self.config["suspicious_keywords"]:
                if keyword in subject or keyword in body:
                    risk_score += 0.1
                    indicators.append(f"keyword:{keyword}")

            # Check sender reputation
            sender = email.get("sender")
            if self._is_suspicious_sender(sender, email.get("sender_domain")):
                risk_score += 0.3
                indicators.append(f"suspicious_sender:{sender}")

            # Check for URL shorteners
            if self._contains_url_shortener(body):
                risk_score += 0.2
                indicators.append("url_shortener_detected")

            # If risk score exceeds threshold
            if risk_score >= 0.5:
                confidence = min(risk_score, 1.0)

                finding = Finding(
                    activity_type="phishing_email",
                    description=f"Phishing email detected from {sender}: '{subject}'",
                    indicators=indicators,
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="email_gateway",
                            data={
                                "sender": sender,
                                "subject": subject,
                                "recipients": email.get("recipients", []),
                                "risk_score": risk_score
                            },
                            description=f"Suspicious email from {sender}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1566"]  # Phishing
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_credential_stuffing(self, auth_logs: List[Dict]) -> Dict[str, Any]:
        """Detect credential stuffing attacks."""
        if not auth_logs:
            return None

        # Group by source IP
        source_attempts = {}
        for log in auth_logs:
            src_ip = log.get("source_ip")
            if src_ip not in source_attempts:
                source_attempts[src_ip] = {
                    "attempts": [],
                    "accounts": set(),
                    "failures": 0
                }

            source_attempts[src_ip]["attempts"].append(log)
            source_attempts[src_ip]["accounts"].add(log.get("username"))

            if log.get("result") == "failure":
                source_attempts[src_ip]["failures"] += 1

        # Analyze patterns
        for src_ip, data in source_attempts.items():
            account_count = len(data["accounts"])
            failure_count = data["failures"]

            # Multiple accounts with failures indicates credential stuffing
            if account_count > 5 and failure_count > self.config["failed_login_threshold"]:
                confidence = min(
                    (account_count / 20.0) * 0.5 + (failure_count / 50.0) * 0.5,
                    1.0
                )

                finding = Finding(
                    activity_type="credential_stuffing",
                    description=f"Credential stuffing from {src_ip}: {account_count} accounts, {failure_count} failures",
                    indicators=[src_ip, f"accounts_targeted:{account_count}"],
                    evidence=[
                        Evidence(
                            timestamp=datetime.utcnow(),
                            source="authentication_logs",
                            data={
                                "source_ip": src_ip,
                                "account_count": account_count,
                                "failure_count": failure_count
                            },
                            description=f"Credential stuffing detected from {src_ip}",
                            confidence_contribution=confidence
                        )
                    ],
                    mitre_techniques=["T1110", "T1078"]  # Brute Force, Valid Accounts
                )

                return {
                    "finding": finding,
                    "evidence": finding.evidence,
                    "confidence": confidence
                }

        return None

    def _detect_geographic_anomaly(self, auth_logs: List[Dict]) -> Dict[str, Any]:
        """Detect impossible travel / geographic anomalies."""
        if not auth_logs:
            return None

        # Group by account
        account_logins = {}
        for log in auth_logs:
            account = log.get("username")
            if log.get("result") == "success":
                if account not in account_logins:
                    account_logins[account] = []
                account_logins[account].append(log)

        # Check for impossible travel
        for account, logins in account_logins.items():
            if len(logins) < 2:
                continue

            # Sort by timestamp
            sorted_logins = sorted(logins, key=lambda x: x.get("timestamp", datetime.utcnow()))

            for i in range(len(sorted_logins) - 1):
                current = sorted_logins[i]
                next_login = sorted_logins[i + 1]

                # Check if locations are significantly different
                current_country = current.get("country", "")
                next_country = next_login.get("country", "")

                if current_country != next_country and current_country and next_country:
                    # Calculate time difference
                    time_diff = (next_login.get("timestamp") - current.get("timestamp")).total_seconds() / 3600

                    # If logins from different countries within impossible timeframe
                    if time_diff < self.config["impossible_travel_hours"]:
                        confidence = 0.85

                        finding = Finding(
                            activity_type="impossible_travel",
                            description=f"Impossible travel for {account}: {current_country} to {next_country} in {time_diff:.1f} hours",
                            indicators=[account, current_country, next_country],
                            evidence=[
                                Evidence(
                                    timestamp=datetime.utcnow(),
                                    source="authentication_logs",
                                    data={
                                        "account": account,
                                        "first_location": current_country,
                                        "second_location": next_country,
                                        "time_difference_hours": time_diff
                                    },
                                    description=f"Impossible travel detected for {account}",
                                    confidence_contribution=confidence
                                )
                            ],
                            mitre_techniques=["T1078"]  # Valid Accounts
                        )

                        return {
                            "finding": finding,
                            "evidence": finding.evidence,
                            "confidence": confidence
                        }

        return None

    def _detect_exploitation(self, web_logs: List[Dict]) -> Dict[str, Any]:
        """Detect web exploitation attempts."""
        if not web_logs:
            return None

        # Common exploit patterns
        exploit_patterns = [
            r"(\.\./|\.\.\\)",  # Directory traversal
            r"(union\s+select|union\s+all)",  # SQL injection
            r"(<script|javascript:)",  # XSS
            r"(exec\(|eval\(|system\()",  # Code injection
            r"(\${|<%=|<\?php)",  # Template/code injection
        ]

        for log in web_logs:
            request_uri = log.get("request_uri", "")
            user_agent = log.get("user_agent", "")
            post_data = log.get("post_data", "")

            combined_data = f"{request_uri} {user_agent} {post_data}".lower()

            for pattern in exploit_patterns:
                if re.search(pattern, combined_data, re.IGNORECASE):
                    confidence = 0.75

                    finding = Finding(
                        activity_type="exploitation_attempt",
                        description=f"Web exploitation attempt from {log.get('source_ip')}",
                        indicators=[log.get("source_ip"), pattern],
                        evidence=[
                            Evidence(
                                timestamp=datetime.utcnow(),
                                source="web_logs",
                                data={
                                    "source_ip": log.get("source_ip"),
                                    "request_uri": request_uri[:200],
                                    "pattern_matched": pattern
                                },
                                description="Exploitation pattern detected",
                                confidence_contribution=confidence
                            )
                        ],
                        mitre_techniques=["T1190"]  # Exploit Public-Facing Application
                    )

                    return {
                        "finding": finding,
                        "evidence": finding.evidence,
                        "confidence": confidence
                    }

        return None

    def _is_suspicious_sender(self, sender: str, domain: str) -> bool:
        """Check if sender appears suspicious."""
        if not sender or not domain:
            return False

        # Check for common spoofing patterns
        suspicious_patterns = ["noreply", "admin", "support", "security", "verify"]
        for pattern in suspicious_patterns:
            if pattern in sender.lower():
                return True

        # Check domain age, reputation (simplified)
        # In real implementation, check against threat intel
        return False

    def _contains_url_shortener(self, text: str) -> bool:
        """Check if text contains URL shorteners."""
        shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]
        return any(shortener in text.lower() for shortener in shorteners)

    def _determine_severity(self, confidence: float, findings: List[Finding]) -> Severity:
        """Determine severity."""
        if confidence >= 0.8:
            return Severity.CRITICAL
        elif confidence >= 0.6:
            return Severity.HIGH
        elif confidence >= 0.4:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _get_relevant_techniques(self, findings: List[Finding]) -> List[str]:
        """Extract MITRE techniques."""
        techniques = set()
        for finding in findings:
            techniques.update(finding.mitre_techniques)
        return list(techniques)

    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate recommendations."""
        if not findings:
            return []

        recommendations = []
        activity_types = {f.activity_type for f in findings}

        if "phishing_email" in activity_types:
            recommendations.append("Quarantine email and block sender")
            recommendations.append("Alert recipients and conduct phishing awareness")
            recommendations.append("Update email gateway rules")

        if "credential_stuffing" in activity_types:
            recommendations.append("Block source IP at firewall")
            recommendations.append("Force password resets for affected accounts")
            recommendations.append("Enable MFA for all accounts")

        if "impossible_travel" in activity_types:
            recommendations.append("Disable affected account immediately")
            recommendations.append("Conduct incident response investigation")
            recommendations.append("Review all recent account activity")

        if "exploitation_attempt" in activity_types:
            recommendations.append("Block attacker IP")
            recommendations.append("Patch vulnerable application")
            recommendations.append("Review web application firewall rules")

        return recommendations
