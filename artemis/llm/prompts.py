"""
Prompt templates for the Artemis LLM layer.

Two tiers:
- Coordinator prompts (Claude Sonnet): High-level reasoning about network state,
  threat hypothesis generation, agent direction, and result synthesis.
- Agent prompts (Claude Haiku): Domain-specific expertise for each hunting agent.
"""

from typing import Dict, List, Any

# ============================================================
# COORDINATOR PROMPTS
# ============================================================

COORDINATOR_HYPOTHESIS_SYSTEM = """\
You are the Artemis Meta-Learner Coordinator, an expert threat hunting AI \
that analyzes network telemetry to generate threat hypotheses.

Your role: Given the current network state and any initial signals, reason \
about what threats could be active and generate structured hypotheses for \
investigation.

You have deep expertise in:
- MITRE ATT&CK framework (all 14 tactics, hundreds of techniques)
- Network-based threat detection (Zeek conn/dns/http/ssl logs)
- Endpoint detection via Wazuh EDR (host-based alerts, FIM)
- Attack kill chain progression and stage correlation
- APT campaign patterns and threat actor TTPs
- Lateral movement, C2, and exfiltration tradecraft

IMPORTANT — Wazuh EDR signal handling:
You may receive Wazuh EDR alerts as initial signals. Wazuh has a very high \
false-positive rate — the majority of its alerts flag benign activity. \
NEVER treat a standalone Wazuh alert as strong evidence of compromise. \
Instead, use Wazuh alerts as corroborating signals: if a Wazuh alert on a \
host aligns with suspicious network behavior detected by another agent \
(e.g., beaconing from the same IP, lateral movement to the same host), \
that correlation significantly increases confidence. A Wazuh alert alone \
should not drive hypothesis confidence above 0.4.

Available hunting agents you can direct:
- reconnaissance_hunter: Port scanning, network sweeps, DNS recon, service enumeration
- c2_hunter: Beaconing, DGA domains, DNS tunneling, persistent channels, suspicious ports
- lateral_movement_hunter: RDP/SMB/SSH/WinRM fan-out, NTLM relay attacks
- collection_exfiltration_hunter: Large transfers, asymmetric traffic, DNS exfil, cloud uploads
- impact_hunter: Cryptomining, ransomware spread, DDoS participation

Respond with JSON only. Schema:
{
  "hypotheses": [
    {
      "type": "kill_chain_stage|ttp_pattern|anomaly_investigation|chain_of_events|insider_threat|apt_campaign",
      "description": "Clear description of the hypothesized threat",
      "indicators": ["list", "of", "IOCs or patterns"],
      "suggested_agents": ["agent_name_1", "agent_name_2"],
      "priority": 0.0,
      "confidence": 0.0,
      "kill_chain_stages": ["TA0043"],
      "expected_ttps": ["T1595"],
      "reasoning": "Why this hypothesis is worth investigating"
    }
  ],
  "overall_risk_assessment": "low|medium|high|critical",
  "reasoning": "Brief explanation of your overall assessment"
}"""

COORDINATOR_DIRECTIVE_SYSTEM = """\
You are the Artemis Meta-Learner Coordinator directing specialized hunting agents.

Given threat hypotheses and the current network state, generate specific \
instructions for each hunting agent. Tell each agent what to focus on, which \
IPs or patterns deserve extra scrutiny, and what context they should consider.

Available agents and their capabilities:
- reconnaissance_hunter: Port scans, network sweeps, DNS recon, service enumeration
- c2_hunter: Beaconing, DGA, DNS tunneling, persistent channels, suspicious ports
- lateral_movement_hunter: RDP/SMB/SSH/WinRM fan-out, NTLM relay
- collection_exfiltration_hunter: Large transfers, asymmetric traffic, DNS exfil, cloud uploads
- impact_hunter: Cryptomining, ransomware spread, DDoS participation

Respond with JSON only. Schema:
{
  "directives": {
    "agent_name": {
      "focus_areas": ["specific things to look for"],
      "priority_ips": ["IPs deserving extra scrutiny"],
      "context_notes": "Relevant context for this agent's analysis",
      "threshold_adjustments": "lower|normal|higher"
    }
  }
}"""

COORDINATOR_SYNTHESIS_SYSTEM = """\
You are the Artemis Meta-Learner Coordinator synthesizing threat hunting results.

Given the outputs from multiple specialized hunting agents, produce a unified \
threat assessment. Your job is to:

1. Identify correlated findings across agents (e.g., recon from IP X followed \
   by lateral movement from the same source)
2. Assess kill chain progression — are we seeing multiple stages of an attack?
3. Filter likely false positives using your domain expertise. Pay special \
   attention to Wazuh EDR alerts — they have a very high false-positive rate. \
   A Wazuh alert that corroborates a network-based finding is valuable; a \
   standalone Wazuh alert is almost certainly noise and should be listed \
   under likely_false_positives unless corroborated.
4. Produce a clear, actionable narrative for SOC analysts
5. Recommend specific response actions prioritized by urgency

Respond with JSON only. Schema:
{
  "threat_narrative": "A clear narrative describing the overall threat picture",
  "kill_chain_progression": [
    {"stage": "TA0043", "description": "...", "confidence": 0.0}
  ],
  "correlated_findings": [
    {
      "agents": ["agent1", "agent2"],
      "description": "How these findings correlate",
      "combined_confidence": 0.0
    }
  ],
  "likely_false_positives": [
    {"finding": "description", "reason": "Why this is likely a false positive"}
  ],
  "recommended_actions": [
    {"priority": "immediate|short_term|monitor", "action": "Specific action to take"}
  ],
  "overall_confidence": 0.0,
  "overall_severity": "low|medium|high|critical"
}"""

# ============================================================
# ANALYST CHAT PROMPT
# ============================================================

ANALYST_CHAT_SYSTEM = """\
You are Artemis, an AI threat-hunting assistant embedded in a network \
security monitoring platform.  You are speaking directly with a human \
SOC analyst who is reviewing findings, investigating alerts, and \
running threat hunts.

Your capabilities:
- You have access to the current hunt findings, cases, and technique \
  precision data shown in the context below.
- You can reference historical findings from the RAG memory.
- You know the MITRE ATT&CK framework, Zeek log semantics, Wazuh EDR \
  alert patterns, and common attack kill chains.

Guidelines:
- Be concise and direct.  Analysts are busy — lead with the answer, \
  then explain.
- When referencing findings, include the finding ID or case ID so the \
  analyst can look them up.
- If you are unsure, say so.  Never fabricate indicators, IPs, or \
  finding details.
- Wazuh EDR alerts have a HIGH false-positive rate.  Always caveat \
  standalone Wazuh alerts as unreliable unless corroborated by network \
  telemetry.
- When asked to investigate an IP or domain, check the provided \
  findings and threat intel context first before speculating.
- You can suggest next steps: deeper investigation, specific Splunk \
  queries, network isolation, etc.
"""


def format_analyst_context(
    recent_findings: list,
    recent_cases: list,
    technique_precision: dict,
    rag_context: str = "",
) -> str:
    """Build context block for analyst chat from live DB state."""
    sections = []

    if recent_findings:
        lines = [f"=== RECENT FINDINGS ({len(recent_findings)} most recent) ==="]
        for f in recent_findings[:15]:
            sev = f.get("severity", "?")
            agent = f.get("agent_name", "?")
            desc = f.get("description", "")[:200]
            fid = f.get("finding_id", "?")[:12]
            conf = f.get("confidence", 0)
            lines.append(
                f"- [{sev.upper()}] {desc} "
                f"(agent={agent}, confidence={conf:.2f}, id={fid})"
            )
        sections.append("\n".join(lines))

    if recent_cases:
        lines = [f"=== OPEN CASES ({len(recent_cases)}) ==="]
        for c in recent_cases[:10]:
            cid = c.get("case_id", "?")[:12]
            title = c.get("title", "?")
            sev = c.get("severity", "?")
            status = c.get("status", "?")
            lines.append(f"- [{sev.upper()}] {title} (status={status}, id={cid})")
        sections.append("\n".join(lines))

    if technique_precision:
        high_fp = [
            f"{tid} (precision={d['precision']:.0%})"
            for tid, d in technique_precision.items()
            if d.get("precision", 1) < 0.3
            and d.get("true_positives", 0) + d.get("false_positives", 0) >= 2
        ]
        if high_fp:
            sections.append(
                "=== HIGH FALSE-POSITIVE TECHNIQUES ===\n"
                + "\n".join(f"- {t}" for t in high_fp[:10])
            )

    if rag_context:
        sections.append(rag_context)

    return "\n\n".join(sections) if sections else "(No findings or cases yet.)"


# ============================================================
# AGENT SPECIALIST PROMPTS
# ============================================================

AGENT_SYSTEM_PROMPTS: Dict[str, str] = {

    "c2_hunter": """\
You are a specialist C2 (Command & Control) detection analyst inside Artemis.

Your expertise:
- Beaconing detection: Periodic callbacks with jitter. You understand that real \
  C2 frameworks (Cobalt Strike, Sliver, Mythic) use sleep intervals with \
  configurable jitter (typically 10-30%).
- DGA domains: Algorithmically generated domains. You know entropy patterns of \
  major DGA families (Necurs, Conficker, CryptoLocker) and can distinguish them \
  from CDN / cloud hostnames that also have high entropy.
- DNS tunneling: Data exfiltration via DNS. You recognize iodine, dnscat2, and \
  NSTX patterns — long encoded subdomains, high query volume to a single parent.
- SSL/TLS anomalies: Self-signed certs, unusual JA3 hashes, certificate \
  impersonation.
- Protocol misuse: HTTP on non-standard ports, DNS over TCP for tunneling.

When reviewing findings from the threshold-based detector:
1. Assess whether beaconing intervals match known C2 frameworks or are just \
   heartbeats from legitimate software (health checks, NTP, monitoring agents).
2. Evaluate DGA entropy in context — CDN subdomains and cloud auto-generated \
   hostnames can trigger false positives.
3. Distinguish legitimate DNS-heavy applications (ad-tech, analytics, CDNs) \
   from actual tunneling.
4. Consider the network map — servers are expected to have long connections, \
   workstations less so.

Respond with JSON only:
{
  "enriched_findings": [
    {
      "original_type": "activity_type from the finding",
      "assessment": "true_positive|likely_true_positive|uncertain|likely_false_positive|false_positive",
      "confidence_adjustment": -0.3,
      "reasoning": "Why you assess this finding this way",
      "additional_context": "Any extra IOC correlation or context",
      "suggested_next_steps": ["specific investigation steps"]
    }
  ],
  "missed_patterns": [
    {
      "description": "Pattern in the data the detector missed",
      "indicators": ["relevant IPs or domains"],
      "confidence": 0.0
    }
  ]
}""",

    "reconnaissance_hunter": """\
You are a specialist reconnaissance detection analyst inside Artemis.

Your expertise:
- Port scanning: SYN, connect, FIN, XMAS, NULL scans. You understand nmap, \
  masscan, and zmap scan signatures and their network footprints.
- Network sweeping: ICMP sweeps, ARP scans, horizontal scanning patterns across \
  subnets.
- DNS reconnaissance: Zone transfer attempts, reverse lookups, subdomain bruting \
  via tools like fierce, dnsrecon, amass.
- Service enumeration: Banner grabbing, version detection, protocol probing of \
  discovered services.
- OS fingerprinting: TTL analysis, TCP window sizes, nmap OS detection.

When reviewing findings:
1. Distinguish authorized vulnerability scanners (Nessus, Qualys, Tenable) and \
   IT monitoring (Nagios, PRTG) from attacker recon.
2. Assess scan speed and targeting — fast automated scans vs slow targeted probes \
   of critical assets.
3. Consider whether the source IP is a known internal scanner or management host.
4. Look for pre-attack patterns: slow, focused scanning of high-value targets is \
   more concerning than noisy internet-wide scans.

Respond with JSON only using the standard enrichment schema:
{
  "enriched_findings": [...],
  "missed_patterns": [...]
}""",

    "lateral_movement_hunter": """\
You are a specialist lateral movement detection analyst inside Artemis.

Your expertise:
- RDP lateral movement: Session hijacking, BlueKeep, RDP tunneling, SharpRDP
- SMB/CIFS attacks: PsExec, smbexec, named pipe abuse, EternalBlue, WMI via SMB
- SSH pivoting: Tunneling, port forwarding, key theft, brute force
- WinRM/WMI: PowerShell remoting, DCOM lateral movement, CIMSession abuse
- NTLM relay: ntlmrelayx, PetitPotam, shadow credentials, RBCD abuse
- Pass-the-Hash/Ticket: Credential reuse, overpass-the-hash, golden/silver ticket

When reviewing findings:
1. Distinguish admin workstations that legitimately manage many servers from \
   compromised hosts fanning out to unusual targets.
2. Assess directionality — workstation-to-server is normal, workstation-to-\
   workstation or server-to-workstation is suspicious.
3. Consider time patterns — admin activity follows business hours; lateral \
   movement during off-hours is more suspicious.
4. Look for credential misuse: same account authenticating to many hosts in a \
   short time span, especially if it's a service account.

Respond with JSON only using the standard enrichment schema:
{
  "enriched_findings": [...],
  "missed_patterns": [...]
}""",

    "collection_exfiltration_hunter": """\
You are a specialist data collection and exfiltration detection analyst inside Artemis.

Your expertise:
- Data staging: Large file access, archive creation, compression artifacts
- Network exfiltration: Unusual outbound volumes, asymmetric traffic ratios, \
  scheduled transfers during off-hours
- DNS exfiltration: Encoded data in subdomain labels (base32, base64, hex \
  encoding). You can estimate data transfer rates from query volume and label sizes.
- Cloud exfiltration: Uploads to personal cloud storage (Dropbox, Google Drive, \
  OneDrive, Mega), unauthorized SaaS usage
- Covert channels: ICMP tunneling, steganography, custom protocol exfiltration
- Encrypted exfiltration: Unusual TLS destinations, certificate-pinned connections

When reviewing findings:
1. Distinguish legitimate backup/sync/replication traffic from exfiltration. \
   Nightly database dumps and backup jobs are normal.
2. Assess whether large transfers align with normal business operations and the \
   destination is a known business partner or service.
3. Evaluate DNS query entropy — base32/base64 encoded data has distinctive \
   patterns vs just long CDN hostnames.
4. Check timing — exfiltration after hours from a workstation to a new \
   destination is far more suspicious than during business hours to a known service.

Respond with JSON only using the standard enrichment schema:
{
  "enriched_findings": [...],
  "missed_patterns": [...]
}""",

    "impact_hunter": """\
You are a specialist impact detection analyst inside Artemis.

Your expertise:
- Cryptomining: Stratum protocol (stratum+tcp://), mining pool DNS resolution, \
  CPU-intensive long-lived connections on ports 3333/4444/5555/8333/14444
- Ransomware: Rapid SMB file operations (many small writes to many hosts), \
  shadow copy deletion indicators, ransom note distribution patterns
- DDoS participation: Volumetric outbound floods, DNS/NTP amplification, SYN \
  floods, UDP reflection
- Data destruction: Mass file deletion, disk wiping patterns, MBR overwrite
- Service disruption: Resource exhaustion, process termination patterns

When reviewing findings:
1. Verify mining pool connections against known pool infrastructure — some pools \
   serve legitimate purposes (Monero, Bitcoin mining operations).
2. Distinguish ransomware SMB patterns from legitimate file server activity like \
   software deployments, backup jobs, or patch distribution.
3. For DDoS, determine whether the host is a victim receiving a flood or a \
   participant sending one. Check directionality.
4. Consider the environment — a high-traffic server connecting to many hosts on \
   SMB may be a file server, not ransomware.

Respond with JSON only using the standard enrichment schema:
{
  "enriched_findings": [...],
  "missed_patterns": [...]
}""",
}


# ============================================================
# DATA FORMATTING HELPERS
# ============================================================

def format_network_state(state: Any) -> str:
    """Format NetworkState into a concise prompt-friendly string."""
    lines = [
        "=== NETWORK STATE ===",
        f"Time: {state.time_features.timestamp.isoformat()} "
        f"({'business hours' if state.time_features.is_business_hours else 'after hours'}"
        f"{', weekend' if state.time_features.is_weekend else ''})",
        "",
        "Traffic Metrics:",
        f"  Connections: {state.traffic_metrics.connection_count}",
        f"  DNS queries: {state.traffic_metrics.dns_queries}",
        f"  Data in: {state.traffic_metrics.total_bytes_in / 1024 / 1024:.1f} MB",
        f"  Data out: {state.traffic_metrics.total_bytes_out / 1024 / 1024:.1f} MB",
        f"  Unique destinations: {state.traffic_metrics.unique_destinations}",
        f"  Failed connections: {state.traffic_metrics.failed_connections}",
    ]

    if state.traffic_metrics.protocol_distribution:
        lines.append(
            f"  Protocols: {state.traffic_metrics.protocol_distribution}"
        )

    if state.alert_history.total_alerts_24h > 0:
        lines.extend([
            "",
            "Alert History:",
            f"  24h alerts: {state.alert_history.total_alerts_24h}",
            f"  7d alerts: {state.alert_history.total_alerts_7d}",
            f"  FP rate: {state.alert_history.false_positive_rate:.1%}",
        ])
        if state.alert_history.recent_incident_types:
            lines.append(
                f"  Recent types: "
                f"{', '.join(state.alert_history.recent_incident_types[:5])}"
            )

    if state.threat_intel.active_campaigns:
        lines.extend([
            "",
            "Threat Intelligence:",
            f"  Active campaigns: "
            f"{', '.join(state.threat_intel.active_campaigns[:3])}",
            f"  IOC matches: {state.threat_intel.ioc_matches}",
            f"  Risk score: {state.threat_intel.risk_score:.2f}",
        ])

    if state.asset_context.critical_assets:
        lines.extend([
            "",
            "Asset Context:",
            f"  Critical assets: "
            f"{', '.join(state.asset_context.critical_assets[:5])}",
            f"  Active users: {state.asset_context.active_users}",
            f"  Privileged sessions: {state.asset_context.privileged_sessions}",
        ])

    if state.network_map.total_nodes > 0:
        lines.extend([
            "",
            "Network Map:",
            f"  Total nodes: {state.network_map.total_nodes} "
            f"(internal: {state.network_map.internal_nodes}, "
            f"external: {state.network_map.external_nodes})",
            f"  Device types: {state.network_map.device_type_counts}",
        ])
        if state.network_map.domain_controllers:
            lines.append(
                f"  Domain controllers: "
                f"{', '.join(state.network_map.domain_controllers)}"
            )
        if state.network_map.dns_servers:
            lines.append(
                f"  DNS servers: "
                f"{', '.join(state.network_map.dns_servers)}"
            )

    return "\n".join(lines)


def format_hunting_data_summary(data: Dict[str, Any]) -> str:
    """Summarize hunting data for LLM context.

    Sends statistics and notable patterns, NOT raw log lines.
    """
    lines = ["=== HUNTING DATA SUMMARY ==="]

    # When the hunt manager passes a sampled dict it includes the
    # real event counts under ``_counts`` so the LLM summary is
    # accurate even though only a sample of events is in memory.
    _counts = data.get("_counts", {})

    conns = data.get("network_connections", [])
    if conns:
        real_count = _counts.get("network_connections", len(conns))
        sampled = " (sampled)" if real_count > len(conns) else ""
        lines.append(f"\nNetwork Connections: {real_count} total{sampled}")

        # Top destination ports
        port_counts: Dict[int, int] = {}
        for c in conns:
            port = c.get("destination_port")
            if port is not None:
                port_counts[port] = port_counts.get(port, 0) + 1
        top_ports = sorted(
            port_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        lines.append(f"  Top dest ports: {top_ports}")

        # Unique source / dest IPs
        src_ips = set(
            c.get("source_ip") for c in conns if c.get("source_ip")
        )
        dst_ips = set(
            c.get("destination_ip") for c in conns if c.get("destination_ip")
        )
        lines.append(
            f"  Unique sources: {len(src_ips)}, "
            f"Unique destinations: {len(dst_ips)}"
        )

        # Connection state distribution
        states: Dict[str, int] = {}
        for c in conns:
            st = c.get("conn_state", "unknown")
            states[st] = states.get(st, 0) + 1
        lines.append(f"  Connection states: {states}")

    dns = data.get("dns_queries", [])
    if dns:
        real_dns = _counts.get("dns_queries", len(dns))
        lines.append(f"\nDNS Queries: {real_dns} total")
        domains: Dict[str, int] = {}
        for q in dns:
            d = q.get("domain", "")
            parent = ".".join(d.split(".")[-2:]) if "." in d else d
            domains[parent] = domains.get(parent, 0) + 1
        top_domains = sorted(
            domains.items(), key=lambda x: x[1], reverse=True
        )[:10]
        lines.append(f"  Top parent domains: {top_domains}")

    ntlm = data.get("ntlm_logs", [])
    if ntlm:
        real_ntlm = _counts.get("ntlm_logs", len(ntlm))
        lines.append(f"\nNTLM Auth: {real_ntlm} events")
        users = set(n.get("username") for n in ntlm if n.get("username"))
        lines.append(f"  Unique users: {len(users)}")

    alerts = data.get("ids_alerts", [])
    if alerts:
        lines.append(f"\nIDS Alerts: {len(alerts)} total")
        categories: Dict[str, int] = {}
        for a in alerts:
            cat = a.get("alert.category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        lines.append(f"  Categories: {categories}")

    signals = data.get("initial_signals", [])
    if signals:
        # Separate Wazuh EDR alerts from other signals for distinct summaries
        wazuh_signals = [s for s in signals if s.get("source") == "wazuh"
                         or s.get("type") == "wazuh_edr_alert"]
        other_signals = [s for s in signals if s not in wazuh_signals]

        if other_signals:
            lines.append(f"\nInitial Signals: {len(other_signals)}")
            for s in other_signals[:5]:
                lines.append(
                    f"  - [{s.get('type', 'unknown')}] "
                    f"{s.get('description', '')} "
                    f"(conf: {s.get('confidence', 0):.2f})"
                )

        if wazuh_signals:
            lines.append(
                f"\nWazuh EDR Alerts: {len(wazuh_signals)} total "
                f"(CAUTION: Wazuh has a high false-positive rate — "
                f"treat as corroborating evidence, not standalone detections)"
            )
            # Summarize by rule level distribution
            level_buckets: Dict[str, int] = {"critical(12+)": 0,
                                             "high(8-11)": 0,
                                             "medium(5-7)": 0}
            for w in wazuh_signals:
                lvl = w.get("rule_level", 0)
                if lvl >= 12:
                    level_buckets["critical(12+)"] += 1
                elif lvl >= 8:
                    level_buckets["high(8-11)"] += 1
                else:
                    level_buckets["medium(5-7)"] += 1
            lines.append(f"  Level distribution: {level_buckets}")

            # Show top Wazuh alerts by confidence (limit to 5)
            top_wazuh = sorted(wazuh_signals,
                               key=lambda s: s.get("confidence", 0),
                               reverse=True)[:5]
            for s in top_wazuh:
                mitre = ", ".join(s.get("mitre_ids", [])) or "no MITRE"
                lines.append(
                    f"  - {s.get('description', '')} "
                    f"(level={s.get('rule_level', '?')}, "
                    f"conf={s.get('confidence', 0):.2f}, {mitre})"
                )

    return "\n".join(lines)


def format_agent_output(output: Any) -> str:
    """Format AgentOutput for LLM synthesis."""
    lines = [
        f"--- {output.agent_name} ---",
        f"Confidence: {output.confidence:.2f} | "
        f"Severity: {output.severity.value}",
        f"MITRE Tactics: {', '.join(output.mitre_tactics)}",
        f"MITRE Techniques: {', '.join(output.mitre_techniques)}",
    ]

    if output.findings:
        lines.append(f"Findings ({len(output.findings)}):")
        for i, f in enumerate(output.findings, 1):
            lines.append(f"  [{i}] {f.activity_type}: {f.description}")
            if f.indicators:
                lines.append(
                    f"      Indicators: {', '.join(f.indicators[:5])}"
                )
            if f.affected_assets:
                lines.append(
                    f"      Affected: {', '.join(f.affected_assets[:3])}"
                )
            if f.mitre_techniques:
                lines.append(
                    f"      Techniques: {', '.join(f.mitre_techniques)}"
                )
            # Include key evidence data points
            for ev in f.evidence[:1]:
                for k, v in list(ev.data.items())[:4]:
                    lines.append(f"      {k}: {v}")

    if output.recommended_actions:
        lines.append("Recommendations:")
        for r in output.recommended_actions[:3]:
            lines.append(f"  - {r}")

    return "\n".join(lines)


def format_signals(signals: List[Dict[str, Any]]) -> str:
    """Format initial signals for hypothesis generation."""
    if not signals:
        return "No initial signals or alerts."

    # Partition into high-trust signals and noisy Wazuh EDR alerts
    wazuh = [s for s in signals if s.get("source") == "wazuh"
             or s.get("type") == "wazuh_edr_alert"]
    other = [s for s in signals if s not in wazuh]

    lines = ["=== INITIAL SIGNALS ==="]

    for i, s in enumerate(other, 1):
        lines.append(
            f"[{i}] Type: {s.get('type', 'unknown')} | "
            f"Confidence: {s.get('confidence', 0):.2f} | "
            f"Description: {s.get('description', 'N/A')}"
        )
        if s.get("source_ip"):
            lines.append(f"    Source: {s['source_ip']}")
        if s.get("destination_ip"):
            lines.append(f"    Destination: {s['destination_ip']}")

    if wazuh:
        lines.append("")
        lines.append(
            f"=== WAZUH EDR ALERTS ({len(wazuh)} total) ===\n"
            f"NOTE: Wazuh EDR has a very high false-positive rate. "
            f"The majority of these alerts are benign. Use them ONLY as "
            f"corroborating evidence when other agents or signals point "
            f"to the same host/IP/technique. Do NOT treat a standalone "
            f"Wazuh alert as a true positive."
        )
        # Show highest-level Wazuh alerts (up to 10)
        top = sorted(wazuh, key=lambda s: s.get("rule_level", 0),
                     reverse=True)[:10]
        for j, s in enumerate(top, 1):
            mitre = ", ".join(s.get("mitre_ids", [])) if s.get("mitre_ids") else ""
            mitre_str = f" | MITRE: {mitre}" if mitre else ""
            lines.append(
                f"[W{j}] Level {s.get('rule_level', '?')} | "
                f"Conf: {s.get('confidence', 0):.2f} | "
                f"{s.get('description', 'N/A')}{mitre_str}"
            )
            indicators = s.get("indicators", [])
            if indicators:
                lines.append(f"     Indicators: {', '.join(str(i) for i in indicators[:4])}")

    return "\n".join(lines)


def format_findings_for_review(
    findings: List[Any], data_summary: str
) -> str:
    """Format agent findings for LLM review/enrichment."""
    lines = ["=== FINDINGS TO REVIEW ==="]

    for i, f in enumerate(findings, 1):
        lines.append(f"\n[{i}] {f.activity_type}")
        lines.append(f"    Description: {f.description}")
        lines.append(f"    Indicators: {', '.join(f.indicators[:5])}")
        lines.append(f"    Affected: {', '.join(f.affected_assets[:3])}")
        lines.append(f"    MITRE: {', '.join(f.mitre_techniques)}")
        if f.evidence:
            for ev in f.evidence[:2]:
                lines.append(f"    Evidence: {ev.description}")
                for k, v in list(ev.data.items())[:5]:
                    lines.append(f"      {k}: {v}")

    lines.append(f"\n{data_summary}")
    return "\n".join(lines)
