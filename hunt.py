#!/usr/bin/env python3
"""
Artemis Threat Hunting - Network-Focused Hunt
Optimized for environments with Zeek/Suricata network data.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

from artemis.meta_learner.coordinator import MetaLearnerCoordinator
from artemis.integrations.data_pipeline import DataPipeline
from artemis.models.network_state import NetworkState
from artemis.plugins.network_mapper import NetworkMapperPlugin


class HuntAnalyzer:
    """Analyzes and displays hunt results in detail."""

    def __init__(self, output_dir: str = "hunt_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.hunt_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def display_banner(self):
        """Display Artemis banner."""
        print("\n" + "=" * 80)
        print("  █████╗ ██████╗ ████████╗███████╗███╗   ███╗██╗███████╗")
        print(" ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝████╗ ████║██║██╔════╝")
        print(" ███████║██████╔╝   ██║   █████╗  ██╔████╔██║██║███████╗")
        print(" ██╔══██║██╔══██╗   ██║   ██╔══╝  ██║╚██╔╝██║██║╚════██║")
        print(" ██║  ██║██║  ██║   ██║   ███████╗██║ ╚═╝ ██║██║███████║")
        print(" ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝╚══════╝")
        print("           Multi-Agent Threat Hunting System")
        print("=" * 80)

    def print_section(self, title: str):
        """Print a section header."""
        print(f"\n{'─' * 80}")
        print(f"  {title}")
        print(f"{'─' * 80}")

    def print_network_state(self, state: NetworkState):
        """Display the current network state being analyzed."""
        self.print_section("📊 NETWORK STATE ANALYSIS")

        print(f"\n🔍 Network Metrics:")
        print(f"  • Connection Count: {state.traffic_metrics.connection_count}")
        print(f"  • DNS Queries: {state.traffic_metrics.dns_queries}")
        total_bytes = state.traffic_metrics.total_bytes_in + state.traffic_metrics.total_bytes_out
        print(f"  • Total Data Transfer: {total_bytes / 1024 / 1024:.2f} MB")
        print(f"  • Unique Destinations: {state.traffic_metrics.unique_destinations}")
        print(f"  • Failed Connections: {state.traffic_metrics.failed_connections}")

        print(f"\n⏰ Time Context:")
        print(f"  • Hour of Day: {state.time_features.hour_of_day}:00")
        print(f"  • Day of Week: {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'][state.time_features.day_of_week]}")
        print(f"  • Is Business Hours: {'Yes' if state.time_features.is_business_hours else 'No'}")
        print(f"  • Is Weekend: {'Yes' if state.time_features.is_weekend else 'No'}")

        if state.alert_history.total_alerts_24h > 0:
            print(f"\n⚠️  Recent Alerts: {state.alert_history.total_alerts_24h} in last 24h")

    def print_hypotheses(self, hypotheses: list):
        """Display threat hypotheses generated."""
        if not hypotheses:
            print("\n✓ No immediate threat indicators detected")
            return

        self.print_section("🎯 THREAT HYPOTHESES GENERATED")

        for i, hyp in enumerate(hypotheses, 1):
            print(f"\n[{i}] {hyp.description}")
            print(f"    Type: {hyp.hypothesis_type}")
            print(f"    Confidence: {hyp.initial_confidence:.2f}")
            print(f"    Priority: {hyp.priority}")
            if hyp.indicators:
                print(f"    Indicators: {', '.join(hyp.indicators[:3])}")

    def print_agent_selection(self, selected_agents: list):
        """Display which agents were selected and why."""
        self.print_section("🤖 AGENT DEPLOYMENT")

        print(f"\nDeploying {len(selected_agents)} specialized hunting agents:\n")

        agent_descriptions = {
            "ReconnaissanceHunter": "Scanning for port scans, network sweeps, DNS recon",
            "C2Hunter": "Detecting beaconing, DGA domains, suspicious callbacks",
            "LateralMovementHunter": "Tracking SMB/RDP lateral movement patterns",
            "CollectionExfiltrationHunter": "Monitoring large data transfers and exfil",
            "InitialAccessHunter": "Analyzing authentication patterns and access",
            "ExecutionPersistenceHunter": "Checking process execution and persistence",
            "CredentialAccessHunter": "Detecting credential theft attempts",
            "DefenseEvasionHunter": "Finding evasion techniques and anti-forensics",
            "ImpactHunter": "Identifying destructive activities and impacts"
        }

        for agent in selected_agents:
            agent_name = agent.__class__.__name__
            desc = agent_descriptions.get(agent_name, "Specialized threat detection")
            print(f"  ✓ {agent_name:30s} → {desc}")

    def print_findings(self, assessment: dict):
        """Display findings from the hunt assessment."""
        self.print_section("🔍 HUNTING RESULTS")

        total_findings = assessment.get('total_findings', 0)

        if total_findings == 0:
            print("\n✓ No threats detected - Network appears clean")
            return

        print(f"\n⚠️  Found {total_findings} potential threats:\n")

        # Group by severity using agent outputs
        critical = []
        high = []
        medium = []
        low = []

        for agent_output in assessment.get('agent_outputs', []):
            agent_name = agent_output['agent_name']
            severity = agent_output.get('severity', 'low').upper()
            confidence = agent_output.get('confidence', 0)

            for finding in agent_output.get('findings', []):
                entry = (agent_name, finding, confidence)
                if severity == "CRITICAL":
                    critical.append(entry)
                elif severity == "HIGH":
                    high.append(entry)
                elif severity == "MEDIUM":
                    medium.append(entry)
                else:
                    low.append(entry)

        # Display findings by severity
        for severity_name, findings_list, emoji in [
            ("CRITICAL", critical, "🔴"),
            ("HIGH", high, "🟠"),
            ("MEDIUM", medium, "🟡"),
            ("LOW", low, "🔵")
        ]:
            if findings_list:
                print(f"\n{emoji} {severity_name} Severity ({len(findings_list)} findings):")
                for agent_name, finding, confidence in findings_list:
                    print(f"\n  [{agent_name}] {finding.get('activity_type', 'Unknown')}")
                    print(f"  └─ {finding.get('description', 'No description')}")
                    print(f"  └─ Confidence: {confidence:.2f}")
                    if finding.get('mitre_techniques'):
                        print(f"  └─ MITRE: {', '.join(finding['mitre_techniques'])}")
                    if finding.get('affected_assets'):
                        print(f"  └─ Affected: {', '.join(finding['affected_assets'][:3])}")

    def print_aggregated_results(self, assessment: dict):
        """Display meta-learner's aggregated assessment."""
        self.print_section("🧠 META-LEARNER ANALYSIS")

        print(f"\n📈 Overall Threat Assessment:")
        print(f"  • Total Findings: {assessment.get('total_findings', 0)}")
        print(f"  • Overall Confidence: {assessment.get('final_confidence', 0):.2f}")
        print(f"  • Corroborating Agents: {assessment.get('corroborating_agents', 0)}")
        print(f"  • Alert Level: {assessment.get('alert_level', 'none')}")

        if assessment.get('mitre_techniques'):
            print(f"\n🎯 MITRE ATT&CK Techniques Detected:")
            for technique in assessment['mitre_techniques']:
                print(f"  • {technique}")

        if assessment.get('recommendations'):
            print(f"\n📋 Recommendations:")
            for rec in assessment['recommendations']:
                print(f"  • {rec}")

    def save_results(self, assessment: dict, network_state: NetworkState):
        """Save hunt results to JSON for later analysis."""
        output_file = self.output_dir / f"hunt_{self.hunt_timestamp}.json"

        # Serialize severity enum if present
        severity = assessment.get('severity', 'low')
        if hasattr(severity, 'value'):
            severity = severity.value

        hunt_data = {
            "timestamp": self.hunt_timestamp,
            "network_state": {
                "connection_count": network_state.traffic_metrics.connection_count,
                "dns_queries": network_state.traffic_metrics.dns_queries,
                "total_bytes": network_state.traffic_metrics.total_bytes_in + network_state.traffic_metrics.total_bytes_out,
                "unique_destinations": network_state.traffic_metrics.unique_destinations,
                "failed_connections": network_state.traffic_metrics.failed_connections,
                "is_business_hours": network_state.time_features.is_business_hours,
            },
            "total_findings": assessment.get('total_findings', 0),
            "final_confidence": assessment.get('final_confidence', 0),
            "severity": severity,
            "alert_level": assessment.get('alert_level', 'none'),
            "mitre_techniques": assessment.get('mitre_techniques', []),
            "agent_outputs": assessment.get('agent_outputs', []),
            "recommendations": assessment.get('recommendations', [])
        }

        with open(output_file, 'w') as f:
            json.dump(hunt_data, f, indent=2, default=str)

        print(f"\n💾 Results saved to: {output_file}")

        # Also save a summary
        summary_file = self.output_dir / "latest_hunt.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Artemis Hunt Summary - {self.hunt_timestamp}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total Findings: {assessment.get('total_findings', 0)}\n")
            f.write(f"Overall Confidence: {assessment.get('final_confidence', 0):.2f}\n")
            f.write(f"Alert Level: {assessment.get('alert_level', 'none')}\n")
            f.write(f"Agents Deployed: {assessment.get('agent_count', 0)}\n\n")

            for agent_output in assessment.get('agent_outputs', []):
                findings = agent_output.get('findings', [])
                if findings:
                    f.write(f"\n{agent_output['agent_name']}:\n")
                    for finding in findings:
                        f.write(f"  - {finding.get('activity_type', 'Unknown')} ({finding.get('description', '')})\n")

        return output_file


def main():
    """Run a network-focused threat hunt."""

    analyzer = HuntAnalyzer()
    analyzer.display_banner()

    print("\n🚀 Initializing Artemis Threat Hunting System...")

    # Check Splunk credentials
    host = os.getenv('SPLUNK_HOST', '10.25.11.86')
    token = os.getenv('SPLUNK_TOKEN')
    username = os.getenv('SPLUNK_USERNAME')
    password = os.getenv('SPLUNK_PASSWORD')

    if not token and not (username and password):
        print("\n❌ ERROR: Splunk credentials not set!")
        print("   Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD")
        sys.exit(1)

    # Initialize data pipeline (Splunk only, no Security Onion for now)
    print("📡 Connecting to data sources...")
    from artemis.integrations.data_pipeline import DataSourceConfig

    config = DataSourceConfig(
        splunk_host=host,
        splunk_port=8089,
        splunk_username=username if not token else "",
        splunk_password=password if not token else "",
        splunk_token=token if token else ""
    )

    pipeline = DataPipeline(config)

    # Initialize meta-learner coordinator
    print("🧠 Initializing Meta-Learner Coordinator...")
    coordinator = MetaLearnerCoordinator()

    # Collect network data
    analyzer.print_section("📡 COLLECTING NETWORK DATA")
    print("\nQuerying Splunk for network telemetry...")
    print("  • Time range: Last 1 hour")
    print("  • Sources: Zeek (conn, dns, http, ssl), Suricata alerts")

    hunting_data = pipeline.collect_hunting_data(time_range="-1h")

    print(f"\n✓ Collected {sum(len(v) for v in hunting_data.values())} total events")
    print(f"  • Network Connections: {len(hunting_data.get('network_connections', []))}")
    print(f"  • DNS Queries: {len(hunting_data.get('dns_queries', []))}")

    # Create network state for display purposes
    network_state = NetworkState.from_data(hunting_data)
    analyzer.print_network_state(network_state)

    # Run the hunt
    analyzer.print_section("🎯 LAUNCHING THREAT HUNT")
    print("\nMeta-learner is analyzing the network state...")
    print("This may take 30-60 seconds...\n")

    # coordinator.hunt() signature: hunt(data, initial_signals=None, context_data=None)
    # It creates NetworkState internally from context_data
    hunt_result = coordinator.hunt(
        data=hunting_data,
        initial_signals=None,
        context_data=None
    )

    # Update network mapper
    print("\n🗺️  Updating network map...")
    mapper = NetworkMapperPlugin({'output_dir': 'network_maps'})
    mapper.initialize()
    map_result = mapper.execute(
        network_connections=hunting_data.get('network_connections', []),
        dns_queries=hunting_data.get('dns_queries', []),
    )
    mapper.save_map()
    print(f"  • Mapped {map_result['total_nodes']} nodes across sensors: {', '.join(map_result.get('sensors', []))}")

    # Display findings
    analyzer.print_findings(hunt_result)

    # Display aggregated results
    analyzer.print_aggregated_results(hunt_result)

    # Save results
    output_file = analyzer.save_results(hunt_result, network_state)

    # Final summary
    analyzer.print_section("✅ HUNT COMPLETE")

    total_findings = hunt_result.get('total_findings', 0)

    if total_findings > 0:
        print(f"\n⚠️  Detected {total_findings} potential threats requiring investigation")
        print(f"\n📋 Next Steps:")
        print(f"  1. Review the findings above prioritized by severity")
        print(f"  2. Investigate affected assets and network flows")
        print(f"  3. Check {output_file} for detailed JSON output")
        print(f"  4. Re-run with different time ranges: hunt.py --time-range '-24h'")
    else:
        print(f"\n✓ No threats detected in this hunt")
        print(f"\n💡 Tips for improving detection:")
        print(f"  • Increase time range: hunt.py --time-range '-24h'")
        print(f"  • Hunt during high activity periods")
        print(f"  • Enable Windows log collection for host-based detection")

    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    # Add argument parsing for time range
    import argparse
    parser = argparse.ArgumentParser(description="Artemis Threat Hunting")
    parser.add_argument('--time-range', default='-1h', help='Splunk time range (e.g., -1h, -24h)')
    args = parser.parse_args()

    # For now, use default time range (will enhance later)
    main()
