"""
Production deployment example with Splunk and Security Onion integration.

Demonstrates how to use Artemis with real security infrastructure.
"""

from datetime import datetime
from artemis import MetaLearnerCoordinator
from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
from artemis.utils.logging_config import ArtemisLogger


def run_continuous_hunting():
    """
    Run continuous threat hunting with Splunk and Security Onion.

    This example shows production deployment with real data sources.
    """
    print("=" * 80)
    print("ARTEMIS - Production Threat Hunting Deployment")
    print("=" * 80)

    # Configure data sources
    config = DataSourceConfig(
        # Splunk configuration
        splunk_host="splunk.company.com",
        splunk_port=8089,
        splunk_token="YOUR_SPLUNK_TOKEN",  # or use username/password

        # Security Onion configuration
        security_onion_host="https://securityonion.company.com",
        security_onion_api_key="YOUR_API_KEY",  # or use username/password

        # Feature flags
        enable_pcap_analysis=True,
        enable_zeek_logs=True,
        enable_suricata_alerts=True
    )

    # Initialize data pipeline
    print("\n[1] Initializing data pipeline...")
    pipeline = DataPipeline(config)
    print("    ✓ Connected to Splunk and Security Onion")

    # Initialize Artemis coordinator
    print("\n[2] Initializing Artemis Meta-Learner Coordinator...")
    coordinator = MetaLearnerCoordinator(
        deployment_mode="adaptive",
        enable_parallel_execution=True,
        max_workers=4
    )
    print("    ✓ Coordinator initialized with 9 hunting agents")

    # Collect hunting data
    print("\n[3] Collecting threat hunting data...")
    print("    - Querying Splunk for last hour of logs")
    print("    - Retrieving Zeek connection logs")
    print("    - Retrieving Zeek DNS logs")
    print("    - Collecting Suricata IDS alerts")
    print("    - Gathering process execution logs")
    print("    - Pulling authentication events")

    hunting_data = pipeline.collect_hunting_data(
        time_range="-1h",
        include_pcap=False  # Set True to analyze PCAP (resource intensive)
    )

    print(f"\n    ✓ Collected data:")
    for data_type, events in hunting_data.items():
        if isinstance(events, list):
            print(f"      - {data_type}: {len(events)} events")

    # Get network context
    print("\n[4] Assessing network state context...")
    context_data = pipeline.get_context_data()
    print(f"    - Alerts (24h): {context_data['alerts']['alerts_24h']}")
    print(f"    - Network connections: {context_data['network_traffic']['connections']}")

    # Execute threat hunt
    print("\n[5] Executing threat hunt with Artemis...")

    assessment = coordinator.hunt(
        data=hunting_data,
        initial_signals=hunting_data.get("initial_signals"),
        context_data=context_data
    )

    # Display results
    print("\n" + "=" * 80)
    print("THREAT ASSESSMENT RESULTS")
    print("=" * 80)

    print(f"\nOverall Confidence: {assessment['final_confidence']:.2f}")
    print(f"Severity: {assessment['severity'].value}")
    print(f"Alert Level: {assessment['alert_level'].upper()}")
    print(f"\nAgents Activated: {assessment['agent_count']}")
    print(f"Corroborating Agents: {assessment.get('corroborating_agents', 0)}")
    print(f"Total Findings: {assessment['total_findings']}")

    if assessment['mitre_techniques']:
        print(f"\nMITRE ATT&CK Techniques Detected:")
        for technique in assessment['mitre_techniques'][:5]:
            print(f"  - {technique}")

    if assessment['findings']:
        print(f"\nTop Findings:")
        for i, finding in enumerate(assessment['findings'][:3], 1):
            print(f"  {i}. {finding.activity_type}: {finding.description}")

    if assessment['recommendations']:
        print(f"\nRecommended Actions:")
        for i, rec in enumerate(assessment['recommendations'][:5], 1):
            print(f"  {i}. {rec}")

    # Handle high-confidence detections
    if assessment['alert_level'] in ['critical', 'high']:
        print("\n" + "!" * 80)
        print("HIGH PRIORITY ALERT DETECTED")
        print("!" * 80)

        # Example: Investigate suspicious IPs with PCAP
        suspicious_ips = extract_suspicious_ips(assessment)

        if suspicious_ips:
            print(f"\nInvestigating {len(suspicious_ips)} suspicious IPs with PCAP analysis...")

            pcap_data = pipeline.collect_hunting_data(
                time_range="-1h",
                include_pcap=True,
                suspicious_ips=suspicious_ips
            )

            # Re-run hunt with PCAP data
            detailed_assessment = coordinator.hunt(
                data=pcap_data,
                context_data=context_data
            )

            print(f"Deep dive confidence: {detailed_assessment['final_confidence']:.2f}")

    # Get system statistics
    print("\n" + "=" * 80)
    print("SYSTEM STATISTICS")
    print("=" * 80)

    stats = coordinator.get_statistics()
    print(f"Total Hunts: {stats['total_hunts']}")
    print(f"Total Detections: {stats['total_detections']}")
    print(f"High-Confidence Detections: {stats['high_confidence_detections']}")
    print(f"Detection Rate: {stats['detection_rate']:.1%}")

    if stats['most_active_agents']:
        print(f"\nMost Active Agents:")
        for agent, count in stats['most_active_agents']:
            print(f"  - {agent}: {count} activations")

    # Provide analyst feedback (example)
    print("\n" + "=" * 80)
    print("ANALYST FEEDBACK")
    print("=" * 80)

    feedback = input("Was this a true positive? (yes/no/uncertain): ").lower()

    if feedback == "yes":
        coordinator.provide_feedback(assessment, "true_positive", "Confirmed threat")
        print("✓ Feedback recorded - System will learn from this detection")
    elif feedback == "no":
        coordinator.provide_feedback(assessment, "false_positive", "False alarm")
        print("✓ Feedback recorded - Detection thresholds will be adjusted")

    print("\n" + "=" * 80)
    print("Threat hunting complete")
    print("=" * 80)


def run_streaming_mode():
    """
    Run Artemis in continuous streaming mode.

    Continuously polls for new data and runs threat hunts.
    """
    print("=" * 80)
    print("ARTEMIS - Continuous Streaming Mode")
    print("=" * 80)

    # Configure data sources
    config = DataSourceConfig(
        splunk_host="splunk.company.com",
        splunk_token="YOUR_TOKEN",
        security_onion_host="https://securityonion.company.com",
        security_onion_api_key="YOUR_API_KEY"
    )

    pipeline = DataPipeline(config)
    coordinator = MetaLearnerCoordinator()

    def hunt_callback(hunting_data):
        """Callback for each batch of data."""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New data batch received")

        # Run threat hunt
        assessment = coordinator.hunt(
            data=hunting_data,
            initial_signals=hunting_data.get("initial_signals")
        )

        # Alert on high-confidence detections
        if assessment['final_confidence'] >= 0.7:
            print(f"⚠️  DETECTION: Confidence={assessment['final_confidence']:.2f}, "
                  f"Severity={assessment['severity'].value}")

            # Could trigger automated response here
            # - Send to SIEM
            # - Create ticket in SOAR
            # - Send Slack/Teams notification
            # - Trigger automated containment

    print("\nStarting continuous threat hunting...")
    print("Press Ctrl+C to stop\n")

    # Stream data every 5 minutes
    pipeline.stream_hunting_data(
        callback=hunt_callback,
        time_window=300,  # 5 minute windows
        poll_interval=60   # Poll every minute
    )


def extract_suspicious_ips(assessment: dict) -> list:
    """Extract suspicious IP addresses from assessment findings."""
    ips = set()

    for finding in assessment.get('findings', []):
        for indicator in finding.indicators:
            # Simple IP pattern matching
            if '.' in indicator and indicator.replace('.', '').replace(':', '').isdigit():
                ips.add(indicator.split(':')[0])  # Remove port if present

    return list(ips)


def investigate_specific_host(hostname: str):
    """
    Investigate a specific host in depth.

    Args:
        hostname: Hostname to investigate
    """
    print(f"Investigating host: {hostname}")

    config = DataSourceConfig(
        splunk_host="splunk.company.com",
        splunk_token="YOUR_TOKEN"
    )

    pipeline = DataPipeline(config)
    coordinator = MetaLearnerCoordinator()

    # Collect data specific to this host
    # Would need to add hostname filtering to Splunk queries
    hunting_data = pipeline.collect_hunting_data(time_range="-24h")

    # Filter for specific host (simplified)
    filtered_data = {
        key: [
            event for event in events
            if isinstance(event, dict) and event.get('hostname') == hostname
        ]
        for key, events in hunting_data.items()
        if isinstance(events, list)
    }

    # Run hunt
    assessment = coordinator.hunt(data=filtered_data)

    print(f"\nHost Investigation Results for {hostname}:")
    print(f"Confidence: {assessment['final_confidence']:.2f}")
    print(f"Findings: {assessment['total_findings']}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "stream":
            run_streaming_mode()
        elif sys.argv[1] == "investigate" and len(sys.argv) > 2:
            investigate_specific_host(sys.argv[2])
        else:
            print("Usage:")
            print("  python production_deployment.py           - Single hunt")
            print("  python production_deployment.py stream    - Continuous mode")
            print("  python production_deployment.py investigate HOSTNAME")
    else:
        run_continuous_hunting()
