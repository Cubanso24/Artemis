"""
Example: Phishing Campaign Detection

Demonstrates how Artemis detects and responds to a phishing campaign
that leads to execution and persistence.
"""

from datetime import datetime
from artemis.meta_learner.coordinator import MetaLearnerCoordinator, DeploymentMode


def run_phishing_scenario():
    """
    Simulate detection of a phishing campaign.

    Timeline:
    T=0: Suspicious email detected
    T=5min: Macro execution detected
    T=10min: PowerShell execution and persistence
    T=15min: C2 beaconing detected
    """
    print("=" * 80)
    print("SCENARIO: Phishing Campaign Detection")
    print("=" * 80)

    # Initialize coordinator
    coordinator = MetaLearnerCoordinator(
        deployment_mode=DeploymentMode.ADAPTIVE,
        enable_parallel_execution=True
    )

    # T=0: Initial signal - suspicious email
    print("\n[T=0] Initial signal: Suspicious email detected")

    initial_signals = [
        {
            "type": "suspicious_email",
            "confidence": 0.6,
            "description": "Email with suspicious attachment",
            "indicators": ["malicious_macro", "suspicious_sender"]
        }
    ]

    # Simulated email data
    email_data = {
        "emails": [
            {
                "sender": "admin@suspicious-domain.com",
                "subject": "Urgent: Verify your account",
                "recipients": ["user@company.com"],
                "attachments": [
                    {"filename": "invoice.doc", "extension": ".doc"}
                ],
                "body": "Click here to verify your account urgently"
            }
        ]
    }

    # Run initial hunt
    assessment_t0 = coordinator.hunt(
        data=email_data,
        initial_signals=initial_signals
    )

    print(f"\n[T=0] Assessment:")
    print(f"  Confidence: {assessment_t0['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t0['severity'].value}")
    print(f"  Alert Level: {assessment_t0['alert_level']}")
    print(f"  Findings: {assessment_t0['total_findings']}")

    # T=5: Macro execution detected
    print("\n[T=5min] Macro execution detected")

    execution_data = {
        "powershell_logs": [
            {
                "hostname": "WORKSTATION-01",
                "user": "user@company.com",
                "command_line": "powershell.exe -nop -w hidden -encodedcommand JABhAD...",
                "timestamp": datetime.utcnow()
            }
        ],
        "process_logs": [
            {
                "hostname": "WORKSTATION-01",
                "process_name": "winword.exe",
                "parent_process": "explorer.exe",
                "command_line": "winword.exe invoice.doc",
                "timestamp": datetime.utcnow()
            }
        ]
    }

    execution_signals = [
        {
            "type": "execution_detected",
            "confidence": 0.75,
            "description": "PowerShell execution from Office document"
        }
    ]

    assessment_t5 = coordinator.hunt(
        data=execution_data,
        initial_signals=execution_signals
    )

    print(f"\n[T=5min] Assessment:")
    print(f"  Confidence: {assessment_t5['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t5['severity'].value}")
    print(f"  Alert Level: {assessment_t5['alert_level']}")
    print(f"  Techniques: {', '.join(assessment_t5['mitre_techniques'][:3])}")

    # T=10: Persistence detected
    print("\n[T=10min] Persistence mechanism detected")

    persistence_data = {
        "scheduled_tasks": [
            {
                "event_type": "created",
                "task_name": "WindowsUpdate_7a3f9e21",
                "command": "powershell.exe -w hidden -nop -c IEX ...",
                "trigger": "on logon",
                "creator": "user@company.com",
                "timestamp": datetime.utcnow()
            }
        ],
        "registry_changes": [
            {
                "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "SecurityUpdate",
                "value_data": "C:\\Users\\user\\AppData\\Local\\Temp\\update.exe",
                "user": "user@company.com",
                "timestamp": datetime.utcnow()
            }
        ]
    }

    persistence_signals = [
        {
            "type": "persistence_detected",
            "confidence": 0.8,
            "description": "Registry Run key and scheduled task created"
        }
    ]

    assessment_t10 = coordinator.hunt(
        data=persistence_data,
        initial_signals=persistence_signals
    )

    print(f"\n[T=10min] Assessment:")
    print(f"  Confidence: {assessment_t10['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t10['severity'].value}")
    print(f"  Kill Chain Progression: CONFIRMED")

    # T=15: C2 beaconing
    print("\n[T=15min] C2 beaconing detected")

    c2_data = {
        "network_connections": [
            {
                "source_ip": "10.0.1.50",
                "destination_ip": "185.220.101.23",
                "destination_port": 8443,
                "timestamp": datetime.utcnow()
            }
            for _ in range(10)  # Regular beaconing
        ]
    }

    c2_signals = [
        {
            "type": "c2_beaconing",
            "confidence": 0.85,
            "description": "Regular C2 communication detected"
        }
    ]

    assessment_t15 = coordinator.hunt(
        data=c2_data,
        initial_signals=c2_signals
    )

    print(f"\n[T=15min] Final Assessment:")
    print(f"  Confidence: {assessment_t15['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t15['severity'].value}")
    print(f"  Alert Level: {assessment_t15['alert_level']}")
    print(f"  Corroborating Agents: {assessment_t15.get('corroborating_agents', 0)}")

    # Recommendations
    print("\n[RECOMMENDATIONS]")
    for i, rec in enumerate(assessment_t15.get('recommendations', [])[:5], 1):
        print(f"  {i}. {rec}")

    # Provide feedback (simulating analyst confirmation)
    print("\n[ANALYST FEEDBACK] Confirmed as True Positive - Active phishing campaign")
    coordinator.provide_feedback(
        assessment_t15,
        "true_positive",
        "Confirmed active phishing campaign leading to malware installation"
    )

    # Get statistics
    print("\n[SYSTEM STATISTICS]")
    stats = coordinator.get_statistics()
    print(f"  Total Hunts: {stats['total_hunts']}")
    print(f"  Total Detections: {stats['total_detections']}")
    print(f"  Detection Rate: {stats['detection_rate']:.1%}")

    print("\n" + "=" * 80)
    print("Scenario complete - Phishing campaign successfully detected and tracked")
    print("=" * 80)


if __name__ == "__main__":
    run_phishing_scenario()
