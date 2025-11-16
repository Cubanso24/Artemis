"""
Basic usage example for Artemis threat hunting system.
"""

from datetime import datetime
from artemis import MetaLearnerCoordinator


def basic_example():
    """
    Basic example showing how to use Artemis.
    """
    print("Artemis Threat Hunting System - Basic Usage Example\n")

    # 1. Initialize the coordinator
    print("1. Initializing Meta-Learner Coordinator...")
    coordinator = MetaLearnerCoordinator()
    print("   ✓ Coordinator initialized with 9 specialized agents\n")

    # 2. Prepare input data
    print("2. Preparing threat hunting data...")
    hunting_data = {
        "network_connections": [
            {
                "source_ip": "10.0.1.100",
                "destination_ip": "8.8.8.8",
                "destination_port": 53,
                "timestamp": datetime.utcnow()
            }
        ],
        "dns_queries": [
            {
                "source_ip": "10.0.1.100",
                "domain": "malicious-domain.com",
                "response_code": "NXDOMAIN",
                "timestamp": datetime.utcnow()
            }
        ],
        "process_logs": [
            {
                "hostname": "WORKSTATION-01",
                "process_name": "powershell.exe",
                "command_line": "powershell -w hidden",
                "user": "user@company.com",
                "timestamp": datetime.utcnow()
            }
        ]
    }
    print("   ✓ Data prepared\n")

    # 3. Run threat hunt
    print("3. Executing threat hunt...")
    assessment = coordinator.hunt(data=hunting_data)
    print("   ✓ Hunt complete\n")

    # 4. Review results
    print("4. Threat Assessment Results:")
    print(f"   Confidence: {assessment['final_confidence']:.2f}")
    print(f"   Severity: {assessment['severity'].value}")
    print(f"   Alert Level: {assessment['alert_level']}")
    print(f"   Total Findings: {assessment['total_findings']}")
    print(f"   Agents Activated: {assessment['agent_count']}")
    print(f"   Corroborating Agents: {assessment.get('corroborating_agents', 0)}\n")

    # 5. Review MITRE techniques
    if assessment['mitre_techniques']:
        print("5. MITRE ATT&CK Techniques Detected:")
        for technique in assessment['mitre_techniques'][:3]:
            print(f"   - {technique}")
        print()

    # 6. Review recommendations
    if assessment['recommendations']:
        print("6. Recommended Actions:")
        for i, rec in enumerate(assessment['recommendations'][:3], 1):
            print(f"   {i}. {rec}")
        print()

    # 7. Get system statistics
    print("7. System Statistics:")
    stats = coordinator.get_statistics()
    print(f"   Total Hunts: {stats['total_hunts']}")
    print(f"   Total Detections: {stats['total_detections']}")
    print(f"   Detection Rate: {stats['detection_rate']:.1%}\n")

    print("Example complete!")


if __name__ == "__main__":
    basic_example()
