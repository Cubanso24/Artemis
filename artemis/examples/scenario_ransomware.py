"""
Example: Ransomware Early Detection

Demonstrates how Artemis detects ransomware activity early
through multi-agent correlation.
"""

from datetime import datetime
from artemis.meta_learner.coordinator import MetaLearnerCoordinator


def run_ransomware_scenario():
    """
    Simulate early ransomware detection.

    Timeline:
    T=0: Suspicious scheduled task
    T=30min: Security log clearing
    T=45min: Rapid file encryption detected
    """
    print("=" * 80)
    print("SCENARIO: Ransomware Early Detection")
    print("=" * 80)

    coordinator = MetaLearnerCoordinator()

    # T=0: Suspicious scheduled task
    print("\n[T=0] Suspicious scheduled task created")

    task_data = {
        "scheduled_tasks": [
            {
                "event_type": "created",
                "task_name": "SystemMaintenanceService",
                "command": "cmd.exe /c vssadmin delete shadows /all /quiet",
                "trigger": "at startup",
                "run_as": "SYSTEM",
                "creator": "admin",
                "timestamp": datetime.utcnow()
            }
        ]
    }

    assessment_t0 = coordinator.hunt(data=task_data)

    print(f"  Confidence: {assessment_t0['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t0['severity'].value}")

    # T=30: Log clearing
    print("\n[T=30min] Security log clearing detected")

    evasion_data = {
        "event_logs": [
            {
                "event_id": 1102,
                "log_name": "Security",
                "hostname": "SERVER-01",
                "timestamp": datetime.utcnow()
            }
        ],
        "service_logs": [
            {
                "service_name": "Windows Defender",
                "action": "stopped",
                "user": "admin",
                "timestamp": datetime.utcnow()
            }
        ]
    }

    assessment_t30 = coordinator.hunt(data=evasion_data)

    print(f"  Confidence: {assessment_t30['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t30['severity'].value}")
    print(f"  WARNING: Defense evasion detected")

    # T=45: Rapid file encryption
    print("\n[T=45min] CRITICAL: Rapid file encryption detected")

    impact_data = {
        "file_operations": [
            {
                "operation": "rename",
                "filename": f"document_{i}.txt.encrypted",
                "old_filename": f"document_{i}.txt",
                "file_size_bytes": 1024 * 100,
                "timestamp": datetime.utcnow()
            }
            for i in range(150)  # 150 rapid file changes
        ]
    }

    impact_signals = [
        {
            "type": "ransomware",
            "confidence": 0.95,
            "description": "Rapid file encryption pattern detected"
        }
    ]

    assessment_t45 = coordinator.hunt(
        data=impact_data,
        initial_signals=impact_signals
    )

    print(f"\n[CRITICAL ALERT]")
    print(f"  Confidence: {assessment_t45['final_confidence']:.2f}")
    print(f"  Severity: {assessment_t45['severity'].value}")
    print(f"  Alert Level: {assessment_t45['alert_level']}")
    print(f"  Activity: RANSOMWARE ENCRYPTION IN PROGRESS")

    print("\n[IMMEDIATE ACTIONS REQUIRED]")
    for i, rec in enumerate(assessment_t45.get('recommendations', [])[:7], 1):
        print(f"  {i}. {rec}")

    # Provide feedback
    coordinator.provide_feedback(
        assessment_t45,
        "true_positive",
        "Confirmed ransomware attack - systems isolated and recovery initiated"
    )

    print("\n" + "=" * 80)
    print("Scenario complete - Ransomware detected and contained")
    print("=" * 80)


if __name__ == "__main__":
    run_ransomware_scenario()
