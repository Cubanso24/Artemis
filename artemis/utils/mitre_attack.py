"""
MITRE ATT&CK framework integration and mappings.
"""

from enum import Enum
from typing import Dict, List, Set


class KillChainStage(Enum):
    """MITRE ATT&CK Tactics (Kill Chain Stages)."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class MITREAttack:
    """
    MITRE ATT&CK framework reference and mapping utilities.

    Provides mappings between tactics, techniques, and hunting agents.
    """

    # Agent to MITRE Tactics mapping
    AGENT_TACTICS: Dict[str, List[KillChainStage]] = {
        "reconnaissance_hunter": [
            KillChainStage.RECONNAISSANCE,
            KillChainStage.DISCOVERY
        ],
        "initial_access_hunter": [
            KillChainStage.INITIAL_ACCESS,
            KillChainStage.RESOURCE_DEVELOPMENT
        ],
        "execution_persistence_hunter": [
            KillChainStage.EXECUTION,
            KillChainStage.PERSISTENCE,
            KillChainStage.PRIVILEGE_ESCALATION
        ],
        "credential_access_hunter": [
            KillChainStage.CREDENTIAL_ACCESS
        ],
        "lateral_movement_hunter": [
            KillChainStage.LATERAL_MOVEMENT
        ],
        "collection_exfiltration_hunter": [
            KillChainStage.COLLECTION,
            KillChainStage.EXFILTRATION
        ],
        "c2_hunter": [
            KillChainStage.COMMAND_AND_CONTROL
        ],
        "defense_evasion_hunter": [
            KillChainStage.DEFENSE_EVASION
        ],
        "impact_hunter": [
            KillChainStage.IMPACT
        ]
    }

    # Common MITRE ATT&CK Techniques by Tactic
    TECHNIQUES: Dict[KillChainStage, List[str]] = {
        KillChainStage.RECONNAISSANCE: [
            "T1595",  # Active Scanning
            "T1592",  # Gather Victim Host Information
            "T1589",  # Gather Victim Identity Information
            "T1590",  # Gather Victim Network Information
            "T1591",  # Gather Victim Org Information
            "T1598",  # Phishing for Information
        ],
        KillChainStage.INITIAL_ACCESS: [
            "T1566",  # Phishing
            "T1190",  # Exploit Public-Facing Application
            "T1133",  # External Remote Services
            "T1078",  # Valid Accounts
            "T1195",  # Supply Chain Compromise
            "T1199",  # Trusted Relationship
        ],
        KillChainStage.EXECUTION: [
            "T1059",  # Command and Scripting Interpreter
            "T1047",  # Windows Management Instrumentation
            "T1053",  # Scheduled Task/Job
            "T1204",  # User Execution
            "T1106",  # Native API
        ],
        KillChainStage.PERSISTENCE: [
            "T1053",  # Scheduled Task/Job
            "T1547",  # Boot or Logon Autostart Execution
            "T1543",  # Create or Modify System Process
            "T1136",  # Create Account
            "T1078",  # Valid Accounts
            "T1098",  # Account Manipulation
        ],
        KillChainStage.CREDENTIAL_ACCESS: [
            "T1003",  # OS Credential Dumping
            "T1558",  # Steal or Forge Kerberos Tickets
            "T1110",  # Brute Force
            "T1555",  # Credentials from Password Stores
            "T1212",  # Exploitation for Credential Access
            "T1187",  # Forced Authentication
        ],
        KillChainStage.DISCOVERY: [
            "T1087",  # Account Discovery
            "T1083",  # File and Directory Discovery
            "T1046",  # Network Service Discovery
            "T1135",  # Network Share Discovery
            "T1201",  # Password Policy Discovery
            "T1069",  # Permission Groups Discovery
        ],
        KillChainStage.LATERAL_MOVEMENT: [
            "T1021",  # Remote Services
            "T1080",  # Taint Shared Content
            "T1550",  # Use Alternate Authentication Material
            "T1563",  # Remote Service Session Hijacking
        ],
        KillChainStage.COLLECTION: [
            "T1560",  # Archive Collected Data
            "T1119",  # Automated Collection
            "T1115",  # Clipboard Data
            "T1005",  # Data from Local System
            "T1039",  # Data from Network Shared Drive
            "T1113",  # Screen Capture
        ],
        KillChainStage.COMMAND_AND_CONTROL: [
            "T1071",  # Application Layer Protocol
            "T1132",  # Data Encoding
            "T1001",  # Data Obfuscation
            "T1568",  # Dynamic Resolution
            "T1573",  # Encrypted Channel
            "T1090",  # Proxy
        ],
        KillChainStage.EXFILTRATION: [
            "T1020",  # Automated Exfiltration
            "T1030",  # Data Transfer Size Limits
            "T1048",  # Exfiltration Over Alternative Protocol
            "T1041",  # Exfiltration Over C2 Channel
            "T1011",  # Exfiltration Over Other Network Medium
        ],
        KillChainStage.DEFENSE_EVASION: [
            "T1562",  # Impair Defenses
            "T1070",  # Indicator Removal
            "T1202",  # Indirect Command Execution
            "T1036",  # Masquerading
            "T1055",  # Process Injection
            "T1620",  # Reflective Code Loading
        ],
        KillChainStage.IMPACT: [
            "T1486",  # Data Encrypted for Impact
            "T1485",  # Data Destruction
            "T1489",  # Service Stop
            "T1490",  # Inhibit System Recovery
            "T1491",  # Defacement
            "T1496",  # Resource Hijacking
        ],
    }

    # Kill chain progression rules
    KILL_CHAIN_PROGRESSION: Dict[KillChainStage, List[KillChainStage]] = {
        KillChainStage.RECONNAISSANCE: [
            KillChainStage.INITIAL_ACCESS,
            KillChainStage.RESOURCE_DEVELOPMENT
        ],
        KillChainStage.INITIAL_ACCESS: [
            KillChainStage.EXECUTION,
            KillChainStage.COMMAND_AND_CONTROL
        ],
        KillChainStage.EXECUTION: [
            KillChainStage.PERSISTENCE,
            KillChainStage.CREDENTIAL_ACCESS,
            KillChainStage.LATERAL_MOVEMENT
        ],
        KillChainStage.PERSISTENCE: [
            KillChainStage.CREDENTIAL_ACCESS,
            KillChainStage.LATERAL_MOVEMENT
        ],
        KillChainStage.CREDENTIAL_ACCESS: [
            KillChainStage.LATERAL_MOVEMENT,
            KillChainStage.PRIVILEGE_ESCALATION
        ],
        KillChainStage.LATERAL_MOVEMENT: [
            KillChainStage.COLLECTION,
            KillChainStage.EXFILTRATION
        ],
        KillChainStage.COLLECTION: [
            KillChainStage.EXFILTRATION
        ],
    }

    @classmethod
    def get_agents_for_tactic(cls, tactic: KillChainStage) -> List[str]:
        """Get hunting agents responsible for a given tactic."""
        agents = []
        for agent_name, tactics in cls.AGENT_TACTICS.items():
            if tactic in tactics:
                agents.append(agent_name)
        return agents

    @classmethod
    def get_next_stage_agents(cls, current_tactic: KillChainStage) -> List[str]:
        """
        Get agents for likely next stages in the kill chain.

        Args:
            current_tactic: Current detected kill chain stage

        Returns:
            List of agent names to activate for next expected stages
        """
        next_stages = cls.KILL_CHAIN_PROGRESSION.get(current_tactic, [])
        agents = []
        for stage in next_stages:
            agents.extend(cls.get_agents_for_tactic(stage))
        return list(set(agents))  # Remove duplicates

    @classmethod
    def get_techniques_for_tactic(cls, tactic: KillChainStage) -> List[str]:
        """Get common techniques for a tactic."""
        return cls.TECHNIQUES.get(tactic, [])

    @classmethod
    def is_kill_chain_progression(cls, tactics: List[KillChainStage]) -> bool:
        """
        Check if tactics represent a valid kill chain progression.

        Args:
            tactics: List of observed tactics in chronological order

        Returns:
            True if tactics follow a logical progression
        """
        if len(tactics) < 2:
            return False

        for i in range(len(tactics) - 1):
            current = tactics[i]
            next_tactic = tactics[i + 1]
            expected_next = cls.KILL_CHAIN_PROGRESSION.get(current, [])

            if next_tactic not in expected_next:
                return False

        return True

    @classmethod
    def get_tactic_name(cls, tactic: KillChainStage) -> str:
        """Get human-readable name for a tactic."""
        return tactic.name.replace("_", " ").title()

    @classmethod
    def get_all_agent_names(cls) -> List[str]:
        """Get all agent names."""
        return list(cls.AGENT_TACTICS.keys())
