"""
Artemis Hunting Agents

Five specialized agents focused on network-observable threats
detectable via Zeek conn/dns/http/ssl/ntlm telemetry from Splunk.
"""

from artemis.agents.base_agent import BaseAgent, AgentPriority
from artemis.agents.reconnaissance_hunter import ReconnaissanceHunter
from artemis.agents.lateral_movement_hunter import LateralMovementHunter
from artemis.agents.collection_exfiltration_hunter import CollectionExfiltrationHunter
from artemis.agents.c2_hunter import C2Hunter
from artemis.agents.impact_hunter import ImpactHunter

__all__ = [
    "BaseAgent",
    "AgentPriority",
    "ReconnaissanceHunter",
    "LateralMovementHunter",
    "CollectionExfiltrationHunter",
    "C2Hunter",
    "ImpactHunter",
]
