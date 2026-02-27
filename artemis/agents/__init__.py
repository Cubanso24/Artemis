"""
Specialized hunting agents for the Artemis threat hunting system.
"""

from artemis.agents.base_agent import BaseAgent, AgentPriority
from artemis.agents.reconnaissance_hunter import ReconnaissanceHunter
from artemis.agents.initial_access_hunter import InitialAccessHunter
from artemis.agents.execution_persistence_hunter import ExecutionPersistenceHunter
from artemis.agents.credential_access_hunter import CredentialAccessHunter
from artemis.agents.lateral_movement_hunter import LateralMovementHunter
from artemis.agents.collection_exfiltration_hunter import CollectionExfiltrationHunter
from artemis.agents.c2_hunter import C2Hunter
from artemis.agents.defense_evasion_hunter import DefenseEvasionHunter
from artemis.agents.impact_hunter import ImpactHunter

__all__ = [
    "BaseAgent",
    "AgentPriority",
    "ReconnaissanceHunter",
    "InitialAccessHunter",
    "ExecutionPersistenceHunter",
    "CredentialAccessHunter",
    "LateralMovementHunter",
    "CollectionExfiltrationHunter",
    "C2Hunter",
    "DefenseEvasionHunter",
    "ImpactHunter",
]
