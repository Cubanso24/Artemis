"""
Artemis - Hierarchical Threat Hunting System
A meta-learning coordinator orchestrating specialized hunting agents for cybersecurity threat detection.
"""

__version__ = "1.0.0"
__author__ = "Artemis Development Team"

from artemis.meta_learner.coordinator import MetaLearnerCoordinator
from artemis.models.agent_output import AgentOutput, Severity
from artemis.models.network_state import NetworkState
from artemis.models.threat_hypothesis import ThreatHypothesis, HypothesisType

__all__ = [
    "MetaLearnerCoordinator",
    "AgentOutput",
    "Severity",
    "NetworkState",
    "ThreatHypothesis",
    "HypothesisType",
]
