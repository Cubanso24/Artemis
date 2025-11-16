"""
Threat hypothesis generation and management.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any
from datetime import datetime


class HypothesisType(Enum):
    """Types of threat hypotheses."""
    KILL_CHAIN_STAGE = "kill_chain_stage"
    TTP_PATTERN = "ttp_pattern"
    ANOMALY_INVESTIGATION = "anomaly_investigation"
    CHAIN_OF_EVENTS = "chain_of_events"
    INSIDER_THREAT = "insider_threat"
    APT_CAMPAIGN = "apt_campaign"


@dataclass
class ThreatHypothesis:
    """
    A hypothesis about potential threat activity.

    The meta-learner generates hypotheses based on initial signals,
    then activates appropriate agents to investigate.
    """
    hypothesis_id: str
    hypothesis_type: HypothesisType
    description: str
    initial_indicators: List[str]
    suggested_agents: List[str]  # Agent names to activate
    priority: float  # 0.0 to 1.0
    confidence: float = 0.0  # Updated as agents report findings
    kill_chain_stages: List[str] = field(default_factory=list)  # MITRE tactics
    threat_actor_profile: str = ""
    expected_ttps: List[str] = field(default_factory=list)  # MITRE techniques
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def update_confidence(self, new_confidence: float):
        """Update hypothesis confidence based on agent findings."""
        self.confidence = max(self.confidence, new_confidence)
        self.updated_at = datetime.utcnow()

    def add_supporting_evidence(self, agent_name: str, evidence: Dict[str, Any]):
        """Add evidence supporting this hypothesis."""
        if "supporting_evidence" not in self.metadata:
            self.metadata["supporting_evidence"] = {}
        self.metadata["supporting_evidence"][agent_name] = evidence
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "type": self.hypothesis_type.value,
            "description": self.description,
            "initial_indicators": self.initial_indicators,
            "suggested_agents": self.suggested_agents,
            "priority": self.priority,
            "confidence": self.confidence,
            "kill_chain_stages": self.kill_chain_stages,
            "threat_actor_profile": self.threat_actor_profile,
            "expected_ttps": self.expected_ttps,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
