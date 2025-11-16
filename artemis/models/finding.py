"""
Finding and evidence data structures.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List


@dataclass
class Evidence:
    """
    Evidence supporting a security finding.

    Attributes:
        timestamp: When this evidence was collected
        source: Where the evidence came from (log source, sensor, etc.)
        data: The actual evidence data
        description: Human-readable description
        confidence_contribution: How much this evidence contributes to overall confidence
    """
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    description: str
    confidence_contribution: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "data": self.data,
            "description": self.description,
            "confidence_contribution": self.confidence_contribution
        }


@dataclass
class Finding:
    """
    A suspicious activity detected by a hunting agent.

    Attributes:
        activity_type: Type of suspicious activity
        description: Detailed description of what was found
        indicators: List of specific indicators (IPs, domains, file hashes, etc.)
        evidence: Supporting evidence for this finding
        mitre_techniques: MITRE ATT&CK technique IDs
        affected_assets: Systems, users, or resources affected
        timestamp: When this finding was identified
    """
    activity_type: str
    description: str
    indicators: List[str]
    evidence: List[Evidence]
    mitre_techniques: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence: Evidence):
        """Add new evidence to this finding."""
        self.evidence.append(evidence)

    def get_total_confidence(self) -> float:
        """Calculate total confidence from all evidence."""
        if not self.evidence:
            return 0.0
        return min(sum(e.confidence_contribution for e in self.evidence), 1.0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "activity_type": self.activity_type,
            "description": self.description,
            "indicators": self.indicators,
            "evidence": [e.to_dict() for e in self.evidence],
            "mitre_techniques": self.mitre_techniques,
            "affected_assets": self.affected_assets,
            "timestamp": self.timestamp.isoformat(),
            "total_confidence": self.get_total_confidence(),
            "metadata": self.metadata
        }
