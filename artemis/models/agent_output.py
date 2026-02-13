"""
Agent output data structures for threat hunting results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any
from datetime import datetime
import hashlib


class Severity(Enum):
    """Severity levels for detected threats."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        """Enable severity comparison."""
        severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3
        }
        return severity_order[self] < severity_order[other]


@dataclass
class Evidence:
    """Evidence supporting a finding."""
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    description: str
    confidence_contribution: float = 0.0


@dataclass
class Finding:
    """A suspicious activity detected by an agent."""
    activity_type: str
    description: str
    indicators: List[str]
    evidence: List[Evidence]
    mitre_techniques: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def fingerprint(self) -> str:
        """
        Generate a stable fingerprint for deduplication.

        Based on activity_type, sorted indicators, sorted affected_assets,
        and sorted MITRE techniques. Two findings with the same fingerprint
        describe the same underlying threat activity.
        """
        parts = [
            self.activity_type,
            "|".join(sorted(self.indicators)),
            "|".join(sorted(self.affected_assets)),
            "|".join(sorted(self.mitre_techniques)),
        ]
        raw = "::".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class AgentOutput:
    """
    Standard output format for all hunting agents.

    Attributes:
        agent_name: Name of the agent producing this output
        confidence: Detection confidence score (0.0-1.0)
        findings: List of suspicious activities detected
        evidence: Supporting evidence for the findings
        severity: Overall severity assessment
        mitre_tactics: MITRE ATT&CK tactic IDs (e.g., TA0001)
        mitre_techniques: MITRE ATT&CK technique IDs (e.g., T1595)
        recommended_actions: Suggested response actions
        processing_time: Time taken to analyze (seconds)
        metadata: Additional agent-specific information
    """
    agent_name: str
    confidence: float
    findings: List[Finding]
    evidence: List[Evidence]
    severity: Severity
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    processing_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        """Validate output after initialization."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_name": self.agent_name,
            "confidence": self.confidence,
            "findings": [
                {
                    "activity_type": f.activity_type,
                    "description": f.description,
                    "indicators": f.indicators,
                    "mitre_techniques": f.mitre_techniques,
                    "affected_assets": f.affected_assets,
                    "timestamp": f.timestamp.isoformat(),
                    "fingerprint": f.fingerprint,
                }
                for f in self.findings
            ],
            "evidence_count": len(self.evidence),
            "severity": self.severity.value,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "processing_time": self.processing_time,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }
