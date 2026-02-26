"""
Case data model for autonomous threat hunting.

Cases are auto-generated from hunt assessments when confidence exceeds
configured thresholds. Each case groups correlated findings and tracks
its lifecycle from creation through analyst verdict.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid


class CaseStatus(Enum):
    """Lifecycle status of a case."""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED_TP = "confirmed_tp"
    CONFIRMED_FP = "confirmed_fp"
    CLOSED = "closed"


class EscalationLevel(Enum):
    """Confidence-based escalation levels.

    Thresholds (configurable):
        auto_respond:     >= 0.95  Auto-escalate to SOC + notify
        auto_investigate: >= 0.80  Create case + recommend actions
        human_review:     >= 0.60  Generate report for analyst review
        log_only:         <  0.60  Log for trend analysis only
    """
    AUTO_RESPOND = "auto_respond"
    AUTO_INVESTIGATE = "auto_investigate"
    HUMAN_REVIEW = "human_review"
    LOG_ONLY = "log_only"


class CaseSource(Enum):
    """How the case was created."""
    AUTONOMOUS = "autonomous"   # Auto-generated from scheduled hunt
    MANUAL = "manual"           # Created from manual hunt
    IRIS_IMPORT = "iris_import" # Imported from DFIR-IRIS


@dataclass
class Case:
    """
    A threat hunting case grouping correlated findings.

    Cases are the primary output of autonomous hunting. They aggregate
    findings from one or more hunt cycles, track investigation status,
    and feed the self-learning loop when resolved.
    """
    case_id: str
    title: str
    status: CaseStatus
    severity: str                          # low, medium, high, critical
    confidence: float                      # aggregated from findings (0.0-1.0)
    description: str                       # LLM-generated threat narrative
    findings: List[str] = field(default_factory=list)  # finding_id refs
    mitre_techniques: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    kill_chain_stages: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    hunt_cycle: int = 0
    source: CaseSource = CaseSource.AUTONOMOUS
    escalation_level: EscalationLevel = EscalationLevel.HUMAN_REVIEW
    iris_case_id: Optional[str] = None
    analyst_verdict: Optional[str] = None  # tp, fp, uncertain
    analyst_notes: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    @staticmethod
    def generate_id() -> str:
        """Generate a unique case ID."""
        return f"CASE-{uuid.uuid4().hex[:12].upper()}"

    def resolve(self, verdict: str, notes: str = ""):
        """Mark the case as resolved with an analyst verdict."""
        if verdict not in ("tp", "fp", "uncertain"):
            raise ValueError(f"Invalid verdict: {verdict}. Must be tp, fp, or uncertain.")
        self.analyst_verdict = verdict
        self.analyst_notes = notes
        self.resolved_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        if verdict == "tp":
            self.status = CaseStatus.CONFIRMED_TP
        elif verdict == "fp":
            self.status = CaseStatus.CONFIRMED_FP
        else:
            self.status = CaseStatus.CLOSED

    def add_findings(self, finding_ids: List[str]):
        """Add findings to this case (deduplicates)."""
        existing = set(self.findings)
        for fid in finding_ids:
            if fid not in existing:
                self.findings.append(fid)
                existing.add(fid)
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "findings": self.findings,
            "mitre_techniques": self.mitre_techniques,
            "affected_assets": self.affected_assets,
            "kill_chain_stages": self.kill_chain_stages,
            "recommended_actions": self.recommended_actions,
            "hunt_cycle": self.hunt_cycle,
            "source": self.source.value,
            "escalation_level": self.escalation_level.value,
            "iris_case_id": self.iris_case_id,
            "analyst_verdict": self.analyst_verdict,
            "analyst_notes": self.analyst_notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Case':
        """Create a Case from a dictionary."""
        return cls(
            case_id=data["case_id"],
            title=data["title"],
            status=CaseStatus(data["status"]),
            severity=data["severity"],
            confidence=data["confidence"],
            description=data.get("description", ""),
            findings=data.get("findings", []),
            mitre_techniques=data.get("mitre_techniques", []),
            affected_assets=data.get("affected_assets", []),
            kill_chain_stages=data.get("kill_chain_stages", []),
            recommended_actions=data.get("recommended_actions", []),
            hunt_cycle=data.get("hunt_cycle", 0),
            source=CaseSource(data.get("source", "autonomous")),
            escalation_level=EscalationLevel(data.get("escalation_level", "human_review")),
            iris_case_id=data.get("iris_case_id"),
            analyst_verdict=data.get("analyst_verdict"),
            analyst_notes=data.get("analyst_notes", ""),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data.get("created_at"), str) else data.get("created_at", datetime.utcnow()),
            updated_at=datetime.fromisoformat(data["updated_at"]) if isinstance(data.get("updated_at"), str) else data.get("updated_at", datetime.utcnow()),
            resolved_at=datetime.fromisoformat(data["resolved_at"]) if data.get("resolved_at") else None,
        )
