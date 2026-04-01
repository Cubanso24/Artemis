"""
Autonomous case generation from hunt assessments.

Uses confidence-based escalation levels to decide when to create cases,
deduplicates findings against existing open cases, and indexes case data
into the RAG store for future hypothesis generation.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from artemis.models.case import (
    Case, CaseStatus, CaseSource, EscalationLevel,
)

logger = logging.getLogger("artemis.case_generator")


class CaseGenerator:
    """Auto-creates cases from hunt assessments using confidence-based escalation.

    Escalation levels (thresholds configurable via ``ArtemisConfig``):
        auto_respond     >= 0.95   Auto-escalate to SOC + create case + notify
        auto_investigate >= 0.80   Create case + recommend actions for approval
        human_review     >= 0.60   Generate case for analyst review
        log_only          < 0.60   Log for trend analysis only (no case)
    """

    def __init__(
        self,
        db_manager,
        rag_store=None,
        auto_respond_threshold: float = 0.95,
        auto_investigate_threshold: float = 0.80,
        auto_case_threshold: float = 0.60,
        dedup_window_hours: int = 1,
    ):
        self.db = db_manager
        self.rag_store = rag_store
        self.auto_respond_threshold = auto_respond_threshold
        self.auto_investigate_threshold = auto_investigate_threshold
        self.auto_case_threshold = auto_case_threshold
        self.dedup_window_hours = dedup_window_hours

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_and_create(
        self,
        assessment: Dict,
        hunt_cycle: int = 0,
        source: str = "autonomous",
    ) -> Optional[Case]:
        """Evaluate a hunt assessment and create a case if warranted.

        Args:
            assessment: The full assessment dict produced by
                ``MetaLearnerCoordinator.hunt()``.
            hunt_cycle: The current hunt cycle number.
            source: ``"autonomous"`` for scheduled hunts, ``"manual"`` for
                analyst-initiated.

        Returns:
            The created or updated :class:`Case`, or *None* if the
            confidence was below the case-creation threshold.
        """
        confidence = assessment.get("final_confidence", 0.0)
        escalation = self._determine_escalation(confidence)

        if escalation == EscalationLevel.LOG_ONLY:
            logger.debug(
                f"Hunt confidence {confidence:.2f} below threshold — logging only"
            )
            return None

        # Collect all finding IDs from agent outputs
        finding_ids = self._extract_finding_ids(assessment)
        mitre_techniques = assessment.get("mitre_techniques", [])
        affected_assets = self._extract_affected_assets(assessment)

        # Check for deduplication against existing open cases
        logger.info(
            f"[DEDUP] Checking dedup: techniques={mitre_techniques}, "
            f"assets={affected_assets}, window={self.dedup_window_hours}h, "
            f"findings={finding_ids}"
        )
        existing = self.db.get_open_cases_for_dedup(
            mitre_techniques=mitre_techniques,
            affected_assets=affected_assets,
            window_hours=self.dedup_window_hours,
        )
        logger.info(
            f"[DEDUP] Found {len(existing)} matching open case(s)"
            + (f": {[c['case_id'] for c in existing]}" if existing else "")
        )

        if existing:
            logger.info(
                f"[DEDUP] Merging {len(finding_ids)} findings into "
                f"existing case {existing[0]['case_id']} "
                f"(title: {existing[0].get('title', 'N/A')})"
            )
            return self._merge_into_existing(existing[0], finding_ids, assessment)

        return self._create_new_case(
            assessment, escalation, finding_ids, mitre_techniques,
            affected_assets, hunt_cycle, source,
        )

    # ------------------------------------------------------------------
    # Escalation
    # ------------------------------------------------------------------

    def _determine_escalation(self, confidence: float) -> EscalationLevel:
        """Map a confidence score to an escalation level."""
        if confidence >= self.auto_respond_threshold:
            return EscalationLevel.AUTO_RESPOND
        if confidence >= self.auto_investigate_threshold:
            return EscalationLevel.AUTO_INVESTIGATE
        if confidence >= self.auto_case_threshold:
            return EscalationLevel.HUMAN_REVIEW
        return EscalationLevel.LOG_ONLY

    # ------------------------------------------------------------------
    # Case creation
    # ------------------------------------------------------------------

    def _create_new_case(
        self,
        assessment: Dict,
        escalation: EscalationLevel,
        finding_ids: List[str],
        mitre_techniques: List[str],
        affected_assets: List[str],
        hunt_cycle: int,
        source: str,
    ) -> Case:
        """Create a brand-new case from the assessment."""
        case_id = Case.generate_id()
        severity = self._resolve_severity(assessment)
        title = self._generate_title(assessment)
        description = self._generate_description(assessment)
        kill_chain = self._extract_kill_chain(assessment)
        actions = assessment.get("recommendations", [])

        # Persist
        self.db.create_case(
            case_id=case_id,
            title=title,
            severity=severity,
            confidence=assessment.get("final_confidence", 0.0),
            description=description,
            mitre_techniques=mitre_techniques,
            affected_assets=affected_assets,
            kill_chain_stages=kill_chain,
            recommended_actions=actions,
            hunt_cycle=hunt_cycle,
            source=source,
            escalation_level=escalation.value,
            finding_ids=finding_ids,
        )

        # Index into RAG for future hypothesis generation
        self._index_case_to_rag(case_id, title, description,
                                mitre_techniques, severity)

        case = Case(
            case_id=case_id,
            title=title,
            status=CaseStatus.NEW,
            severity=severity,
            confidence=assessment.get("final_confidence", 0.0),
            description=description,
            findings=finding_ids,
            mitre_techniques=mitre_techniques,
            affected_assets=affected_assets,
            kill_chain_stages=kill_chain,
            recommended_actions=actions,
            hunt_cycle=hunt_cycle,
            source=CaseSource(source),
            escalation_level=escalation,
        )

        logger.info(
            f"Created case {case_id}: {title} "
            f"[{escalation.value}, confidence={case.confidence:.2f}]"
        )
        return case

    def _merge_into_existing(
        self,
        existing_case: Dict,
        new_finding_ids: List[str],
        assessment: Dict,
    ) -> Case:
        """Add new findings to an existing open case."""
        case_id = existing_case["case_id"]

        for fid in new_finding_ids:
            self.db.link_finding_to_case(case_id, fid)

        # Update confidence to the max of old and new
        new_confidence = max(
            existing_case["confidence"],
            assessment.get("final_confidence", 0.0),
        )
        self.db.update_case(case_id, confidence=new_confidence)

        logger.info(
            f"Merged {len(new_finding_ids)} findings into existing case "
            f"{case_id} (confidence: {new_confidence:.2f})"
        )

        # Return updated case
        updated = self.db.get_case(case_id)
        return Case.from_dict(updated)

    # ------------------------------------------------------------------
    # Field extraction helpers
    # ------------------------------------------------------------------

    def _extract_finding_ids(self, assessment: Dict) -> List[str]:
        """Extract all finding fingerprint IDs from agent outputs."""
        ids = []
        for output in assessment.get("agent_outputs", []):
            for finding in output.get("findings", []):
                fid = finding.get("fingerprint") or finding.get("finding_id", "")
                if fid:
                    ids.append(fid)
        return list(set(ids))

    def _extract_affected_assets(self, assessment: Dict) -> List[str]:
        """Collect unique affected assets from all findings."""
        assets = set()
        for output in assessment.get("agent_outputs", []):
            for finding in output.get("findings", []):
                for asset in finding.get("affected_assets", []):
                    assets.add(asset)
        return sorted(assets)

    def _resolve_severity(self, assessment: Dict) -> str:
        """Get severity string from assessment."""
        sev = assessment.get("severity", "medium")
        if hasattr(sev, "value"):
            return sev.value
        return str(sev).lower()

    def _generate_title(self, assessment: Dict) -> str:
        """Generate a concise case title from the LLM synthesis or fallback."""
        synthesis = assessment.get("llm_synthesis", {})

        # Use LLM narrative if available
        narrative = synthesis.get("threat_narrative", "")
        if narrative:
            # Take first sentence, cap at 120 chars
            first_sentence = narrative.split(".")[0].strip()
            if len(first_sentence) > 120:
                return first_sentence[:117] + "..."
            return first_sentence

        # Fallback: build from MITRE techniques
        techniques = assessment.get("mitre_techniques", [])
        confidence = assessment.get("final_confidence", 0.0)
        if techniques:
            return f"Threat activity detected: {', '.join(techniques[:3])} (confidence: {confidence:.0%})"
        return f"Automated hunt finding (confidence: {confidence:.0%})"

    def _generate_description(self, assessment: Dict) -> str:
        """Generate case description from LLM synthesis."""
        synthesis = assessment.get("llm_synthesis", {})
        narrative = synthesis.get("threat_narrative", "")
        if narrative:
            return narrative

        # Fallback: summarize findings
        finding_count = sum(
            len(o.get("findings", []))
            for o in assessment.get("agent_outputs", [])
        )
        return (
            f"Automated threat hunt detected {finding_count} findings "
            f"with aggregated confidence {assessment.get('final_confidence', 0):.2f}."
        )

    def _extract_kill_chain(self, assessment: Dict) -> List[str]:
        """Extract kill chain progression from LLM synthesis."""
        synthesis = assessment.get("llm_synthesis", {})
        progression = synthesis.get("kill_chain_progression", [])
        if isinstance(progression, list):
            stages = []
            for entry in progression:
                if isinstance(entry, dict):
                    stages.append(entry.get("stage", ""))
                elif isinstance(entry, str):
                    stages.append(entry)
            return [s for s in stages if s]
        return []

    # ------------------------------------------------------------------
    # RAG indexing
    # ------------------------------------------------------------------

    def _index_case_to_rag(
        self,
        case_id: str,
        title: str,
        description: str,
        mitre_techniques: List[str],
        severity: str,
    ):
        """Index a new case into the RAG store for future hypothesis context."""
        if not self.rag_store or not self.rag_store.available:
            return

        self.rag_store.index_finding({
            "activity_type": "autonomous_case",
            "description": f"Case {case_id}: {title}. {description}",
            "indicators": [],
            "severity": severity,
            "mitre_techniques": mitre_techniques,
            "agent_name": "case_generator",
            "confidence": 1.0,
        })
