"""
Historical case ingestion from DFIR-IRIS.

Pulls existing cases from IRIS, converts them to Artemis format, indexes
them into ChromaDB for RAG, and seeds the technique precision table and
adaptive learner with analyst verdicts — calibrating Artemis against real
analyst decisions before it begins autonomous hunting.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from artemis.models.case import Case, CaseStatus, CaseSource, EscalationLevel

logger = logging.getLogger("artemis.integrations.iris_ingest")


class IRISCaseIngestor:
    """Import historical cases from IRIS into Artemis.

    Usage::

        ingestor = IRISCaseIngestor(iris_connector, db_manager, rag_store)
        stats = ingestor.ingest_all()
    """

    def __init__(self, iris_connector, db_manager, rag_store=None,
                 adaptive_learner=None):
        self.iris = iris_connector
        self.db = db_manager
        self.rag = rag_store
        self.adaptive_learner = adaptive_learner

    def ingest_all(self, since: Optional[datetime] = None) -> Dict:
        """Pull all cases from IRIS and import them.

        Args:
            since: Only import cases modified after this date.
                Pass None to import all cases.

        Returns:
            Summary stats: ``{imported, skipped, errors, techniques_seeded}``.
        """
        stats = {"imported": 0, "skipped": 0, "errors": 0,
                 "techniques_seeded": set()}

        cases = self.iris.pull_cases(since=since)
        logger.info(f"Retrieved {len(cases)} cases from IRIS for import")

        for iris_case in cases:
            try:
                result = self._import_case(iris_case)
                if result == "imported":
                    stats["imported"] += 1
                    # Track techniques for seeding report
                    techniques = self._extract_techniques(iris_case)
                    stats["techniques_seeded"].update(techniques)
                elif result == "skipped":
                    stats["skipped"] += 1
            except Exception as e:
                stats["errors"] += 1
                logger.error(
                    f"Failed to import IRIS case "
                    f"{iris_case.get('case_id', '?')}: {e}"
                )

        stats["techniques_seeded"] = list(stats["techniques_seeded"])
        logger.info(
            f"IRIS import complete: {stats['imported']} imported, "
            f"{stats['skipped']} skipped, {stats['errors']} errors, "
            f"{len(stats['techniques_seeded'])} techniques seeded"
        )
        return stats

    def _import_case(self, iris_case: Dict) -> str:
        """Import a single IRIS case into Artemis.

        Returns "imported" or "skipped".
        """
        iris_id = str(iris_case.get("case_id", ""))

        # Check for duplicates: skip if this IRIS case was already imported
        existing = self.db.get_cases(limit=500, source="iris_import")
        for e in existing:
            if e.get("iris_case_id") == iris_id:
                return "skipped"

        # Pull full detail + IOCs
        detail = self.iris.pull_case_detail(int(iris_id)) if iris_id.isdigit() else iris_case
        iocs = self.iris.pull_case_iocs(int(iris_id)) if iris_id.isdigit() else []

        # Map IRIS fields to Artemis Case
        case_id = Case.generate_id()
        title = iris_case.get("case_name", f"IRIS Case #{iris_id}")
        description = iris_case.get("case_description", "")
        severity = self._map_severity(iris_case.get("case_severity_id", 2))
        techniques = self._extract_techniques(iris_case)
        affected_assets = self._extract_assets(iocs)
        verdict = self._determine_verdict(iris_case, detail)

        # Set status based on IRIS resolution
        status_id = iris_case.get("case_status_id", 0)
        if status_id in (1, 2):  # Closed or Merged
            status = "confirmed_tp" if verdict == "tp" else (
                "confirmed_fp" if verdict == "fp" else "closed"
            )
        else:
            status = "investigating"

        # Create in Artemis DB
        self.db.create_case(
            case_id=case_id,
            title=title,
            severity=severity,
            confidence=0.5,  # No confidence score from analyst cases
            description=description,
            mitre_techniques=techniques,
            affected_assets=affected_assets,
            kill_chain_stages=[],
            recommended_actions=[],
            hunt_cycle=0,
            source="iris_import",
            escalation_level="human_review",
        )
        # Set additional fields
        self.db.update_case(
            case_id,
            iris_case_id=iris_id,
            status=status,
            analyst_verdict=verdict if status_id in (1, 2) else None,
            analyst_notes=f"Imported from IRIS case #{iris_id}",
        )

        # Seed technique precision from resolved cases
        if verdict and status_id in (1, 2):
            for tech in techniques:
                self.db.update_technique_precision(tech, verdict)

        # Index into RAG for future hypothesis generation
        if self.rag and self.rag.available:
            self.rag.index_finding({
                "activity_type": "iris_imported_case",
                "description": f"IRIS Case #{iris_id}: {title}. {description}",
                "indicators": [ioc.get("ioc_value", "") for ioc in iocs[:20]],
                "severity": severity,
                "mitre_techniques": techniques,
                "agent_name": "iris_import",
                "confidence": 0.5,
                "analyst_feedback": verdict or "",
            })

        logger.info(
            f"Imported IRIS case #{iris_id} → {case_id} "
            f"(verdict={verdict}, techniques={techniques})"
        )
        return "imported"

    # ------------------------------------------------------------------
    # Field extraction helpers
    # ------------------------------------------------------------------

    def _extract_techniques(self, iris_case: Dict) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from IRIS case data."""
        techniques = []

        # IRIS may store techniques in tags, custom attributes, or notes
        tags = iris_case.get("case_tags", "")
        if isinstance(tags, str):
            # Look for T-codes in tags
            import re
            techniques.extend(re.findall(r'T\d{4}(?:\.\d{3})?', tags))

        # Check classification
        classification = iris_case.get("classification", "")
        if isinstance(classification, dict):
            class_name = classification.get("name", "")
            import re
            techniques.extend(re.findall(r'T\d{4}(?:\.\d{3})?', class_name))

        return list(set(techniques))

    def _extract_assets(self, iocs: List[Dict]) -> List[str]:
        """Extract affected assets from IRIS IOCs."""
        assets = []
        for ioc in iocs:
            value = ioc.get("ioc_value", "")
            if value:
                assets.append(value)
        return assets[:50]  # Cap at 50 assets

    @staticmethod
    def _map_severity(iris_severity_id) -> str:
        """Map IRIS severity ID to Artemis severity string."""
        mapping = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        return mapping.get(iris_severity_id, "medium")

    def _determine_verdict(self, iris_case: Dict,
                           detail: Optional[Dict]) -> Optional[str]:
        """Determine TP/FP verdict from IRIS case resolution."""
        if detail:
            return self.iris._map_iris_verdict(detail)

        # Fallback: check if case is closed
        status = iris_case.get("case_status_id", 0)
        if status in (1, 2):
            return "uncertain"
        return None
