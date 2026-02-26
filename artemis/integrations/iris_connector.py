"""
DFIR-IRIS v2.x bidirectional connector for Artemis.

Provides:
- Pull cases from IRIS for import and learning
- Push auto-generated cases from Artemis to IRIS
- Sync verdicts: when analysts resolve cases in IRIS, pull the
  verdict back to update Artemis and trigger the feedback loop
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

import requests

logger = logging.getLogger("artemis.integrations.iris")


class IRISConnector:
    """Bidirectional integration with DFIR-IRIS v2.x REST API.

    Usage::

        connector = IRISConnector(
            url="https://iris.company.com",
            api_key="your-iris-api-key",
        )
        cases = connector.pull_cases()
        connector.push_case(artemis_case)
    """

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    def test_connection(self) -> Dict:
        """Test connectivity to the IRIS API."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/versions",
                timeout=10,
            )
            if resp.status_code == 200:
                return {"status": "connected", "data": resp.json()}
            return {"status": "error", "code": resp.status_code,
                    "message": resp.text}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ------------------------------------------------------------------
    # Pull cases from IRIS
    # ------------------------------------------------------------------

    def pull_cases(self, since: Optional[datetime] = None) -> List[Dict]:
        """Pull cases from IRIS.

        Args:
            since: Only return cases modified after this datetime.

        Returns:
            List of IRIS case dicts.
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/api/v2/cases",
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            cases = data.get("data", data) if isinstance(data, dict) else data
            if not isinstance(cases, list):
                cases = [cases] if cases else []

            if since:
                cutoff = since.isoformat()
                cases = [
                    c for c in cases
                    if c.get("case_open_date", "") >= cutoff
                    or c.get("modification_history", {}).get("modified_at", "") >= cutoff
                ]

            logger.info(f"Pulled {len(cases)} cases from IRIS")
            return cases

        except Exception as e:
            logger.error(f"Failed to pull cases from IRIS: {e}")
            return []

    def pull_case_detail(self, case_id: int) -> Optional[Dict]:
        """Pull full detail for a specific IRIS case."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/v2/cases/{case_id}",
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", data)
        except Exception as e:
            logger.error(f"Failed to pull case {case_id} detail: {e}")
            return None

    def pull_case_iocs(self, case_id: int) -> List[Dict]:
        """Pull IOCs from an IRIS case."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/v2/cases/{case_id}/iocs",
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            iocs = data.get("data", data) if isinstance(data, dict) else data
            return iocs if isinstance(iocs, list) else []
        except Exception as e:
            logger.error(f"Failed to pull IOCs for case {case_id}: {e}")
            return []

    # ------------------------------------------------------------------
    # Push cases to IRIS
    # ------------------------------------------------------------------

    def push_case(self, artemis_case: Dict) -> Optional[int]:
        """Create an IRIS case from an Artemis case.

        Args:
            artemis_case: Artemis case dict (from Case.to_dict()).

        Returns:
            The IRIS case ID, or None on failure.
        """
        severity_map = {
            "critical": 4, "high": 3, "medium": 2, "low": 1,
        }

        payload = {
            "case_name": artemis_case.get("title", "Artemis Auto-Case"),
            "case_description": self._build_iris_description(artemis_case),
            "case_customer": 1,  # Default customer ID
            "case_soc_id": artemis_case.get("case_id", ""),
            "classification_id": None,
            "case_severity_id": severity_map.get(
                artemis_case.get("severity", "medium"), 2
            ),
        }

        try:
            resp = self.session.post(
                f"{self.base_url}/api/v2/cases",
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            iris_id = data.get("data", {}).get("case_id")

            if iris_id:
                logger.info(
                    f"Pushed case to IRIS: {artemis_case.get('case_id')} → "
                    f"IRIS #{iris_id}"
                )
                # Add IOCs
                self._push_iocs(iris_id, artemis_case)
            return iris_id

        except Exception as e:
            logger.error(f"Failed to push case to IRIS: {e}")
            return None

    def _push_iocs(self, iris_case_id: int, artemis_case: Dict):
        """Push affected assets and indicators as IOCs to an IRIS case."""
        assets = artemis_case.get("affected_assets", [])
        techniques = artemis_case.get("mitre_techniques", [])

        for asset in assets:
            ioc_type = 1 if self._is_ip(asset) else 6  # 1=IP, 6=other
            try:
                self.session.post(
                    f"{self.base_url}/api/v2/cases/{iris_case_id}/iocs",
                    json={
                        "ioc_value": asset,
                        "ioc_type_id": ioc_type,
                        "ioc_description": f"Affected asset from Artemis case {artemis_case.get('case_id', '')}",
                        "ioc_tags": ",".join(techniques[:5]),
                    },
                    timeout=10,
                )
            except Exception as e:
                logger.debug(f"Failed to push IOC {asset}: {e}")

    # ------------------------------------------------------------------
    # Sync verdicts
    # ------------------------------------------------------------------

    def sync_verdicts(self, linked_cases: List[Dict]) -> List[Dict]:
        """Check IRIS for resolved cases and return verdict updates.

        Args:
            linked_cases: List of Artemis cases with ``iris_case_id`` set.

        Returns:
            List of dicts ``{case_id, verdict, notes}`` for cases that
            were resolved in IRIS but still open in Artemis.
        """
        updates = []
        for case in linked_cases:
            iris_id = case.get("iris_case_id")
            if not iris_id:
                continue

            detail = self.pull_case_detail(int(iris_id))
            if not detail:
                continue

            iris_status = detail.get("case_status_id", 0)
            # IRIS statuses: 0=Open, 1=Closed, 2=Merged
            if iris_status in (1, 2) and case.get("status") in ("new", "investigating"):
                close_note = detail.get("status_name", "")
                # Map IRIS closing to Artemis verdict
                verdict = self._map_iris_verdict(detail)
                updates.append({
                    "case_id": case["case_id"],
                    "iris_case_id": iris_id,
                    "verdict": verdict,
                    "notes": f"Resolved in IRIS: {close_note}",
                })

        if updates:
            logger.info(f"Synced {len(updates)} verdict(s) from IRIS")
        return updates

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_iris_description(self, case: Dict) -> str:
        """Build a rich description for IRIS from Artemis case data."""
        parts = [
            f"**Auto-generated by Artemis** (Case: {case.get('case_id', '')})",
            "",
            case.get("description", ""),
            "",
            f"**Confidence:** {case.get('confidence', 0):.0%}",
            f"**Escalation Level:** {case.get('escalation_level', '')}",
            f"**MITRE Techniques:** {', '.join(case.get('mitre_techniques', []))}",
            f"**Affected Assets:** {', '.join(case.get('affected_assets', []))}",
            f"**Kill Chain Stages:** {', '.join(case.get('kill_chain_stages', []))}",
        ]
        actions = case.get("recommended_actions", [])
        if actions:
            parts.append("")
            parts.append("**Recommended Actions:**")
            for a in actions:
                parts.append(f"- {a}")
        return "\n".join(parts)

    @staticmethod
    def _map_iris_verdict(iris_detail: Dict) -> str:
        """Map IRIS case resolution to Artemis verdict."""
        # IRIS has classification tags; heuristic mapping
        classification = iris_detail.get("classification", "")
        if isinstance(classification, dict):
            classification = classification.get("name", "")
        classification = str(classification).lower()

        if "true" in classification or "malicious" in classification:
            return "tp"
        if "false" in classification or "benign" in classification:
            return "fp"
        return "uncertain"

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if a string looks like an IP address."""
        parts = value.split(".")
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        return ":" in value  # IPv6
