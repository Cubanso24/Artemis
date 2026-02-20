"""
Agent LLM — specialist LLM wrapper for hunting agents.

Uses Claude Haiku for fast, domain-specific analysis. Each agent gets a
specialized system prompt that functions as its "fine-tuning", giving it
deep expertise in a particular threat domain.

The LLM receives:
1. Its specialist system prompt (domain expertise)
2. The coordinator's directive (what to focus on)
3. The threshold-based detection findings
4. A summary of the raw hunting data

It returns:
- Enriched findings with confidence adjustments and reasoning
- Patterns the threshold detector may have missed
"""

from typing import Dict, List, Any, Optional

from artemis.llm.client import LLMClient
from artemis.llm.prompts import (
    AGENT_SYSTEM_PROMPTS,
    format_findings_for_review,
    format_hunting_data_summary,
    format_network_state,
)
from artemis.models.agent_output import AgentOutput, Finding, Evidence, Severity
from artemis.models.network_state import NetworkState
from artemis.utils.logging_config import ArtemisLogger


class AgentLLM:
    """
    Specialist LLM wrapper that enriches hunting agent analysis.

    Each instance is bound to one agent and uses a domain-specific system
    prompt.  The coordinator creates one AgentLLM per hunting agent and
    calls ``enrich_output`` after the threshold-based detection runs.
    """

    def __init__(self, client: LLMClient, agent_name: str):
        self.client = client
        self.agent_name = agent_name
        self.system_prompt = AGENT_SYSTEM_PROMPTS.get(agent_name, "")
        self.logger = ArtemisLogger.setup_logger(
            f"artemis.llm.agent.{agent_name}"
        )

        if not self.system_prompt:
            self.logger.warning(
                f"No specialist prompt for agent '{agent_name}' — "
                f"LLM enrichment disabled for this agent"
            )

    @property
    def available(self) -> bool:
        return self.client.available and bool(self.system_prompt)

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def enrich_output(
        self,
        output: AgentOutput,
        directive: Optional[Dict[str, Any]],
        hunting_data: Dict[str, Any],
        network_state: Optional[NetworkState] = None,
    ) -> AgentOutput:
        """
        Use the specialist LLM to review and enrich agent findings.

        Modifies the AgentOutput in place:
        - Adjusts confidence based on LLM assessment
        - Stores LLM reasoning in evidence metadata
        - Adds missed patterns as new findings

        If the LLM is unavailable or the call fails, returns the output
        unchanged.
        """
        if not self.available or not output.findings:
            return output

        enrichment = self._call_llm(output, directive, hunting_data, network_state)
        if enrichment is None:
            return output

        return self._apply_enrichment(output, enrichment)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    def _call_llm(
        self,
        output: AgentOutput,
        directive: Optional[Dict[str, Any]],
        hunting_data: Dict[str, Any],
        network_state: Optional[NetworkState],
    ) -> Optional[Dict[str, Any]]:
        """Call the agent LLM and return parsed JSON, or None on failure."""
        data_summary = format_hunting_data_summary(hunting_data)
        findings_text = format_findings_for_review(
            output.findings, data_summary
        )

        # Build context from coordinator directive
        directive_text = ""
        if directive:
            directive_text = (
                "\n=== COORDINATOR DIRECTIVE ===\n"
                f"Focus areas: {', '.join(directive.get('focus_areas', []))}\n"
                f"Priority IPs: {', '.join(directive.get('priority_ips', []))}\n"
                f"Context: {directive.get('context_notes', 'None')}\n"
                f"Threshold adjustment: "
                f"{directive.get('threshold_adjustments', 'normal')}\n"
            )

        state_text = ""
        if network_state:
            state_text = format_network_state(network_state) + "\n\n"

        user_message = (
            f"{state_text}"
            f"{directive_text}\n"
            f"{findings_text}\n\n"
            "Review these findings from the threshold-based detector. "
            "For each finding, assess whether it's a true positive or "
            "false positive, adjust confidence, explain your reasoning, "
            "and note any patterns the detector may have missed."
        )

        result = self.client.agent_json(
            messages=[{"role": "user", "content": user_message}],
            system=self.system_prompt,
            max_tokens=3000,
        )

        if result is None:
            self.logger.warning(
                f"Agent LLM enrichment failed for {self.agent_name}"
            )
            return None

        enriched_count = len(result.get("enriched_findings", []))
        missed_count = len(result.get("missed_patterns", []))
        self.logger.info(
            f"Agent LLM enriched {enriched_count} findings, "
            f"found {missed_count} missed patterns for {self.agent_name}"
        )
        return result

    # ------------------------------------------------------------------
    # Apply enrichment
    # ------------------------------------------------------------------

    def _apply_enrichment(
        self,
        output: AgentOutput,
        enrichment: Dict[str, Any],
    ) -> AgentOutput:
        """Apply LLM enrichment to the AgentOutput."""
        enriched_findings = enrichment.get("enriched_findings", [])

        # Track net confidence adjustments
        confidence_adjustments: List[float] = []

        # Annotate each existing finding with LLM assessment
        for i, finding in enumerate(output.findings):
            if i >= len(enriched_findings):
                break

            ef = enriched_findings[i]
            adjustment = float(ef.get("confidence_adjustment", 0))
            assessment = ef.get("assessment", "uncertain")
            reasoning = ef.get("reasoning", "")

            confidence_adjustments.append(adjustment)

            # Store LLM assessment in the primary evidence entry
            if finding.evidence:
                finding.evidence[0].data["llm_assessment"] = assessment
                finding.evidence[0].data["llm_reasoning"] = reasoning
                finding.evidence[0].data["llm_confidence_adj"] = adjustment

        # Apply the average confidence adjustment to the overall score
        if confidence_adjustments:
            avg_adj = sum(confidence_adjustments) / len(confidence_adjustments)
            output.confidence = max(
                0.0, min(1.0, output.confidence + avg_adj)
            )

        # Add missed patterns as new findings
        missed = enrichment.get("missed_patterns", [])
        from datetime import datetime

        for mp in missed:
            desc = mp.get("description", "")
            indicators = mp.get("indicators", [])
            conf = float(mp.get("confidence", 0.4))
            if not desc:
                continue

            new_finding = Finding(
                activity_type=f"llm_detected_{self.agent_name}",
                description=f"[LLM] {desc}",
                indicators=indicators,
                evidence=[
                    Evidence(
                        timestamp=datetime.utcnow(),
                        source=f"llm_agent_{self.agent_name}",
                        data={"llm_detected": True, "raw_pattern": mp},
                        description=desc,
                        confidence_contribution=conf,
                    )
                ],
                affected_assets=indicators[:3],
            )
            output.findings.append(new_finding)

            # Bump overall confidence if a missed pattern is high-confidence
            if conf > output.confidence:
                output.confidence = min(1.0, conf)

        # Re-assess severity after adjustments
        if output.confidence >= 0.8:
            output.severity = Severity.CRITICAL
        elif output.confidence >= 0.6:
            output.severity = Severity.HIGH
        elif output.confidence >= 0.4:
            output.severity = Severity.MEDIUM
        else:
            output.severity = Severity.LOW

        # Store enrichment metadata
        output.metadata["llm_enrichment"] = {
            "enriched_count": len(enriched_findings),
            "missed_pattern_count": len(missed),
            "avg_confidence_adjustment": (
                sum(confidence_adjustments) / len(confidence_adjustments)
                if confidence_adjustments
                else 0.0
            ),
        }

        return output
