"""
Coordinator LLM — the general-purpose reasoning engine for Artemis.

Uses Claude Sonnet to:
1. Generate threat hypotheses from network state + signals + data
2. Generate specific directives for each hunting agent
3. Synthesize results from all agents into a coherent threat narrative

Falls back gracefully when the LLM is unavailable — the existing
threshold-based pipeline continues to work without it.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime

from artemis.llm.client import LLMClient
from artemis.llm.prompts import (
    COORDINATOR_HYPOTHESIS_SYSTEM,
    COORDINATOR_DIRECTIVE_SYSTEM,
    COORDINATOR_SYNTHESIS_SYSTEM,
    COORDINATOR_FOLLOWUP_SYSTEM,
    format_network_state,
    format_hunting_data_summary,
    format_agent_output,
    format_signals,
)
from artemis.models.threat_hypothesis import ThreatHypothesis, HypothesisType
from artemis.models.network_state import NetworkState
from artemis.utils.logging_config import ArtemisLogger


# Map LLM response strings → HypothesisType enum
_HYPOTHESIS_TYPE_MAP = {
    "kill_chain_stage": HypothesisType.KILL_CHAIN_STAGE,
    "ttp_pattern": HypothesisType.TTP_PATTERN,
    "anomaly_investigation": HypothesisType.ANOMALY_INVESTIGATION,
    "chain_of_events": HypothesisType.CHAIN_OF_EVENTS,
    "insider_threat": HypothesisType.INSIDER_THREAT,
    "apt_campaign": HypothesisType.APT_CAMPAIGN,
}


class CoordinatorLLM:
    """
    General LLM coordinator that directs specialized hunting agents.

    Uses Claude Sonnet to reason about the network state, generate
    hypotheses, direct agents with specific instructions, and synthesize
    a unified threat assessment from all agent outputs.
    """

    def __init__(self, client: LLMClient, rag_store=None,
                 adaptive_learner=None, db_manager=None):
        self.client = client
        self.rag_store = rag_store
        self.adaptive_learner = adaptive_learner
        self.db_manager = db_manager
        self.logger = ArtemisLogger.setup_logger("artemis.llm.coordinator")

    @property
    def available(self) -> bool:
        return self.client.available

    # ------------------------------------------------------------------
    # Stage 2: Hypothesis Generation
    # ------------------------------------------------------------------

    def generate_hypotheses(
        self,
        network_state: NetworkState,
        initial_signals: List[Dict[str, Any]],
        hunting_data: Dict[str, Any],
    ) -> Optional[List[ThreatHypothesis]]:
        """
        Reason about the network state and generate threat hypotheses.

        Returns a list of ThreatHypothesis objects, or None if the LLM
        is unavailable (the caller should fall back to the existing
        rule-based hypothesis generator).
        """
        if not self.available:
            return None

        state_text = format_network_state(network_state)
        signals_text = format_signals(initial_signals)
        data_text = format_hunting_data_summary(hunting_data)

        # RAG: inject historical context if available
        rag_context = ""
        if self.rag_store and self.rag_store.available:
            rag_context = self.rag_store.build_context(
                current_findings_text=signals_text,
                network_summary=data_text[:300],
            )
            if rag_context:
                rag_context = f"\n{rag_context}\n"

        # Technique precision context from self-learning feedback loop
        precision_context = self._build_precision_context()

        user_message = (
            f"{state_text}\n\n"
            f"{signals_text}\n\n"
            f"{data_text}\n\n"
            f"{rag_context}"
            f"{precision_context}"
            "Based on this network state, signals, data summary, "
            "historical context, and technique precision data above, "
            "generate threat hypotheses. "
            "Consider what attacks could be in progress, what kill chain "
            "stages might be active, which agents should investigate, and "
            "whether similar patterns were seen in the past. "
            "Prioritize techniques with high historical precision (confirmed TP) "
            "and deprioritize techniques that frequently produce false positives."
        )

        result = self.client.coordinator_json(
            messages=[{"role": "user", "content": user_message}],
            system=COORDINATOR_HYPOTHESIS_SYSTEM,
            max_tokens=4096,
        )

        if result is None:
            self.logger.warning("Hypothesis generation LLM call failed")
            return None

        hypotheses = []
        for i, h in enumerate(result.get("hypotheses", [])):
            try:
                hyp_type = _HYPOTHESIS_TYPE_MAP.get(
                    h.get("type", "anomaly_investigation"),
                    HypothesisType.ANOMALY_INVESTIGATION,
                )
                hypothesis = ThreatHypothesis(
                    hypothesis_id=f"llm_hyp_{datetime.utcnow().timestamp()}_{i}",
                    hypothesis_type=hyp_type,
                    description=h.get("description", ""),
                    initial_indicators=h.get("indicators", []),
                    suggested_agents=h.get("suggested_agents", []),
                    priority=float(h.get("priority", 0.5)),
                    confidence=float(h.get("confidence", 0.3)),
                    kill_chain_stages=h.get("kill_chain_stages", []),
                    expected_ttps=h.get("expected_ttps", []),
                    metadata={
                        "source": "coordinator_llm",
                        "reasoning": h.get("reasoning", ""),
                    },
                )
                hypotheses.append(hypothesis)
            except Exception as e:
                self.logger.warning(f"Failed to parse hypothesis {i}: {e}")

        risk = result.get("overall_risk_assessment", "unknown")
        reasoning = result.get("reasoning", "")
        self.logger.info(
            f"LLM generated {len(hypotheses)} hypotheses "
            f"(risk={risk}): {reasoning[:120]}"
        )

        return hypotheses

    def _build_precision_context(self) -> str:
        """Build technique precision context from the self-learning feedback loop.

        Queries the technique_precision table and formats it for the LLM
        prompt, helping it weight hypotheses by historical reliability.
        """
        if not self.db_manager:
            return ""

        try:
            precision_data = self.db_manager.get_technique_precision()
            if not precision_data:
                return ""

            lines = [
                "=== TECHNIQUE PRECISION (from past case outcomes) ==="
            ]

            # Group by reliability tier
            high = []
            low = []
            for tech_id, data in precision_data.items():
                total = data["true_positives"] + data["false_positives"]
                if total < 2:
                    continue  # Not enough data
                p = data["precision"]
                label = f"{tech_id} (precision={p:.0%}, TP={data['true_positives']}, FP={data['false_positives']})"
                if p >= 0.7:
                    high.append(label)
                elif p < 0.3:
                    low.append(label)

            if high:
                lines.append("High-precision (reliable indicators):")
                for h in high[:10]:
                    lines.append(f"  + {h}")
            if low:
                lines.append("Low-precision (frequent false positives):")
                for l in low[:10]:
                    lines.append(f"  - {l}")

            if len(lines) <= 1:
                return ""

            return "\n".join(lines) + "\n\n"
        except Exception as e:
            self.logger.debug(f"Could not build precision context: {e}")
            return ""

    # ------------------------------------------------------------------
    # Stage 3.5: Agent Directive Generation
    # ------------------------------------------------------------------

    def generate_directives(
        self,
        hypotheses: List[ThreatHypothesis],
        selected_agents: List[str],
        network_state: NetworkState,
    ) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Generate specific instructions for each selected agent.

        Returns dict mapping agent_name -> directive, or None.
        """
        if not self.available:
            return None

        state_text = format_network_state(network_state)

        hyp_lines = []
        for h in hypotheses:
            hyp_lines.append(
                f"- [{h.hypothesis_type.value}] {h.description} "
                f"(priority={h.priority:.2f}, confidence={h.confidence:.2f})\n"
                f"  Suggested agents: {', '.join(h.suggested_agents)}\n"
                f"  Kill chain: {', '.join(h.kill_chain_stages)}"
            )
        hyp_text = (
            "\n".join(hyp_lines)
            if hyp_lines
            else "No specific hypotheses — run baseline detection."
        )

        user_message = (
            f"{state_text}\n\n"
            f"=== THREAT HYPOTHESES ===\n{hyp_text}\n\n"
            f"Selected agents: {', '.join(selected_agents)}\n\n"
            "Generate specific directives for each selected agent. "
            "Tell each agent what patterns to prioritize, which IPs "
            "to scrutinize, and what context is relevant."
        )

        result = self.client.coordinator_json(
            messages=[{"role": "user", "content": user_message}],
            system=COORDINATOR_DIRECTIVE_SYSTEM,
            max_tokens=3000,
        )

        if result is None:
            self.logger.warning("Directive generation LLM call failed")
            return None

        directives = result.get("directives", {})
        self.logger.info(
            f"LLM generated directives for {len(directives)} agents"
        )
        return directives

    # ------------------------------------------------------------------
    # Stage 5.5: Result Synthesis
    # ------------------------------------------------------------------

    def synthesize_results(
        self,
        agent_outputs: list,
        network_state: NetworkState,
    ) -> Optional[Dict[str, Any]]:
        """
        Synthesize all agent outputs into a unified threat narrative.

        Returns a synthesis dict or None if unavailable or nothing to
        synthesize.
        """
        if not self.available:
            return None

        # Only synthesize if there are findings worth analyzing
        total_findings = sum(len(o.findings) for o in agent_outputs)
        if total_findings == 0:
            return None

        state_text = format_network_state(network_state)
        outputs_text = "\n\n".join(
            format_agent_output(o) for o in agent_outputs if o.findings
        )

        # RAG: inject historical context for synthesis
        rag_context = ""
        if self.rag_store and self.rag_store.available:
            rag_context = self.rag_store.build_context(
                current_findings_text=outputs_text[:800],
                network_summary="",
                n_findings=5,
                n_baselines=2,
                n_intel=3,
            )
            if rag_context:
                rag_context = f"\n{rag_context}\n"

        user_message = (
            f"{state_text}\n\n"
            f"=== AGENT OUTPUTS ===\n{outputs_text}\n\n"
            f"{rag_context}"
            "Synthesize these agent findings into a unified threat "
            "assessment. Identify correlations, assess kill chain "
            "progression, flag likely false positives, and recommend "
            "specific response actions.  If historical findings are "
            "shown above, use them to assess whether current detections "
            "match known patterns or were previously dismissed."
        )

        result = self.client.coordinator_json(
            messages=[{"role": "user", "content": user_message}],
            system=COORDINATOR_SYNTHESIS_SYSTEM,
            max_tokens=4096,
        )

        if result is None:
            self.logger.warning("Synthesis LLM call failed")
            return None

        self.logger.info(
            f"LLM synthesis: severity={result.get('overall_severity', '?')}, "
            f"confidence={result.get('overall_confidence', 0):.2f}"
        )
        return result

    # ------------------------------------------------------------------
    # Follow-up Evaluation
    # ------------------------------------------------------------------

    def evaluate_followup(
        self,
        agent_outputs: list,
        network_state: NetworkState,
        iteration: int,
        all_agents: list,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate whether a follow-up hunting round is needed.

        Examines current findings and determines if unexplored leads,
        partial kill chains, or suspicious patterns warrant another round
        with different or additional agents.

        Args:
            agent_outputs: Findings from the current round.
            network_state: Current network context.
            iteration: Current iteration number (1-based).
            all_agents: Names of all available agents.

        Returns:
            Dict with continue_hunting, reasoning, and followup_hypotheses,
            or None if the LLM is unavailable.
        """
        if not self.available:
            return None

        total_findings = sum(len(o.findings) for o in agent_outputs)
        if total_findings == 0:
            return {"continue_hunting": False,
                    "reasoning": "No findings to follow up on",
                    "followup_hypotheses": []}

        state_text = format_network_state(network_state)
        outputs_text = "\n\n".join(
            format_agent_output(o) for o in agent_outputs if o.findings
        )
        agents_that_ran = [o.agent_name for o in agent_outputs]
        agents_available = [a for a in all_agents if a not in agents_that_ran]

        user_message = (
            f"Hunt iteration: {iteration}\n"
            f"Agents that ran this round: {', '.join(agents_that_ran)}\n"
            f"Agents available for follow-up: {', '.join(agents_available) or 'none (all ran)'}\n\n"
            f"{state_text}\n\n"
            f"=== CURRENT FINDINGS ===\n{outputs_text}\n\n"
            "Evaluate whether a follow-up hunting round is warranted. "
            "Consider partial kill chains, unexplored IOCs, and whether "
            "different agents could provide corroborating evidence."
        )

        result = self.client.coordinator_json(
            messages=[{"role": "user", "content": user_message}],
            system=COORDINATOR_FOLLOWUP_SYSTEM,
            max_tokens=2048,
        )

        if result is None:
            self.logger.warning("Follow-up evaluation LLM call failed")
            return None

        should_continue = result.get("continue_hunting", False)
        self.logger.info(
            f"Follow-up evaluation (iter {iteration}): "
            f"continue={should_continue}, "
            f"reason={result.get('reasoning', '?')[:100]}"
        )
        return result
