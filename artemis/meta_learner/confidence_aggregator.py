"""
Confidence aggregation module for the meta-learner.

Aggregates findings from multiple agents into unified threat assessments
with corroboration scoring and false positive dampening.
"""

from typing import Dict, List, Tuple, Optional
from datetime import datetime
import logging

from artemis.models.agent_output import AgentOutput, Severity
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import MITREAttack
from artemis.utils.logging_config import ArtemisLogger


class ConfidenceAggregator:
    """
    Aggregates and correlates findings from multiple agents.

    Implements corroboration scoring, kill chain progression weighting,
    and false positive dampening.
    """

    def __init__(self):
        self.logger = ArtemisLogger.setup_logger("artemis.meta_learner.aggregator")

    def aggregate_outputs(
        self,
        agent_outputs: List[AgentOutput],
        context: NetworkState
    ) -> Dict[str, any]:
        """
        Aggregate outputs from multiple agents.

        Args:
            agent_outputs: List of agent outputs to aggregate
            context: Current network state

        Returns:
            Aggregated assessment with confidence and severity
        """
        if not agent_outputs:
            return self._create_empty_assessment()

        # Apply corroboration scoring
        corroborated_outputs = self._apply_corroboration(agent_outputs)

        # Apply kill chain progression weighting
        weighted_outputs = self._apply_kill_chain_weighting(corroborated_outputs)

        # Apply false positive dampening
        dampened_outputs = self._apply_fp_dampening(weighted_outputs)

        # Calculate final confidence
        final_confidence = self._calculate_final_confidence(dampened_outputs)

        # Determine overall severity
        overall_severity = self._determine_overall_severity(dampened_outputs)

        # Extract all findings
        all_findings = []
        for output in agent_outputs:
            all_findings.extend(output.findings)

        # Extract all MITRE techniques
        all_techniques = set()
        for output in agent_outputs:
            all_techniques.update(output.mitre_techniques)

        # Generate aggregated recommendations
        recommendations = self._aggregate_recommendations(agent_outputs, final_confidence)

        # Determine alert level
        alert_level = self._determine_alert_level(final_confidence)

        assessment = {
            "timestamp": datetime.utcnow(),
            "final_confidence": final_confidence,
            "severity": overall_severity,
            "alert_level": alert_level,
            "agent_count": len(agent_outputs),
            "corroborating_agents": len([o for o in dampened_outputs if o["adjusted_confidence"] > 0.5]),
            "total_findings": len(all_findings),
            "findings": all_findings,
            "mitre_techniques": list(all_techniques),
            "recommendations": recommendations,
            "agent_outputs": [o.to_dict() for o in agent_outputs],
            "context_summary": context.get_context_summary()
        }

        self.logger.info(
            f"Aggregated {len(agent_outputs)} outputs: "
            f"confidence={final_confidence:.2f}, severity={overall_severity.value}"
        )

        return assessment

    def _create_empty_assessment(self) -> Dict[str, any]:
        """Create empty assessment when no outputs."""
        return {
            "timestamp": datetime.utcnow(),
            "final_confidence": 0.0,
            "severity": Severity.LOW,
            "alert_level": "none",
            "agent_count": 0,
            "corroborating_agents": 0,
            "total_findings": 0,
            "findings": [],
            "mitre_techniques": [],
            "recommendations": [],
            "agent_outputs": []
        }

    def _apply_corroboration(
        self,
        outputs: List[AgentOutput]
    ) -> List[Dict[str, any]]:
        """
        Apply corroboration scoring.

        When multiple agents detect related activity, boost confidence.
        Corroboration_Boost = 1 + (0.2 × number_of_confirming_agents)
        """
        corroborated = []

        # Find corroborating evidence (overlapping MITRE techniques)
        technique_agents = {}
        for output in outputs:
            for technique in output.mitre_techniques:
                if technique not in technique_agents:
                    technique_agents[technique] = []
                technique_agents[technique].append(output.agent_name)

        for output in outputs:
            # Count corroborating agents
            corroboration_count = 0
            for technique in output.mitre_techniques:
                # How many other agents detected this technique?
                corroboration_count += len(technique_agents[technique]) - 1

            # Calculate boost
            boost = 1.0 + (0.2 * min(corroboration_count, 3))  # Cap at 3 agents

            corroborated.append({
                "agent_name": output.agent_name,
                "original_confidence": output.confidence,
                "corroboration_boost": boost,
                "boosted_confidence": min(output.confidence * boost, 1.0),
                "output": output,
                "corroborating_agents": corroboration_count
            })

        return corroborated

    def _apply_kill_chain_weighting(
        self,
        outputs: List[Dict[str, any]]
    ) -> List[Dict[str, any]]:
        """
        Apply kill chain progression weighting.

        Sequential detections across kill chain stages increase confidence.
        Chain_Multiplier = 1.5 if (Reconnaissance → Access → Execution detected)
        """
        # Extract detected tactics
        detected_tactics = []
        for output_dict in outputs:
            output = output_dict["output"]
            detected_tactics.extend(output.mitre_tactics)

        # Convert to KillChainStage objects
        tactic_stages = []
        for tactic_id in detected_tactics:
            try:
                from artemis.utils.mitre_attack import KillChainStage
                stage = KillChainStage(tactic_id)
                tactic_stages.append(stage)
            except ValueError:
                continue

        # Check if tactics follow kill chain progression
        is_progression = False
        if len(tactic_stages) >= 2:
            is_progression = MITREAttack.is_kill_chain_progression(tactic_stages)

        # Apply multiplier
        chain_multiplier = 1.5 if is_progression else 1.0

        for output_dict in outputs:
            output_dict["chain_multiplier"] = chain_multiplier
            output_dict["chain_weighted_confidence"] = min(
                output_dict["boosted_confidence"] * chain_multiplier,
                1.0
            )

        if is_progression:
            self.logger.warning("Kill chain progression detected - boosting confidence")

        return outputs

    def _apply_fp_dampening(
        self,
        outputs: List[Dict[str, any]]
    ) -> List[Dict[str, any]]:
        """
        Apply false positive dampening.

        Agents with high historical false positive rates get weighted down.
        Adjusted_Confidence = Agent_Confidence × (1 - FP_Rate × 0.5)
        """
        for output_dict in outputs:
            output = output_dict["output"]
            agent_name = output.agent_name

            # Get FP rate from agent metadata (if available)
            fp_rate = output.metadata.get("false_positive_rate", 0.0)

            # Apply dampening
            dampening_factor = 1.0 - (fp_rate * 0.5)
            adjusted_confidence = output_dict["chain_weighted_confidence"] * dampening_factor

            output_dict["fp_dampening"] = dampening_factor
            output_dict["adjusted_confidence"] = adjusted_confidence

        return outputs

    def _calculate_final_confidence(
        self,
        outputs: List[Dict[str, any]]
    ) -> float:
        """
        Calculate final aggregated confidence score.

        Uses maximum confidence from corroborated outputs.
        """
        if not outputs:
            return 0.0

        # Take maximum adjusted confidence
        max_confidence = max(o["adjusted_confidence"] for o in outputs)

        # If multiple high-confidence agents agree, boost further
        high_conf_agents = [o for o in outputs if o["adjusted_confidence"] > 0.7]
        if len(high_conf_agents) >= 2:
            max_confidence = min(max_confidence * 1.1, 1.0)

        return max_confidence

    def _determine_overall_severity(
        self,
        outputs: List[Dict[str, any]]
    ) -> Severity:
        """Determine overall severity from agent outputs."""
        if not outputs:
            return Severity.LOW

        # Take maximum severity
        severities = [o["output"].severity for o in outputs]
        return max(severities)

    def _determine_alert_level(self, confidence: float) -> str:
        """
        Determine alert level based on confidence thresholds.

        Confidence > 0.9: critical (auto-escalate to SOC)
        Confidence 0.7-0.9: high (analyst review recommended)
        Confidence 0.5-0.7: medium (watchlist monitoring)
        Confidence < 0.5: low (log for pattern analysis)
        """
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def _aggregate_recommendations(
        self,
        outputs: List[AgentOutput],
        confidence: float
    ) -> List[str]:
        """Aggregate recommendations from all agents."""
        all_recommendations = set()

        for output in outputs:
            all_recommendations.update(output.recommended_actions)

        # Add confidence-based recommendations
        if confidence >= 0.9:
            all_recommendations.add("IMMEDIATE: Escalate to SOC for investigation")
            all_recommendations.add("Consider automated containment actions")
        elif confidence >= 0.7:
            all_recommendations.add("Analyst review recommended within 1 hour")
            all_recommendations.add("Monitor for escalation")

        return list(all_recommendations)

    def calculate_correlation_score(
        self,
        outputs: List[AgentOutput]
    ) -> float:
        """
        Calculate correlation score between agent findings.

        Returns score from 0.0 (no correlation) to 1.0 (full correlation).
        """
        if len(outputs) < 2:
            return 0.0

        # Compare MITRE techniques across agents
        technique_sets = [set(o.mitre_techniques) for o in outputs]

        # Calculate pairwise Jaccard similarity
        similarities = []
        for i in range(len(technique_sets)):
            for j in range(i + 1, len(technique_sets)):
                set_i = technique_sets[i]
                set_j = technique_sets[j]

                if not set_i and not set_j:
                    continue

                intersection = len(set_i & set_j)
                union = len(set_i | set_j)

                if union > 0:
                    similarity = intersection / union
                    similarities.append(similarity)

        if not similarities:
            return 0.0

        # Average similarity
        return sum(similarities) / len(similarities)
