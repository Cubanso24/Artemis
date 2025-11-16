"""
Agent selection module for the meta-learner.

Implements priority scoring and selection logic for determining
which agents to activate based on threat hypotheses and context.
"""

from typing import Dict, List, Tuple, Optional
from datetime import datetime
import logging

from artemis.models.network_state import NetworkState
from artemis.models.threat_hypothesis import ThreatHypothesis
from artemis.utils.mitre_attack import MITREAttack, KillChainStage
from artemis.utils.logging_config import ArtemisLogger


class AgentSelector:
    """
    Selects and prioritizes agents based on context and hypotheses.

    Implements the priority scoring system and kill chain progression logic.
    """

    def __init__(self):
        self.logger = ArtemisLogger.setup_logger("artemis.meta_learner.selector")

        # Priority scoring weights
        self.weights = {
            "threat_relevance": 0.4,
            "asset_criticality": 0.3,
            "temporal_urgency": 0.2,
            "agent_confidence_history": 0.1
        }

        # Agent performance history (for adaptive weighting)
        self.agent_history: Dict[str, Dict[str, float]] = {}

    def select_agents(
        self,
        hypotheses: List[ThreatHypothesis],
        context: NetworkState,
        available_agents: List[str],
        mode: str = "adaptive"
    ) -> List[Tuple[str, float]]:
        """
        Select agents to activate based on hypotheses and context.

        Args:
            hypotheses: Current threat hypotheses
            context: Network state context
            available_agents: List of available agent names
            mode: Selection mode ("adaptive", "parallel", "sequential")

        Returns:
            List of (agent_name, priority_score) tuples, sorted by priority
        """
        if mode == "parallel":
            return self._parallel_selection(available_agents)
        elif mode == "sequential":
            return self._sequential_selection(hypotheses, available_agents)
        else:  # adaptive (default)
            return self._adaptive_selection(hypotheses, context, available_agents)

    def _parallel_selection(self, available_agents: List[str]) -> List[Tuple[str, float]]:
        """
        Parallel mode: Activate all agents simultaneously.

        Used for high-priority alerts or known active threats.
        """
        self.logger.info("Parallel mode: Activating all agents")
        return [(agent, 0.8) for agent in available_agents]

    def _sequential_selection(
        self,
        hypotheses: List[ThreatHypothesis],
        available_agents: List[str]
    ) -> List[Tuple[str, float]]:
        """
        Sequential mode: Activate agents based on hypothesis suggestions.

        More efficient, activates only relevant agents.
        """
        agent_priorities = {}

        for hypothesis in hypotheses:
            for agent in hypothesis.suggested_agents:
                if agent in available_agents:
                    # Use hypothesis priority as base
                    priority = hypothesis.priority
                    agent_priorities[agent] = max(
                        agent_priorities.get(agent, 0),
                        priority
                    )

        self.logger.info(f"Sequential mode: Activating {len(agent_priorities)} agents")
        return sorted(agent_priorities.items(), key=lambda x: x[1], reverse=True)

    def _adaptive_selection(
        self,
        hypotheses: List[ThreatHypothesis],
        context: NetworkState,
        available_agents: List[str]
    ) -> List[Tuple[str, float]]:
        """
        Adaptive mode: Intelligent selection based on context and performance.

        Balances exploration/exploitation using agent history.
        """
        agent_scores = {}

        # Start with hypothesis-suggested agents
        suggested_agents = set()
        for hypothesis in hypotheses:
            suggested_agents.update(hypothesis.suggested_agents)

        # Score each agent
        for agent in available_agents:
            score = self._calculate_priority_score(
                agent,
                hypotheses,
                context,
                is_suggested=(agent in suggested_agents)
            )
            agent_scores[agent] = score

        # Always include baseline monitoring agents
        baseline_agents = ["c2_hunter", "reconnaissance_hunter", "defense_evasion_hunter"]
        for agent in baseline_agents:
            if agent in available_agents:
                agent_scores[agent] = max(agent_scores.get(agent, 0), 0.5)

        # Filter out low-priority agents (< 0.3)
        filtered_scores = {
            agent: score
            for agent, score in agent_scores.items()
            if score >= 0.3
        }

        self.logger.info(f"Adaptive mode: Activating {len(filtered_scores)} agents")
        return sorted(filtered_scores.items(), key=lambda x: x[1], reverse=True)

    def _calculate_priority_score(
        self,
        agent_name: str,
        hypotheses: List[ThreatHypothesis],
        context: NetworkState,
        is_suggested: bool = False
    ) -> float:
        """
        Calculate priority score for an agent.

        Priority_Score = (Threat_Relevance × 0.4) +
                        (Asset_Criticality × 0.3) +
                        (Temporal_Urgency × 0.2) +
                        (Agent_Confidence_History × 0.1)
        """
        # Threat relevance
        threat_relevance = 0.0
        if is_suggested:
            # Agent was suggested by hypothesis
            threat_relevance = 0.8
            # Boost if multiple hypotheses suggest this agent
            suggestion_count = sum(
                1 for h in hypotheses if agent_name in h.suggested_agents
            )
            threat_relevance = min(threat_relevance + (suggestion_count - 1) * 0.1, 1.0)
        else:
            # Check if agent's tactics are relevant
            threat_relevance = 0.3  # Base score for non-suggested agents

        # Asset criticality
        asset_criticality = 0.5  # Default
        if len(context.asset_context.critical_assets) > 0:
            asset_criticality = 0.8  # Higher priority when critical assets present
        if context.asset_context.privileged_sessions > 0:
            asset_criticality = min(asset_criticality + 0.2, 1.0)

        # Temporal urgency
        temporal_urgency = 0.5  # Default
        if not context.time_features.is_business_hours:
            temporal_urgency = 0.7  # Higher priority outside business hours
        if context.alert_history.total_alerts_24h > 100:
            temporal_urgency = 0.9  # High alert volume = high urgency

        # Agent confidence history
        agent_confidence = self._get_agent_confidence(agent_name)

        # Calculate weighted score
        score = (
            threat_relevance * self.weights["threat_relevance"] +
            asset_criticality * self.weights["asset_criticality"] +
            temporal_urgency * self.weights["temporal_urgency"] +
            agent_confidence * self.weights["agent_confidence_history"]
        )

        return score

    def _get_agent_confidence(self, agent_name: str) -> float:
        """Get historical confidence score for an agent."""
        if agent_name not in self.agent_history:
            return 0.5  # Neutral default for new agents

        history = self.agent_history[agent_name]
        return history.get("average_confidence", 0.5)

    def update_agent_history(
        self,
        agent_name: str,
        confidence: float,
        was_successful: bool
    ):
        """
        Update agent performance history.

        Args:
            agent_name: Name of the agent
            confidence: Confidence score from latest run
            was_successful: Whether detection was successful (true positive)
        """
        if agent_name not in self.agent_history:
            self.agent_history[agent_name] = {
                "average_confidence": 0.0,
                "run_count": 0,
                "success_count": 0
            }

        history = self.agent_history[agent_name]
        history["run_count"] += 1

        if was_successful:
            history["success_count"] += 1

        # Update moving average of confidence
        n = history["run_count"]
        history["average_confidence"] = (
            (history["average_confidence"] * (n - 1) + confidence) / n
        )

    def get_next_stage_agents(
        self,
        current_detections: List[str],
        available_agents: List[str]
    ) -> List[str]:
        """
        Get agents for next expected kill chain stages.

        Args:
            current_detections: MITRE tactic IDs of current detections
            available_agents: Available agent names

        Returns:
            List of agent names for next stages
        """
        next_agents = set()

        for tactic_id in current_detections:
            try:
                # Convert tactic ID to KillChainStage
                tactic = KillChainStage(tactic_id)

                # Get agents for next stages
                next_stage_agents = MITREAttack.get_next_stage_agents(tactic)
                next_agents.update(
                    agent for agent in next_stage_agents
                    if agent in available_agents
                )
            except ValueError:
                continue

        self.logger.info(f"Next stage agents: {list(next_agents)}")
        return list(next_agents)

    def adjust_weights(
        self,
        feedback: Dict[str, float]
    ):
        """
        Adjust priority scoring weights based on feedback.

        Args:
            feedback: Dictionary of weight adjustments
        """
        for weight_name, adjustment in feedback.items():
            if weight_name in self.weights:
                self.weights[weight_name] = max(0.0, min(1.0, self.weights[weight_name] + adjustment))

        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}

        self.logger.info(f"Updated weights: {self.weights}")
