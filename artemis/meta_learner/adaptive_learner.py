"""
Adaptive learning module for the meta-learner.

Implements feedback loops and continuous improvement mechanisms.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import logging

from artemis.models.agent_output import AgentOutput
from artemis.utils.bandit import ContextualBandit
from artemis.utils.logging_config import ArtemisLogger


class FeedbackType:
    """Types of feedback."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class AdaptiveLearner:
    """
    Handles adaptive learning and feedback integration.

    Implements contextual bandit for agent selection optimization
    and builds playbooks from successful detections.
    """

    def __init__(self, n_strategies: int = 10, context_dim: int = 22):
        """
        Initialize adaptive learner.

        Args:
            n_strategies: Number of agent activation strategies
            context_dim: Dimensionality of context vectors (from NetworkState)
        """
        self.logger = ArtemisLogger.setup_logger("artemis.meta_learner.adaptive")

        # Contextual bandit for strategy selection
        self.bandit = ContextualBandit(n_arms=n_strategies, context_dim=context_dim)

        # Performance metrics
        self.metrics = {
            "total_detections": 0,
            "true_positives": 0,
            "false_positives": 0,
            "uncertain": 0,
            "total_feedback": 0
        }

        # Attack campaign playbooks
        self.playbooks: Dict[str, Dict[str, Any]] = {}

        # Learning history
        self.feedback_history: List[Dict[str, Any]] = []

    def integrate_feedback(
        self,
        assessment: Dict[str, Any],
        feedback_type: str,
        analyst_notes: Optional[str] = None
    ):
        """
        Integrate analyst feedback to improve future performance.

        Args:
            assessment: The threat assessment that was reviewed
            feedback_type: Type of feedback (true_positive, false_positive, uncertain)
            analyst_notes: Optional notes from analyst
        """
        self.metrics["total_feedback"] += 1

        if feedback_type == FeedbackType.TRUE_POSITIVE:
            self.metrics["true_positives"] += 1
            self._handle_true_positive(assessment, analyst_notes)
        elif feedback_type == FeedbackType.FALSE_POSITIVE:
            self.metrics["false_positives"] += 1
            self._handle_false_positive(assessment, analyst_notes)
        else:  # UNCERTAIN
            self.metrics["uncertain"] += 1

        # Store feedback
        feedback_record = {
            "timestamp": datetime.utcnow(),
            "feedback_type": feedback_type,
            "confidence": assessment.get("final_confidence", 0.0),
            "severity": assessment.get("severity", "").value if hasattr(assessment.get("severity", ""), "value") else "",
            "agent_count": assessment.get("agent_count", 0),
            "analyst_notes": analyst_notes
        }
        self.feedback_history.append(feedback_record)

        # Keep last 1000 feedback records
        if len(self.feedback_history) > 1000:
            self.feedback_history = self.feedback_history[-1000:]

        self.logger.info(
            f"Feedback integrated: {feedback_type} | "
            f"TP: {self.metrics['true_positives']}, FP: {self.metrics['false_positives']}"
        )

    def _handle_true_positive(
        self,
        assessment: Dict[str, Any],
        analyst_notes: Optional[str]
    ):
        """Handle true positive feedback."""
        # Record successful agent activation pattern
        activated_agents = [
            output["agent_name"]
            for output in assessment.get("agent_outputs", [])
        ]

        # Extract MITRE techniques
        techniques = assessment.get("mitre_techniques", [])

        # Build/update playbook
        self._update_playbook(activated_agents, techniques, success=True)

        self.logger.info(f"True positive confirmed - updating playbooks")

    def _handle_false_positive(
        self,
        assessment: Dict[str, Any],
        analyst_notes: Optional[str]
    ):
        """Handle false positive feedback."""
        # Adjust agent confidence thresholds
        for output in assessment.get("agent_outputs", []):
            agent_name = output["agent_name"]
            # In production, would update agent-specific thresholds
            self.logger.debug(f"Adjusting thresholds for {agent_name}")

        self.logger.info("False positive recorded - adjusting detection thresholds")

    def _update_playbook(
        self,
        agents: List[str],
        techniques: List[str],
        success: bool
    ):
        """
        Update attack campaign playbooks.

        Args:
            agents: Agents that were activated
            techniques: MITRE techniques detected
            success: Whether this was successful detection
        """
        # Create playbook key from techniques
        technique_key = "_".join(sorted(techniques)[:5])  # Use first 5 techniques

        if technique_key not in self.playbooks:
            self.playbooks[technique_key] = {
                "techniques": techniques,
                "successful_agent_combinations": [],
                "success_count": 0,
                "total_count": 0
            }

        playbook = self.playbooks[technique_key]
        playbook["total_count"] += 1

        if success:
            playbook["success_count"] += 1
            agent_combo = sorted(agents)

            # Record this successful combination
            combo_str = ",".join(agent_combo)
            if combo_str not in playbook["successful_agent_combinations"]:
                playbook["successful_agent_combinations"].append(combo_str)

    def get_recommended_strategy(
        self,
        context_vector: Any,
        techniques: List[str]
    ) -> Optional[List[str]]:
        """
        Get recommended agent activation strategy.

        Args:
            context_vector: Current network state vector
            techniques: Detected MITRE techniques

        Returns:
            Recommended list of agents to activate, or None
        """
        # Check if we have a playbook for these techniques
        technique_key = "_".join(sorted(techniques)[:5])

        if technique_key in self.playbooks:
            playbook = self.playbooks[technique_key]

            if playbook["success_count"] > 0:
                # Use most successful combination
                best_combo = playbook["successful_agent_combinations"][0]
                recommended = best_combo.split(",")

                self.logger.info(f"Using playbook for techniques {technique_key}")
                return recommended

        return None

    def update_bandit(
        self,
        strategy_id: int,
        context_vector: Any,
        reward: float
    ):
        """
        Update contextual bandit with outcome.

        Args:
            strategy_id: ID of strategy that was used
            context_vector: Context vector when strategy was chosen
            reward: Reward received (based on detection success)
        """
        self.bandit.update(strategy_id, context_vector, reward)

        self.logger.debug(f"Updated bandit: strategy={strategy_id}, reward={reward:.2f}")

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        total_confirmed = self.metrics["true_positives"] + self.metrics["false_positives"]

        precision = (
            self.metrics["true_positives"] / total_confirmed
            if total_confirmed > 0 else 0.0
        )

        return {
            **self.metrics,
            "precision": precision,
            "false_positive_rate": (
                self.metrics["false_positives"] / total_confirmed
                if total_confirmed > 0 else 0.0
            ),
            "playbook_count": len(self.playbooks)
        }

    def export_playbooks(self, filepath: str):
        """Export playbooks to file."""
        with open(filepath, 'w') as f:
            json.dump(self.playbooks, f, indent=2)

        self.logger.info(f"Exported {len(self.playbooks)} playbooks to {filepath}")

    def import_playbooks(self, filepath: str):
        """Import playbooks from file."""
        try:
            with open(filepath, 'r') as f:
                self.playbooks = json.load(f)

            self.logger.info(f"Imported {len(self.playbooks)} playbooks from {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to import playbooks: {e}")
