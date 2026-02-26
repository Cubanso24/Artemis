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

    # ------------------------------------------------------------------
    # Autonomous case-based learning
    # ------------------------------------------------------------------

    def learn_from_case(
        self,
        case_dict: Dict[str, Any],
        verdict: str,
        db_manager=None,
        rag_store=None,
    ):
        """Closed-loop learning from a resolved case.

        This is the core of the self-learning feedback loop.  When an
        analyst (or IRIS sync) resolves a case as TP/FP/uncertain, this
        method updates all learning systems:

        1. Agent performance via existing ``integrate_feedback()``
        2. Per-technique precision in the database
        3. Episodic memory in ChromaDB (case outcome for future RAG)
        4. Confidence calibration curve

        Args:
            case_dict: The full case dictionary (from ``Case.to_dict()``
                or ``db_manager.get_case()``).
            verdict: ``"tp"``, ``"fp"``, or ``"uncertain"``.
            db_manager: Database manager for technique precision updates.
            rag_store: RAG store for episodic memory indexing.
        """
        feedback_type = {
            "tp": FeedbackType.TRUE_POSITIVE,
            "fp": FeedbackType.FALSE_POSITIVE,
            "uncertain": FeedbackType.UNCERTAIN,
        }.get(verdict, FeedbackType.UNCERTAIN)

        # 1. Update agent performance metrics
        pseudo_assessment = {
            "final_confidence": case_dict.get("confidence", 0.0),
            "severity": case_dict.get("severity", "medium"),
            "mitre_techniques": case_dict.get("mitre_techniques", []),
            "agent_outputs": [],  # No per-agent data from case resolution
        }
        self.integrate_feedback(
            pseudo_assessment, feedback_type,
            analyst_notes=case_dict.get("analyst_notes", ""),
        )

        # 2. Update per-technique precision in the DB
        if db_manager:
            for technique in case_dict.get("mitre_techniques", []):
                db_manager.update_technique_precision(technique, verdict)

        # 3. Index case outcome to RAG episodic memory
        if rag_store and rag_store.available:
            outcome_text = {
                "tp": "confirmed malicious / true positive",
                "fp": "confirmed benign / false positive",
                "uncertain": "uncertain / requires further investigation",
            }.get(verdict, "unknown")

            rag_store.index_finding({
                "activity_type": "case_outcome",
                "description": (
                    f"Case {case_dict.get('case_id', '?')}: "
                    f"{case_dict.get('title', '')} — "
                    f"RESOLVED as {outcome_text}. "
                    f"{case_dict.get('description', '')}"
                ),
                "indicators": case_dict.get("affected_assets", []),
                "severity": case_dict.get("severity", "medium"),
                "mitre_techniques": case_dict.get("mitre_techniques", []),
                "agent_name": "feedback_loop",
                "confidence": case_dict.get("confidence", 0.0),
                "analyst_feedback": verdict,
            })

        # 4. Update confidence calibration history
        self._update_calibration(
            predicted=case_dict.get("confidence", 0.0),
            actual=1.0 if verdict == "tp" else (0.0 if verdict == "fp" else 0.5),
        )

        self.logger.info(
            f"Learned from case {case_dict.get('case_id', '?')}: "
            f"verdict={verdict}, techniques={case_dict.get('mitre_techniques', [])}"
        )

    def _update_calibration(self, predicted: float, actual: float):
        """Track predicted vs actual outcomes for confidence calibration.

        Over time this builds a calibration curve: if Artemis predicts
        confidence=0.85, how often is the case really a TP?

        The calibration data is stored in-memory (feedback_history) and
        can be used to apply a correction factor to future confidence
        scores.
        """
        if not hasattr(self, '_calibration_data'):
            self._calibration_data = []

        self._calibration_data.append({
            "predicted": predicted,
            "actual": actual,
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Keep last 500 data points
        if len(self._calibration_data) > 500:
            self._calibration_data = self._calibration_data[-500:]

    def get_calibration_factor(self, confidence: float) -> float:
        """Get a calibration adjustment for a given confidence score.

        Returns a multiplier (0.5 to 1.5) based on historical accuracy
        at similar confidence levels.  If insufficient data, returns 1.0
        (no adjustment).
        """
        if not hasattr(self, '_calibration_data') or len(self._calibration_data) < 10:
            return 1.0

        # Find historical outcomes near this confidence level (±0.1)
        nearby = [
            d for d in self._calibration_data
            if abs(d["predicted"] - confidence) <= 0.1
        ]
        if len(nearby) < 3:
            return 1.0

        # Average actual outcome at this confidence band
        avg_actual = sum(d["actual"] for d in nearby) / len(nearby)

        # If predicted 0.80 but average actual is 0.60 → factor = 0.75
        if confidence > 0:
            factor = avg_actual / confidence
            return max(0.5, min(1.5, factor))
        return 1.0

    def get_technique_precision_summary(self, db_manager) -> Dict[str, Any]:
        """Get a summary of technique precision data for hypothesis weighting.

        Returns techniques grouped by reliability tier:
            high_precision:   precision >= 0.7 (weight hypotheses higher)
            medium_precision: 0.3 <= precision < 0.7 (standard weight)
            low_precision:    precision < 0.3 (likely false positive source)
        """
        precision_data = db_manager.get_technique_precision()
        result = {"high_precision": [], "medium_precision": [],
                  "low_precision": []}

        for tech_id, data in precision_data.items():
            p = data["precision"]
            entry = {"technique_id": tech_id, "precision": p,
                     "tp": data["true_positives"], "fp": data["false_positives"]}
            if p >= 0.7:
                result["high_precision"].append(entry)
            elif p >= 0.3:
                result["medium_precision"].append(entry)
            else:
                result["low_precision"].append(entry)

        return result

    # ------------------------------------------------------------------
    # Playbook export/import
    # ------------------------------------------------------------------

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
