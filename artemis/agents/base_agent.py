"""
Base agent class for all specialized hunting agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
import logging

from artemis.models.agent_output import AgentOutput, Severity, Finding, Evidence
from artemis.models.network_state import NetworkState
from artemis.utils.mitre_attack import KillChainStage
from artemis.utils.logging_config import ArtemisLogger


class AgentPriority:
    """Agent priority levels for resource allocation."""
    CONTINUOUS = 0  # Always running (baseline monitoring)
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4  # Maximum priority


@dataclass
class AgentMetrics:
    """Performance metrics for an agent."""
    total_analyses: int = 0
    total_detections: int = 0
    true_positives: int = 0
    false_positives: int = 0
    average_processing_time: float = 0.0
    average_confidence: float = 0.0
    last_execution: Optional[datetime] = None

    @property
    def false_positive_rate(self) -> float:
        """Calculate false positive rate."""
        total = self.true_positives + self.false_positives
        if total == 0:
            return 0.0
        return self.false_positives / total

    @property
    def detection_rate(self) -> float:
        """Calculate detection rate."""
        if self.total_analyses == 0:
            return 0.0
        return self.total_detections / self.total_analyses


class BaseAgent(ABC):
    """
    Abstract base class for all specialized hunting agents.

    Each agent focuses on specific MITRE ATT&CK tactics and techniques,
    analyzing network/system data to detect suspicious activities.

    Attributes:
        name: Agent identifier
        tactics: MITRE ATT&CK tactics this agent covers
        techniques: Common techniques the agent looks for
        priority: Current priority level
        enabled: Whether agent is currently active
        metrics: Performance tracking metrics
    """

    def __init__(
        self,
        name: str,
        tactics: List[KillChainStage],
        description: str = ""
    ):
        """
        Initialize base agent.

        Args:
            name: Agent name
            tactics: MITRE ATT&CK tactics covered
            description: Agent description
        """
        self.name = name
        self.tactics = tactics
        self.description = description
        self.priority = AgentPriority.MEDIUM
        self.enabled = True
        self.metrics = AgentMetrics()
        self.logger = ArtemisLogger.setup_logger(f"artemis.agents.{name}")

        # Historical confidence scores for adaptive thresholding
        self.confidence_history: List[float] = []

        # Agent-specific configuration
        self.config: Dict[str, Any] = self._get_default_config()

    @abstractmethod
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get default configuration for this agent.

        Returns:
            Configuration dictionary
        """
        pass

    @abstractmethod
    def _analyze_data(self, data: Dict[str, Any], context: NetworkState) -> AgentOutput:
        """
        Core analysis logic - implemented by each specialized agent.

        Args:
            data: Input data to analyze (logs, network traffic, etc.)
            context: Current network state and context

        Returns:
            AgentOutput with findings and confidence scores
        """
        pass

    def analyze(
        self,
        data: Dict[str, Any],
        context: Optional[NetworkState] = None
    ) -> AgentOutput:
        """
        Public interface for agent analysis.

        Wraps the specialized analysis with timing, logging, and metrics.

        Args:
            data: Input data to analyze
            context: Optional network state context

        Returns:
            AgentOutput with findings
        """
        if not self.enabled:
            self.logger.debug(f"Agent {self.name} is disabled, skipping analysis")
            return self._create_empty_output()

        start_time = time.time()
        self.logger.info(f"Agent {self.name} starting analysis")

        try:
            # Use current context if none provided
            if context is None:
                context = self._get_default_context()

            # Perform analysis
            output = self._analyze_data(data, context)

            # Update metrics
            processing_time = time.time() - start_time
            self._update_metrics(output, processing_time)

            # Log results
            self._log_results(output)

            return output

        except Exception as e:
            self.logger.error(f"Agent {self.name} analysis failed: {e}", exc_info=True)
            return self._create_error_output(str(e))

    def _create_empty_output(self) -> AgentOutput:
        """Create an empty output when agent is disabled."""
        return AgentOutput(
            agent_name=self.name,
            confidence=0.0,
            findings=[],
            evidence=[],
            severity=Severity.LOW,
            mitre_tactics=[t.value for t in self.tactics]
        )

    def _create_error_output(self, error_msg: str) -> AgentOutput:
        """Create an error output."""
        return AgentOutput(
            agent_name=self.name,
            confidence=0.0,
            findings=[],
            evidence=[],
            severity=Severity.LOW,
            metadata={"error": error_msg},
            mitre_tactics=[t.value for t in self.tactics]
        )

    def _get_default_context(self) -> NetworkState:
        """Create a default network state context."""
        from artemis.models.network_state import TimeFeatures
        return NetworkState(
            time_features=TimeFeatures.from_timestamp(datetime.utcnow())
        )

    def _update_metrics(self, output: AgentOutput, processing_time: float):
        """Update agent performance metrics."""
        self.metrics.total_analyses += 1
        self.metrics.last_execution = datetime.utcnow()

        # Update processing time (moving average)
        n = self.metrics.total_analyses
        self.metrics.average_processing_time = (
            (self.metrics.average_processing_time * (n - 1) + processing_time) / n
        )

        # Track detections
        if output.confidence > 0.5 and len(output.findings) > 0:
            self.metrics.total_detections += 1

        # Track confidence history
        self.confidence_history.append(output.confidence)
        if len(self.confidence_history) > 1000:  # Keep last 1000
            self.confidence_history = self.confidence_history[-1000:]

        # Update average confidence
        self.metrics.average_confidence = (
            (self.metrics.average_confidence * (n - 1) + output.confidence) / n
        )

    def _log_results(self, output: AgentOutput):
        """Log analysis results."""
        if output.confidence > 0.7:
            self.logger.warning(
                f"High confidence detection: {output.confidence:.2f} | "
                f"Severity: {output.severity.value} | "
                f"Findings: {len(output.findings)}"
            )
        elif output.confidence > 0.4:
            self.logger.info(
                f"Medium confidence detection: {output.confidence:.2f} | "
                f"Findings: {len(output.findings)}"
            )
        else:
            self.logger.debug(f"Low confidence: {output.confidence:.2f}")

    def update_feedback(self, was_true_positive: bool):
        """
        Update agent based on analyst feedback.

        Args:
            was_true_positive: Whether the detection was a true positive
        """
        if was_true_positive:
            self.metrics.true_positives += 1
            self.logger.info(f"Agent {self.name}: True positive confirmed")
        else:
            self.metrics.false_positives += 1
            self.logger.info(f"Agent {self.name}: False positive recorded")

        # Adjust thresholds if FP rate is too high
        if self.metrics.false_positive_rate > 0.5:
            self.logger.warning(
                f"Agent {self.name} has high FP rate: {self.metrics.false_positive_rate:.2%}"
            )

    def set_priority(self, priority: int):
        """Set agent priority level."""
        self.priority = priority
        self.logger.info(f"Agent {self.name} priority set to {priority}")

    def enable(self):
        """Enable agent."""
        self.enabled = True
        self.logger.info(f"Agent {self.name} enabled")

    def disable(self):
        """Disable agent."""
        self.enabled = False
        self.logger.info(f"Agent {self.name} disabled")

    def get_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics."""
        return {
            "name": self.name,
            "total_analyses": self.metrics.total_analyses,
            "total_detections": self.metrics.total_detections,
            "true_positives": self.metrics.true_positives,
            "false_positives": self.metrics.false_positives,
            "false_positive_rate": self.metrics.false_positive_rate,
            "detection_rate": self.metrics.detection_rate,
            "average_processing_time": self.metrics.average_processing_time,
            "average_confidence": self.metrics.average_confidence,
            "last_execution": self.metrics.last_execution.isoformat() if self.metrics.last_execution else None
        }

    def reset_metrics(self):
        """Reset performance metrics."""
        self.metrics = AgentMetrics()
        self.confidence_history = []
        self.logger.info(f"Agent {self.name} metrics reset")

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<{self.__class__.__name__} name='{self.name}' "
            f"tactics={[t.name for t in self.tactics]} "
            f"enabled={self.enabled} priority={self.priority}>"
        )
