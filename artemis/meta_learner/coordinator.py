"""
Meta-Learner Coordinator - The orchestration engine for Artemis.

Coordinates specialized hunting agents, manages context assessment,
agent selection, confidence aggregation, and adaptive learning.
"""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging
import concurrent.futures

from artemis.agents.base_agent import BaseAgent, AgentPriority
from artemis.agents import (
    ReconnaissanceHunter,
    InitialAccessHunter,
    ExecutionPersistenceHunter,
    CredentialAccessHunter,
    LateralMovementHunter,
    CollectionExfiltrationHunter,
    C2Hunter,
    DefenseEvasionHunter,
    ImpactHunter
)
from artemis.models.network_state import NetworkState, TimeFeatures
from artemis.models.agent_output import AgentOutput
from artemis.models.threat_hypothesis import ThreatHypothesis
from artemis.meta_learner.context_assessment import ContextAssessor
from artemis.meta_learner.agent_selector import AgentSelector
from artemis.meta_learner.confidence_aggregator import ConfidenceAggregator
from artemis.meta_learner.adaptive_learner import AdaptiveLearner, FeedbackType
from artemis.utils.logging_config import ArtemisLogger


class DeploymentMode:
    """Deployment modes for agent activation."""
    PARALLEL = "parallel"  # All agents simultaneously
    SEQUENTIAL = "sequential"  # Based on hypotheses
    ADAPTIVE = "adaptive"  # Intelligent selection (default)


class MetaLearnerCoordinator:
    """
    Meta-Learning Coordinator for hierarchical threat hunting.

    Orchestrates specialized hunting agents using context-aware decision making,
    adaptive learning, and intelligent resource allocation.
    """

    def __init__(
        self,
        deployment_mode: str = DeploymentMode.ADAPTIVE,
        enable_parallel_execution: bool = True,
        max_workers: int = 4
    ):
        """
        Initialize Meta-Learner Coordinator.

        Args:
            deployment_mode: Agent deployment strategy
            enable_parallel_execution: Whether to run agents in parallel
            max_workers: Maximum parallel agent executions
        """
        self.logger = ArtemisLogger.setup_logger("artemis.meta_learner.coordinator")

        # Configuration
        self.deployment_mode = deployment_mode
        self.enable_parallel_execution = enable_parallel_execution
        self.max_workers = max_workers

        # Initialize components
        self.context_assessor = ContextAssessor()
        self.agent_selector = AgentSelector()
        self.confidence_aggregator = ConfidenceAggregator()
        self.adaptive_learner = AdaptiveLearner()

        # Initialize all hunting agents
        self.agents: Dict[str, BaseAgent] = self._initialize_agents()

        # Baseline agents (always running)
        self.baseline_agents = ["c2_hunter", "reconnaissance_hunter", "defense_evasion_hunter"]

        # Statistics
        self.stats = {
            "total_hunts": 0,
            "total_detections": 0,
            "high_confidence_detections": 0,
            "agent_activations": {},
            "start_time": datetime.utcnow()
        }

        self.logger.info("Meta-Learner Coordinator initialized")

    def _initialize_agents(self) -> Dict[str, BaseAgent]:
        """Initialize all specialized hunting agents."""
        agents = {
            "reconnaissance_hunter": ReconnaissanceHunter(),
            "initial_access_hunter": InitialAccessHunter(),
            "execution_persistence_hunter": ExecutionPersistenceHunter(),
            "credential_access_hunter": CredentialAccessHunter(),
            "lateral_movement_hunter": LateralMovementHunter(),
            "collection_exfiltration_hunter": CollectionExfiltrationHunter(),
            "c2_hunter": C2Hunter(),
            "defense_evasion_hunter": DefenseEvasionHunter(),
            "impact_hunter": ImpactHunter()
        }

        self.logger.info(f"Initialized {len(agents)} hunting agents")
        return agents

    def hunt(
        self,
        data: Dict[str, Any],
        initial_signals: Optional[List[Dict[str, Any]]] = None,
        context_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute threat hunting across all data sources.

        This is the main entry point for the meta-learner system.

        Args:
            data: Input data for agents to analyze
            initial_signals: Optional initial alerts/anomalies
            context_data: Optional network state context data

        Returns:
            Aggregated threat assessment
        """
        self.logger.info("=" * 80)
        self.logger.info("Starting threat hunting operation")
        self.stats["total_hunts"] += 1

        # Stage 1: Environmental Context Gathering
        context = self._gather_context(context_data or {})

        # Stage 2: Threat Hypothesis Generation
        hypotheses = self._generate_hypotheses(initial_signals or [], context)

        # Stage 3: Agent Selection
        selected_agents = self._select_agents(hypotheses, context)

        # Stage 4: Resource Allocation & Agent Execution
        agent_outputs = self._execute_agents(selected_agents, data, context)

        # Stage 5: Confidence Aggregation & Decision Making
        assessment = self._aggregate_results(agent_outputs, context)

        # Stage 6: Update Statistics
        self._update_statistics(assessment, selected_agents)

        self.logger.info(
            f"Hunt complete: confidence={assessment['final_confidence']:.2f}, "
            f"severity={assessment['severity'].value if hasattr(assessment['severity'], 'value') else assessment['severity']}"
        )
        self.logger.info("=" * 80)

        return assessment

    def _gather_context(self, context_data: Dict[str, Any]) -> NetworkState:
        """Stage 1: Gather environmental context."""
        self.logger.info("Stage 1: Gathering environmental context")
        return self.context_assessor.assess_context(context_data)

    def _generate_hypotheses(
        self,
        initial_signals: List[Dict[str, Any]],
        context: NetworkState
    ) -> List[ThreatHypothesis]:
        """Stage 2: Generate threat hypotheses."""
        self.logger.info("Stage 2: Generating threat hypotheses")

        # Generate hypotheses from initial signals
        hypotheses = self.context_assessor.generate_hypotheses(initial_signals, context)

        # Check for anomalies
        anomalies = self.context_assessor.detect_anomalies(context)
        if anomalies:
            self.logger.warning(f"Detected {len(anomalies)} anomalies")
            # Convert anomalies to signals
            for anomaly in anomalies:
                initial_signals.append(anomaly)

        self.logger.info(f"Generated {len(hypotheses)} threat hypotheses")
        return hypotheses

    def _select_agents(
        self,
        hypotheses: List[ThreatHypothesis],
        context: NetworkState
    ) -> List[Tuple[str, float]]:
        """Stage 3: Select agents based on hypotheses and context."""
        self.logger.info("Stage 3: Selecting agents")

        available_agents = list(self.agents.keys())
        selected = self.agent_selector.select_agents(
            hypotheses,
            context,
            available_agents,
            mode=self.deployment_mode
        )

        self.logger.info(
            f"Selected {len(selected)} agents: " +
            ", ".join([f"{name}({priority:.2f})" for name, priority in selected[:5]])
        )

        return selected

    def _execute_agents(
        self,
        selected_agents: List[Tuple[str, float]],
        data: Dict[str, Any],
        context: NetworkState
    ) -> List[AgentOutput]:
        """Stage 4: Execute selected agents."""
        self.logger.info("Stage 4: Executing agents")

        outputs = []

        if self.enable_parallel_execution and len(selected_agents) > 1:
            # Parallel execution
            outputs = self._execute_agents_parallel(selected_agents, data, context)
        else:
            # Sequential execution
            outputs = self._execute_agents_sequential(selected_agents, data, context)

        # Filter out empty outputs
        outputs = [o for o in outputs if o.confidence > 0.0 or len(o.findings) > 0]

        self.logger.info(f"Agent execution complete: {len(outputs)} outputs with findings")
        return outputs

    def _execute_agents_parallel(
        self,
        selected_agents: List[Tuple[str, float]],
        data: Dict[str, Any],
        context: NetworkState
    ) -> List[AgentOutput]:
        """Execute agents in parallel using thread pool."""
        outputs = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all agent tasks
            future_to_agent = {
                executor.submit(self._run_agent, agent_name, priority, data, context): agent_name
                for agent_name, priority in selected_agents
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_agent):
                agent_name = future_to_agent[future]
                try:
                    output = future.result()
                    if output:
                        outputs.append(output)
                except Exception as e:
                    self.logger.error(f"Agent {agent_name} failed: {e}", exc_info=True)

        return outputs

    def _execute_agents_sequential(
        self,
        selected_agents: List[Tuple[str, float]],
        data: Dict[str, Any],
        context: NetworkState
    ) -> List[AgentOutput]:
        """Execute agents sequentially."""
        outputs = []

        for agent_name, priority in selected_agents:
            try:
                output = self._run_agent(agent_name, priority, data, context)
                if output:
                    outputs.append(output)

                    # Auto-activate next stage agents on high-confidence detection
                    if output.confidence >= 0.7:
                        next_agents = self._activate_next_stage_agents(
                            output,
                            selected_agents,
                            data,
                            context
                        )
                        outputs.extend(next_agents)
            except Exception as e:
                self.logger.error(f"Agent {agent_name} failed: {e}", exc_info=True)

        return outputs

    def _run_agent(
        self,
        agent_name: str,
        priority: float,
        data: Dict[str, Any],
        context: NetworkState
    ) -> Optional[AgentOutput]:
        """Execute a single agent."""
        agent = self.agents.get(agent_name)
        if not agent:
            return None

        # Set agent priority
        agent.set_priority(int(priority * 4))  # Scale to 0-4

        self.logger.debug(f"Running agent: {agent_name} (priority={priority:.2f})")

        # Execute agent
        output = agent.analyze(data, context)

        # Update statistics
        self.stats["agent_activations"][agent_name] = \
            self.stats["agent_activations"].get(agent_name, 0) + 1

        return output

    def _activate_next_stage_agents(
        self,
        detection: AgentOutput,
        already_selected: List[Tuple[str, float]],
        data: Dict[str, Any],
        context: NetworkState
    ) -> List[AgentOutput]:
        """Auto-activate next kill chain stage agents on high-confidence detection."""
        # Get next stage agents
        next_agents = self.agent_selector.get_next_stage_agents(
            detection.mitre_tactics,
            list(self.agents.keys())
        )

        # Filter out already selected agents
        already_selected_names = {name for name, _ in already_selected}
        next_agents = [
            agent for agent in next_agents
            if agent not in already_selected_names
        ]

        if not next_agents:
            return []

        self.logger.info(
            f"Auto-activating next stage agents: {next_agents} "
            f"(following {detection.agent_name} detection)"
        )

        outputs = []
        for agent_name in next_agents:
            output = self._run_agent(agent_name, 0.8, data, context)
            if output:
                outputs.append(output)

        return outputs

    def _aggregate_results(
        self,
        agent_outputs: List[AgentOutput],
        context: NetworkState
    ) -> Dict[str, Any]:
        """Stage 5: Aggregate results and make final decision."""
        self.logger.info("Stage 5: Aggregating results")

        assessment = self.confidence_aggregator.aggregate_outputs(agent_outputs, context)

        # Calculate correlation score
        if len(agent_outputs) >= 2:
            correlation = self.confidence_aggregator.calculate_correlation_score(agent_outputs)
            assessment["correlation_score"] = correlation
            self.logger.info(f"Agent correlation score: {correlation:.2f}")

        return assessment

    def _update_statistics(
        self,
        assessment: Dict[str, Any],
        selected_agents: List[Tuple[str, float]]
    ):
        """Update coordinator statistics."""
        if assessment["final_confidence"] > 0.5:
            self.stats["total_detections"] += 1

        if assessment["final_confidence"] >= 0.7:
            self.stats["high_confidence_detections"] += 1

    def provide_feedback(
        self,
        assessment: Dict[str, Any],
        feedback_type: str,
        analyst_notes: Optional[str] = None
    ):
        """
        Provide analyst feedback for adaptive learning.

        Args:
            assessment: The threat assessment being reviewed
            feedback_type: "true_positive", "false_positive", or "uncertain"
            analyst_notes: Optional analyst notes
        """
        self.logger.info(f"Received feedback: {feedback_type}")

        # Integrate feedback into adaptive learner
        self.adaptive_learner.integrate_feedback(assessment, feedback_type, analyst_notes)

        # Update individual agent feedback
        for output_dict in assessment.get("agent_outputs", []):
            agent_name = output_dict["agent_name"]
            if agent_name in self.agents:
                agent = self.agents[agent_name]
                is_tp = (feedback_type == FeedbackType.TRUE_POSITIVE)
                agent.update_feedback(is_tp)

                # Update agent selector history
                self.agent_selector.update_agent_history(
                    agent_name,
                    output_dict.get("confidence", 0.0),
                    is_tp
                )

    def get_statistics(self) -> Dict[str, Any]:
        """Get coordinator statistics."""
        runtime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()

        return {
            **self.stats,
            "runtime_seconds": runtime,
            "hunts_per_hour": (self.stats["total_hunts"] / (runtime / 3600)) if runtime > 0 else 0,
            "detection_rate": (
                self.stats["total_detections"] / self.stats["total_hunts"]
                if self.stats["total_hunts"] > 0 else 0
            ),
            "adaptive_learner_metrics": self.adaptive_learner.get_performance_metrics(),
            "most_active_agents": sorted(
                self.stats["agent_activations"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }

    def get_agent_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get performance metrics for all agents."""
        metrics = {}
        for name, agent in self.agents.items():
            metrics[name] = agent.get_metrics()
        return metrics

    def enable_agent(self, agent_name: str):
        """Enable a specific agent."""
        if agent_name in self.agents:
            self.agents[agent_name].enable()
            self.logger.info(f"Enabled agent: {agent_name}")

    def disable_agent(self, agent_name: str):
        """Disable a specific agent."""
        if agent_name in self.agents:
            self.agents[agent_name].disable()
            self.logger.info(f"Disabled agent: {agent_name}")

    def set_deployment_mode(self, mode: str):
        """Change deployment mode."""
        if mode in [DeploymentMode.PARALLEL, DeploymentMode.SEQUENTIAL, DeploymentMode.ADAPTIVE]:
            self.deployment_mode = mode
            self.logger.info(f"Deployment mode changed to: {mode}")
        else:
            self.logger.warning(f"Invalid deployment mode: {mode}")
