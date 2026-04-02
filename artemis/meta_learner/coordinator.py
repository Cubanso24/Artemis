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
from artemis.models.threat_hypothesis import ThreatHypothesis, HypothesisType
from artemis.meta_learner.context_assessment import ContextAssessor
from artemis.meta_learner.agent_selector import AgentSelector
from artemis.meta_learner.confidence_aggregator import ConfidenceAggregator
from artemis.meta_learner.adaptive_learner import AdaptiveLearner, FeedbackType
from artemis.llm.client import LLMClient
from artemis.llm.coordinator_llm import CoordinatorLLM
from artemis.llm.agent_llm import AgentLLM
from artemis.managers.case_generator import CaseGenerator
from artemis.utils.logging_config import ArtemisLogger
from artemis.ws import fire_agent_activity


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
        max_workers: int = 4,
        llm_api_key: Optional[str] = None,
        llm_coordinator_model: Optional[str] = None,
        llm_agent_model: Optional[str] = None,
        llm_enabled: bool = True,
        llm_backend: str = "auto",
        max_hunt_iterations: int = 3,
        followup_confidence_threshold: float = 0.5,
    ):
        """
        Initialize Meta-Learner Coordinator.

        Args:
            deployment_mode: Agent deployment strategy
            enable_parallel_execution: Whether to run agents in parallel
            max_workers: Maximum parallel agent executions
            llm_api_key: Anthropic API key (only for anthropic backend)
            llm_coordinator_model: Model for coordinator tier
            llm_agent_model: Model for agent tier
            llm_enabled: Set False to disable all LLM features
            llm_backend: "anthropic", "ollama", or "auto"
            max_hunt_iterations: Max follow-up rounds per hunt cycle
            followup_confidence_threshold: Min confidence to trigger follow-up
        """
        self.logger = ArtemisLogger.setup_logger("artemis.meta_learner.coordinator")

        # Configuration
        self.deployment_mode = deployment_mode
        self.enable_parallel_execution = enable_parallel_execution
        self.max_workers = max_workers
        self.max_hunt_iterations = max_hunt_iterations
        self.followup_confidence_threshold = followup_confidence_threshold

        # Baseline agents (always running in adaptive mode)
        self.baseline_agents = ["c2_hunter", "reconnaissance_hunter", "defense_evasion_hunter"]

        # Initialize components
        self.context_assessor = ContextAssessor()
        self.agent_selector = AgentSelector(baseline_agents=self.baseline_agents)
        self.confidence_aggregator = ConfidenceAggregator()
        self.adaptive_learner = AdaptiveLearner()

        # Initialize LLM layer (gracefully degrades if unavailable)
        self.llm_client: Optional[LLMClient] = None
        self.coordinator_llm: Optional[CoordinatorLLM] = None
        self.agent_llms: Dict[str, AgentLLM] = {}
        if llm_enabled:
            self._initialize_llm(
                llm_api_key, llm_coordinator_model, llm_agent_model,
                llm_backend,
            )

        # Initialize all hunting agents
        self.agents: Dict[str, BaseAgent] = self._initialize_agents()

        # Case generator (initialized lazily when db_manager is available)
        self.case_generator: Optional[CaseGenerator] = None
        self._db_manager = None

        # Per-hunt state (set during hunt())
        self._current_directives: Dict[str, Dict] = {}

        # Statistics
        self.stats = {
            "total_hunts": 0,
            "total_detections": 0,
            "high_confidence_detections": 0,
            "agent_activations": {},
            "start_time": datetime.utcnow()
        }

        llm_status = (
            "enabled" if self.coordinator_llm and self.coordinator_llm.available
            else "disabled"
        )
        self.logger.info(
            f"Meta-Learner Coordinator initialized (LLM: {llm_status})"
        )

    def _initialize_llm(
        self,
        api_key: Optional[str],
        coordinator_model: Optional[str],
        agent_model: Optional[str],
        backend: str = "auto",
    ):
        """Initialize the two-tier LLM layer with optional RAG."""
        self.llm_client = LLMClient(
            backend=backend,
            api_key=api_key,
            coordinator_model=coordinator_model,
            agent_model=agent_model,
        )

        # Initialize RAG store (gracefully degrades if chromadb missing).
        # RAGStore.__init__ is lazy (_client = None), so creation is
        # instant.  We do NOT call rag_store.available here because that
        # triggers chromadb.Client() which can hang for minutes loading a
        # large persisted DuckDB store — especially under I/O contention
        # during event replay.  Instead, RAG initialises on first actual
        # use; if chromadb is missing or broken it degrades gracefully.
        rag_store = None
        try:
            from artemis.llm.rag import RAGStore
            rag_store = RAGStore()
            self.logger.info(
                "RAG store created (lazy init — chromadb will load on "
                "first use)"
            )
        except ImportError:
            self.logger.info("RAG store disabled: chromadb not installed")
        except Exception as e:
            self.logger.info(f"RAG store disabled: {e}")
        self.rag_store = rag_store

        self.coordinator_llm = CoordinatorLLM(self.llm_client, rag_store=rag_store)

        # Create one specialist AgentLLM per hunting agent
        agent_names = [
            "reconnaissance_hunter",
            "initial_access_hunter",
            "execution_persistence_hunter",
            "credential_access_hunter",
            "lateral_movement_hunter",
            "collection_exfiltration_hunter",
            "c2_hunter",
            "defense_evasion_hunter",
            "impact_hunter",
        ]
        for name in agent_names:
            self.agent_llms[name] = AgentLLM(self.llm_client, name, rag_store=rag_store)

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
        context_data: Optional[Dict[str, Any]] = None,
        network_state: Optional['NetworkState'] = None,
    ) -> Dict[str, Any]:
        """
        Execute threat hunting across all data sources.

        This is the main entry point for the meta-learner system.

        Args:
            data: Input data for agents to analyze
            initial_signals: Optional initial alerts/anomalies
            context_data: Optional network state context data
            network_state: Optional pre-built NetworkState (overrides
                context_data when provided).  Use this to pass a state
                that already contains NetworkMapContext from the profiled
                network map.

        Returns:
            Aggregated threat assessment
        """
        self.logger.info("=" * 80)
        self.logger.info("Starting threat hunting operation")
        self.stats["total_hunts"] += 1
        fire_agent_activity("coordinator", "stage", {
            "message": "Starting threat hunting operation",
            "stage": 0,
        })

        # Stage 1: Environmental Context Gathering
        if network_state is not None:
            context = network_state
        else:
            context = self._gather_context(context_data or {})

        # Iterative hunting loop — the LLM can request follow-up rounds
        all_agent_outputs: List[AgentOutput] = []
        agents_run_so_far: List[str] = []

        for iteration in range(1, self.max_hunt_iterations + 1):
            iter_label = f"[iter {iteration}/{self.max_hunt_iterations}]"

            # Stage 2: Threat Hypothesis Generation (LLM-enhanced)
            if iteration == 1:
                fire_agent_activity("coordinator", "stage", {
                    "message": f"{iter_label} Generating threat hypotheses",
                    "stage": 2,
                })
                hypotheses = self._generate_hypotheses(
                    initial_signals or [], context, data
                )
            # Follow-up iterations use hypotheses from the LLM follow-up evaluation
            # (set at the end of the previous iteration)

            # Stage 3: Agent Selection
            fire_agent_activity("coordinator", "stage", {
                "message": f"{iter_label} Selecting agents from {len(hypotheses)} hypotheses",
                "stage": 3,
            })
            selected_agents = self._select_agents(hypotheses, context)

            # On follow-up rounds, prefer agents that haven't run yet
            if iteration > 1:
                new_agents = [
                    (name, score) for name, score in selected_agents
                    if name not in agents_run_so_far
                ]
                if new_agents:
                    selected_agents = new_agents
                # If all agents already ran, the selection stands as-is
                # (re-running with new directives can still find new things)

            # Stage 3.5: Generate agent directives (LLM)
            self._current_directives = self._generate_directives(
                hypotheses, selected_agents, context
            )

            # Stage 4: Resource Allocation & Agent Execution
            fire_agent_activity("coordinator", "stage", {
                "message": f"{iter_label} Executing {len(selected_agents)} agents",
                "stage": 4,
                "agents": [name for name, _ in selected_agents],
            })
            agent_outputs = self._execute_agents(selected_agents, data, context)

            # Stage 4.5: LLM enrichment of agent outputs
            fire_agent_activity("coordinator", "stage", {
                "message": f"{iter_label} LLM enrichment of agent outputs",
                "stage": 4.5,
            })
            agent_outputs = self._enrich_with_llm(
                agent_outputs, data, context
            )

            # Track cumulative outputs
            agents_run_so_far.extend(o.agent_name for o in agent_outputs)
            all_agent_outputs.extend(agent_outputs)

            # Evaluate whether to continue hunting (skip on last allowed iteration)
            if iteration < self.max_hunt_iterations and self.coordinator_llm:
                fire_agent_activity("coordinator", "stage", {
                    "message": f"{iter_label} Evaluating follow-up hunting",
                    "stage": 4.7,
                })
                followup = self.coordinator_llm.evaluate_followup(
                    all_agent_outputs, context, iteration,
                    list(self.agents.keys()),
                )
                if followup and followup.get("continue_hunting"):
                    # Build hypotheses from the LLM's follow-up suggestions
                    followup_hyps = followup.get("followup_hypotheses", [])
                    if followup_hyps:
                        hypotheses = self._build_followup_hypotheses(followup_hyps)
                        self.logger.info(
                            f"{iter_label} LLM requested follow-up: "
                            f"{followup.get('reasoning', '')[:120]}"
                        )
                        fire_agent_activity("coordinator", "stage", {
                            "message": (
                                f"{iter_label} Follow-up requested: "
                                f"{len(hypotheses)} new hypotheses"
                            ),
                            "stage": 4.8,
                            "followup_reasoning": followup.get("reasoning", ""),
                        })
                        continue  # Next iteration
                # LLM says stop, or no follow-up hypotheses — break out
                if followup:
                    self.logger.info(
                        f"{iter_label} LLM stopping: {followup.get('reasoning', '')[:120]}"
                    )
                break

        agent_outputs = all_agent_outputs

        # Stage 4.6: Deduplicate findings across all iterations
        agent_outputs = self._deduplicate_findings(agent_outputs)

        # Stage 5: Confidence Aggregation & Decision Making
        assessment = self._aggregate_results(agent_outputs, context)

        # Apply calibration factor from historical TP/FP outcomes.
        # If Artemis has historically been overconfident at this level,
        # the factor pulls the score down (and vice versa).
        cal = self.adaptive_learner.get_calibration_factor(
            assessment["final_confidence"]
        )
        if cal != 1.0:
            old = assessment["final_confidence"]
            assessment["final_confidence"] = max(
                0.0, min(1.0, old * cal)
            )
            self.logger.info(
                f"Calibration adjustment: {old:.2f} × {cal:.2f} "
                f"→ {assessment['final_confidence']:.2f}"
            )

        # Stage 5.5: LLM synthesis — unified threat narrative
        fire_agent_activity("coordinator", "stage", {
            "message": f"LLM synthesis — confidence={assessment['final_confidence']:.2f}",
            "stage": 5.5,
        })
        assessment = self._synthesize_with_llm(
            assessment, agent_outputs, context
        )

        # Stage 6: Update Statistics
        self._update_statistics(assessment, selected_agents)

        # Stage 6.5: Feed hunt outcome to the contextual bandit so it
        # learns which deployment mode works best for each network state.
        self._update_bandit_reward(assessment)

        # Stage 7: Index findings into RAG for future hunts
        self._index_to_rag(agent_outputs, data)

        # Stage 8: Autonomous case generation
        assessment = self._generate_cases(assessment, data)

        # Record how many iterations this hunt used
        assessment["hunt_iterations"] = iteration
        assessment["agents_activated"] = list(set(agents_run_so_far))

        # Persist learning state so it survives restarts
        if self._db_manager:
            self.adaptive_learner.save_state(self._db_manager)

        self.logger.info(
            f"Hunt complete: confidence={assessment['final_confidence']:.2f}, "
            f"severity={assessment['severity'].value if hasattr(assessment['severity'], 'value') else assessment['severity']}, "
            f"iterations={iteration}, agents={len(set(agents_run_so_far))}"
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
        context: NetworkState,
        hunting_data: Optional[Dict[str, Any]] = None,
    ) -> List[ThreatHypothesis]:
        """Stage 2: Generate threat hypotheses (LLM-enhanced with fallback)."""
        self.logger.info("Stage 2: Generating threat hypotheses")

        # Check for anomalies first (feeds into both paths)
        anomalies = self.context_assessor.detect_anomalies(context)
        if anomalies:
            self.logger.warning(f"Detected {len(anomalies)} anomalies")
            for anomaly in anomalies:
                initial_signals.append(anomaly)

        # Try LLM-based hypothesis generation
        hypotheses = None
        if self.coordinator_llm and self.coordinator_llm.available and hunting_data:
            self.logger.info("Using LLM for hypothesis generation")
            hypotheses = self.coordinator_llm.generate_hypotheses(
                context, initial_signals, hunting_data
            )

        # Fallback to rule-based generation
        if hypotheses is None:
            self.logger.info("Using rule-based hypothesis generation")
            hypotheses = self.context_assessor.generate_hypotheses(
                initial_signals, context
            )

        self.logger.info(f"Generated {len(hypotheses)} threat hypotheses")
        return hypotheses

    def _build_followup_hypotheses(
        self,
        followup_hyps: List[Dict[str, Any]],
    ) -> List[ThreatHypothesis]:
        """Convert LLM follow-up suggestions into ThreatHypothesis objects."""
        hypotheses = []
        for idx, fh in enumerate(followup_hyps):
            priority = float(fh.get("priority", 0.6))
            if priority < self.followup_confidence_threshold:
                continue
            hyp = ThreatHypothesis(
                hypothesis_id=f"followup_{idx}_{datetime.utcnow().strftime('%H%M%S')}",
                hypothesis_type=HypothesisType.ANOMALY_INVESTIGATION,
                description=fh.get("hypothesis", "Follow-up investigation"),
                initial_indicators=fh.get("relevant_findings", []),
                suggested_agents=fh.get("target_agents", []),
                priority=priority,
                confidence=priority,
            )
            hypotheses.append(hyp)
        self.logger.info(
            f"Built {len(hypotheses)} follow-up hypotheses from LLM evaluation"
        )
        return hypotheses

    # Map bandit arms 0-2 to deployment modes for learned strategy selection
    _BANDIT_ARM_TO_MODE = {
        0: DeploymentMode.ADAPTIVE,
        1: DeploymentMode.PARALLEL,
        2: DeploymentMode.SEQUENTIAL,
    }

    def _select_agents(
        self,
        hypotheses: List[ThreatHypothesis],
        context: NetworkState
    ) -> List[Tuple[str, float]]:
        """Stage 3: Select agents based on hypotheses and context.

        When the contextual bandit has enough data, it overrides the default
        deployment mode with the mode it has learned works best for the
        current network state.
        """
        self.logger.info("Stage 3: Selecting agents")

        # Let the bandit choose the deployment mode if it has learned enough
        mode = self.deployment_mode
        try:
            ctx_vec = context.to_state_vector()
            arm = self.adaptive_learner.bandit.select_arm(ctx_vec)
            # Only use bandit-selected mode for arms 0-2 (mapped modes);
            # higher arms fall through to the configured default.
            if arm in self._BANDIT_ARM_TO_MODE:
                learned_mode = self._BANDIT_ARM_TO_MODE[arm]
                if learned_mode != mode:
                    self.logger.info(
                        f"Bandit selected deployment mode "
                        f"'{learned_mode}' (arm {arm}) over default '{mode}'"
                    )
                    mode = learned_mode
            self._last_bandit_arm = arm
            self._last_context_vector = ctx_vec
        except Exception as e:
            self.logger.debug(f"Bandit selection skipped: {e}")
            self._last_bandit_arm = None
            self._last_context_vector = None

        available_agents = list(self.agents.keys())
        selected = self.agent_selector.select_agents(
            hypotheses,
            context,
            available_agents,
            mode=mode
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
        # Log data volume for diagnostics
        conn_count = len(data.get('network_connections', []))
        dns_count = len(data.get('dns_queries', []))
        ntlm_count = len(data.get('ntlm_logs', []))
        self.logger.info(
            f"Stage 4: Executing {len(selected_agents)} agents on "
            f"{conn_count} connections, {dns_count} DNS, {ntlm_count} NTLM"
        )

        outputs = []

        if self.enable_parallel_execution and len(selected_agents) > 1:
            # Parallel execution
            outputs = self._execute_agents_parallel(selected_agents, data, context)
        else:
            # Sequential execution
            outputs = self._execute_agents_sequential(selected_agents, data, context)

        # Log per-agent results before filtering (INFO level for visibility)
        total_before = len(outputs)
        for o in outputs:
            error = (o.metadata or {}).get("error") if hasattr(o, 'metadata') and o.metadata else None
            if error:
                self.logger.warning(
                    f"Agent {o.agent_name} CRASHED: {error}"
                )
            elif o.confidence == 0.0 and len(o.findings) == 0:
                # Near-miss info from metadata
                near_miss = (o.metadata or {}).get("near_misses", [])
                if near_miss:
                    self.logger.info(
                        f"Agent {o.agent_name}: no findings "
                        f"(near misses: {'; '.join(near_miss[:3])})"
                    )
                else:
                    self.logger.info(f"Agent {o.agent_name}: no findings")
            else:
                self.logger.info(
                    f"Agent {o.agent_name}: {len(o.findings)} findings, "
                    f"confidence={o.confidence:.2f}"
                )

        # Filter out empty outputs
        outputs = [o for o in outputs if o.confidence > 0.0 or len(o.findings) > 0]

        self.logger.info(
            f"Agent execution complete: {len(outputs)}/{total_before} "
            f"agents produced findings"
        )
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

    # Directive threshold_adjustments → numeric multiplier for detection
    # thresholds.  "lower" makes agents more sensitive (catches more but
    # noisier); "higher" makes them stricter (fewer findings, less noise).
    _DIRECTIVE_THRESHOLD_MULTIPLIERS = {
        "lower": 0.8,
        "normal": 1.0,
        "higher": 1.2,
    }

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

        fire_agent_activity(agent_name, "stage", {
            "message": f"Agent started (priority={priority:.2f})",
        })

        # Set agent priority
        agent.set_priority(int(priority * 4))  # Scale to 0-4

        # Apply directive threshold adjustments so the LLM coordinator
        # can actually steer detector sensitivity.
        directive = self._current_directives.get(agent_name, {})
        adj_str = directive.get("threshold_adjustments", "normal")
        directive_mult = self._DIRECTIVE_THRESHOLD_MULTIPLIERS.get(adj_str, 1.0)

        # Also apply the adaptive learner's per-agent FP multiplier
        fp_mult = self.adaptive_learner.get_threshold_multiplier(agent_name)

        combined_mult = directive_mult * fp_mult
        original_config = None
        if combined_mult != 1.0:
            # Temporarily scale all numeric thresholds in the agent's config
            original_config = dict(agent.config)
            for key, val in agent.config.items():
                if isinstance(val, (int, float)) and "threshold" in key:
                    agent.config[key] = type(val)(val * combined_mult)
            self.logger.debug(
                f"Agent {agent_name}: threshold multiplier={combined_mult:.2f} "
                f"(directive={directive_mult}, fp_adj={fp_mult:.2f})"
            )

        self.logger.debug(f"Running agent: {agent_name} (priority={priority:.2f})")

        # Execute agent
        output = agent.analyze(data, context)

        # Restore original config
        if original_config is not None:
            agent.config = original_config

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

    def _deduplicate_findings(
        self,
        agent_outputs: List[AgentOutput]
    ) -> List[AgentOutput]:
        """
        Deduplicate findings across agents.

        When multiple agents produce findings with the same fingerprint
        (same activity_type, indicators, affected_assets, MITRE techniques),
        keep only the one from the agent with the highest confidence.
        """
        seen_fingerprints: Dict[str, Tuple[str, float]] = {}  # fingerprint -> (agent_name, confidence)
        total_before = sum(len(o.findings) for o in agent_outputs)

        for output in agent_outputs:
            keep = []
            for finding in output.findings:
                fp = finding.fingerprint
                existing = seen_fingerprints.get(fp)
                if existing is None:
                    # First time seeing this finding
                    seen_fingerprints[fp] = (output.agent_name, output.confidence)
                    keep.append(finding)
                elif output.confidence > existing[1]:
                    # This agent has higher confidence — take ours, mark old for removal
                    seen_fingerprints[fp] = (output.agent_name, output.confidence)
                    keep.append(finding)
                    # Remove from previous agent (handled below in second pass)
                # else: duplicate with lower confidence, skip

            output.findings = keep

        # Second pass: remove findings that were superseded by higher-confidence agents
        for output in agent_outputs:
            output.findings = [
                f for f in output.findings
                if seen_fingerprints[f.fingerprint][0] == output.agent_name
            ]

        total_after = sum(len(o.findings) for o in agent_outputs)
        if total_before != total_after:
            self.logger.info(
                f"Deduplicated findings: {total_before} -> {total_after} "
                f"({total_before - total_after} duplicates removed)"
            )

        return agent_outputs

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

    # ------------------------------------------------------------------
    # LLM integration stages
    # ------------------------------------------------------------------

    def _generate_directives(
        self,
        hypotheses: List[ThreatHypothesis],
        selected_agents: List[Tuple[str, float]],
        context: NetworkState,
    ) -> Dict[str, Dict]:
        """Stage 3.5: Generate LLM directives for each selected agent."""
        if not (self.coordinator_llm and self.coordinator_llm.available):
            return {}

        self.logger.info("Stage 3.5: Generating agent directives (LLM)")
        agent_names = [name for name, _ in selected_agents]
        directives = self.coordinator_llm.generate_directives(
            hypotheses, agent_names, context
        )
        return directives or {}

    def _enrich_with_llm(
        self,
        agent_outputs: List[AgentOutput],
        hunting_data: Dict[str, Any],
        context: NetworkState,
    ) -> List[AgentOutput]:
        """Stage 4.5: Enrich agent outputs using specialist LLMs."""
        if not self.agent_llms:
            return agent_outputs

        self.logger.info("Stage 4.5: LLM enrichment of agent outputs")

        enriched = []
        for output in agent_outputs:
            agent_llm = self.agent_llms.get(output.agent_name)
            if agent_llm and agent_llm.available and output.findings:
                directive = self._current_directives.get(output.agent_name)
                output = agent_llm.enrich_output(
                    output, directive, hunting_data, context
                )
            enriched.append(output)

        return enriched

    def _synthesize_with_llm(
        self,
        assessment: Dict[str, Any],
        agent_outputs: List[AgentOutput],
        context: NetworkState,
    ) -> Dict[str, Any]:
        """Stage 5.5: LLM synthesis — unified threat narrative."""
        if not (self.coordinator_llm and self.coordinator_llm.available):
            return assessment

        self.logger.info("Stage 5.5: LLM synthesis")
        synthesis = self.coordinator_llm.synthesize_results(
            agent_outputs, context
        )

        if synthesis:
            assessment["llm_synthesis"] = synthesis
            # Merge LLM recommendations into the assessment
            llm_recs = [
                r.get("action", "")
                for r in synthesis.get("recommended_actions", [])
                if r.get("action")
            ]
            if llm_recs:
                existing = assessment.get("recommendations", [])
                assessment["recommendations"] = existing + llm_recs

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

    def _update_bandit_reward(self, assessment: Dict[str, Any]):
        """Stage 6.5: Feed hunt outcome back to the contextual bandit.

        Reward signal:
        - If findings exist, reward = final_confidence (0-1).
          Higher-confidence hunts reinforce the chosen mode.
        - If no findings, reward = 0.5 (neutral).
          A clean sweep is not a failure — don't penalise the mode.
        """
        arm = getattr(self, '_last_bandit_arm', None)
        ctx = getattr(self, '_last_context_vector', None)
        if arm is None or ctx is None:
            return

        has_findings = assessment.get("total_findings", 0) > 0
        reward = assessment["final_confidence"] if has_findings else 0.5

        try:
            self.adaptive_learner.update_bandit(arm, ctx, reward)
            self.logger.debug(
                f"Bandit updated: arm={arm}, reward={reward:.2f}"
            )
        except Exception as e:
            self.logger.debug(f"Bandit update failed: {e}")

    def init_case_generator(
        self,
        db_manager,
        auto_respond_threshold: float = 0.95,
        auto_investigate_threshold: float = 0.80,
        auto_case_threshold: float = 0.60,
        dedup_window_hours: int = 1,
    ):
        """Initialize the case generator with a database manager.

        Called by the server after both the coordinator and db_manager
        are created, since the coordinator may be initialised before
        the database layer.
        """
        self._db_manager = db_manager
        rag = getattr(self, 'rag_store', None)
        self.case_generator = CaseGenerator(
            db_manager=db_manager,
            rag_store=rag,
            auto_respond_threshold=auto_respond_threshold,
            auto_investigate_threshold=auto_investigate_threshold,
            auto_case_threshold=auto_case_threshold,
            dedup_window_hours=dedup_window_hours,
        )
        # Restore learning state from DB so it survives restarts
        self.adaptive_learner.load_state(db_manager)
        self.logger.info("Case generator initialized — autonomous case creation enabled")

    def _generate_cases(
        self,
        assessment: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Stage 8: Auto-generate a case from the hunt assessment."""
        if not self.case_generator:
            return assessment

        try:
            hunt_cycle = data.get("_cycle", 0)
            source = data.get("_source", "autonomous")
            case = self.case_generator.evaluate_and_create(
                assessment, hunt_cycle=hunt_cycle, source=source,
            )
            if case:
                assessment["auto_case"] = case.to_dict()
                self.logger.info(
                    f"Stage 8: Auto-created case {case.case_id}: {case.title} "
                    f"[{case.escalation_level.value}]"
                )
            else:
                self.logger.debug("Stage 8: No case created (below threshold)")
        except Exception as e:
            self.logger.error(f"Stage 8: Case generation failed: {e}")

        return assessment

    def _index_to_rag(
        self,
        agent_outputs: List[AgentOutput],
        data: Dict[str, Any],
    ):
        """Stage 7: Index hunt findings into the RAG store."""
        if not getattr(self, 'rag_store', None):
            return
        if not self.rag_store.available:
            return

        findings = []
        for output in agent_outputs:
            for f in output.findings:
                findings.append({
                    "activity_type": f.activity_type,
                    "description": f.description,
                    "indicators": f.indicators,
                    "severity": (
                        output.severity.value
                        if hasattr(output.severity, "value")
                        else str(output.severity)
                    ),
                    "mitre_techniques": getattr(f, 'mitre_techniques', []),
                    "agent_name": output.agent_name,
                    "confidence": output.confidence,
                })

        counts = data.get("_counts", {})
        baseline = None
        if counts:
            baseline = {
                "type": "hunt_cycle",
                "scope": "global",
                "total_connections": counts.get("network_connections", 0),
                "total_dns": counts.get("dns_queries", 0),
                "total_ntlm": counts.get("ntlm_logs", 0),
            }

        if findings or baseline:
            indexed = self.rag_store.index_hunt_results(findings, baseline)
            self.logger.info(f"RAG: indexed {indexed} items from this hunt cycle")

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
