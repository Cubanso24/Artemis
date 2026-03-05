"""
CrewAI orchestration layer for Artemis.

Replaces the sequential coordinator pipeline with a CrewAI-managed
crew of specialist hunting agents that can collaborate, share context,
and dynamically delegate tasks.

The crew mirrors the existing agent architecture:
- **Lead Analyst** (coordinator) — generates hypotheses, delegates work,
  synthesises results.
- **Specialist Agents** — one per hunting domain (C2, recon, lateral
  movement, collection/exfil, impact).

Each CrewAI agent gets:
- A domain-specific backstory (from the existing AGENT_SYSTEM_PROMPTS)
- Access to tools: ``search_past_findings``, ``search_threat_intel``,
  ``query_network_baseline``, ``run_detector`` (wraps the threshold
  detector).
- RAG context injected automatically via the tools.

Design decisions
----------------
- CrewAI is the *orchestration* layer — the underlying analysis logic in
  ``artemis/agents/`` is preserved and exposed as tools.
- The LLM backend is the same ``LLMClient`` used elsewhere, so Ollama
  works transparently.
- Falls back to the existing ``MetaLearnerCoordinator`` if CrewAI is not
  installed.
"""

import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from artemis.llm.prompts import (
    AGENT_SYSTEM_PROMPTS,
    COORDINATOR_HYPOTHESIS_SYSTEM,
    format_hunting_data_summary,
    format_network_state,
)
from artemis.models.agent_output import AgentOutput, Finding, Evidence, Severity
from artemis.models.network_state import NetworkState
from artemis.ws import fire_agent_activity

logger = logging.getLogger("artemis.llm.crew")

# ---------------------------------------------------------------------------
# Lazy imports — CrewAI is optional
# ---------------------------------------------------------------------------

_CREWAI_AVAILABLE = False

try:
    from crewai import Agent, Task, Crew, Process, LLM
    from crewai.tools import tool as crewai_tool
    _CREWAI_AVAILABLE = True
except ImportError:
    pass


def crewai_available() -> bool:
    return _CREWAI_AVAILABLE


# ---------------------------------------------------------------------------
# RAG-backed tools (created at runtime with a bound RAGStore)
# ---------------------------------------------------------------------------

def _make_tools(rag_store, detectors, hunting_data, network_state):
    """Build CrewAI tool functions bound to the current hunt context.

    Returns a list of tool callables decorated with ``@crewai_tool``.
    """
    tools = []

    # 1. Search past findings -------------------------------------------
    @crewai_tool
    def search_past_findings(query: str) -> str:
        """Search the RAG vector store for similar historical findings.
        Returns past detections, analyst feedback, and outcomes.
        Use this to check if a pattern was seen before and whether it
        was a true positive or false positive."""
        if rag_store is None or not rag_store.available:
            return "RAG store not available."
        results = rag_store.query_similar_findings(query, n_results=5)
        if not results:
            return "No similar past findings found."
        lines = []
        for i, r in enumerate(results, 1):
            fb = r["metadata"].get("feedback", "")
            fb_str = f" [Analyst feedback: {fb}]" if fb else ""
            lines.append(
                f"{i}. (similarity={r['similarity']:.2f}){fb_str}\n"
                f"   {r['text'][:400]}"
            )
        return "\n".join(lines)

    tools.append(search_past_findings)

    # 2. Search threat intel --------------------------------------------
    @crewai_tool
    def search_threat_intel(query: str) -> str:
        """Search threat intelligence for IOCs, campaigns, and TTP
        profiles relevant to the given query.  Use this when you need
        to correlate indicators with known threats."""
        if rag_store is None or not rag_store.available:
            return "RAG store not available."
        results = rag_store.query_threat_intel(query, n_results=5)
        if not results:
            return "No matching threat intelligence found."
        lines = []
        for i, r in enumerate(results, 1):
            src = r["metadata"].get("source", "?")
            lines.append(f"{i}. [{src}] {r['text'][:400]}")
        return "\n".join(lines)

    tools.append(search_threat_intel)

    # 3. Query network baselines ----------------------------------------
    @crewai_tool
    def query_network_baseline(query: str) -> str:
        """Query known-normal network baselines.  Use this to determine
        whether observed behaviour is expected for this environment
        (e.g., normal DNS servers, typical traffic patterns)."""
        if rag_store is None or not rag_store.available:
            return "RAG store not available."
        results = rag_store.query_baselines(query, n_results=3)
        if not results:
            return "No matching baselines found."
        return "\n".join(
            f"{i}. {r['text'][:400]}" for i, r in enumerate(results, 1)
        )

    tools.append(query_network_baseline)

    # 4. Run threshold detectors ----------------------------------------
    @crewai_tool
    def run_detector(agent_name: str) -> str:
        """Run a threshold-based hunting detector and return its findings.
        Valid agent names: c2_hunter, reconnaissance_hunter,
        initial_access_hunter, execution_persistence_hunter,
        credential_access_hunter, lateral_movement_hunter,
        collection_exfiltration_hunter, defense_evasion_hunter,
        impact_hunter."""
        det = detectors.get(agent_name)
        if det is None:
            return f"Unknown detector: {agent_name}"
        try:
            output = det.analyze(hunting_data, network_state)
            if not output.findings:
                return f"{agent_name}: No findings (confidence={output.confidence:.2f})"
            lines = [f"{agent_name}: {len(output.findings)} finding(s)"]
            for f in output.findings:
                lines.append(
                    f"  - [{f.activity_type}] {f.description[:200]}"
                    f"\n    Indicators: {', '.join(str(i) for i in f.indicators[:5])}"
                )
            return "\n".join(lines)
        except Exception as e:
            return f"Detector {agent_name} failed: {e}"

    tools.append(run_detector)

    # 5. Get current data summary ---------------------------------------
    @crewai_tool
    def get_hunting_data_summary(unused: str = "") -> str:
        """Get a statistical summary of the current hunting data
        (connection counts, top ports, DNS domains, etc.).  Always
        call this first to understand what data is available."""
        return format_hunting_data_summary(hunting_data)

    tools.append(get_hunting_data_summary)

    # 6. Get network state ----------------------------------------------
    @crewai_tool
    def get_network_state(unused: str = "") -> str:
        """Get the current network state including traffic metrics,
        asset inventory, and network map summary."""
        if network_state is None:
            return "Network state not available."
        return format_network_state(network_state)

    tools.append(get_network_state)

    return tools


# ---------------------------------------------------------------------------
# CrewAI Agent definitions
# ---------------------------------------------------------------------------

def _build_agents(llm, tools: list) -> Dict[str, Any]:
    """Create the CrewAI Agent instances.

    Args:
        llm: A CrewAI ``LLM`` instance (not a raw string).
        tools: List of CrewAI tool callables.

    Returns a dict mapping agent_name -> CrewAI Agent.
    """
    agents = {}

    # Lead analyst (coordinator)
    agents["lead_analyst"] = Agent(
        role="Lead Threat Analyst",
        goal=(
            "Analyse the hunting data, form threat hypotheses, "
            "delegate investigation tasks to specialist hunters, "
            "and synthesise a unified threat assessment."
        ),
        backstory=(
            "You are the lead threat analyst for an enterprise SOC. "
            "You have deep expertise in MITRE ATT&CK, kill chain analysis, "
            "and APT campaign tracking.  You coordinate a team of specialist "
            "hunters and produce actionable intelligence for incident response."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=True,
    )

    # Specialist hunters
    _SPECIALIST_MAP = {
        "c2_hunter": {
            "role": "C2 Communication Hunter",
            "goal": (
                "Detect command-and-control communication patterns including "
                "beaconing, DGA domains, DNS tunnelling, and covert channels."
            ),
        },
        "reconnaissance_hunter": {
            "role": "Reconnaissance Hunter",
            "goal": (
                "Detect network reconnaissance activity including port scans, "
                "service enumeration, DNS recon, and network sweeps."
            ),
        },
        "initial_access_hunter": {
            "role": "Initial Access Hunter",
            "goal": (
                "Detect initial access attempts including phishing indicators, "
                "exploit delivery, drive-by downloads, and supply chain compromise."
            ),
        },
        "execution_persistence_hunter": {
            "role": "Execution & Persistence Hunter",
            "goal": (
                "Detect malicious execution and persistence mechanisms including "
                "PowerShell abuse, LOLBins, scheduled tasks, and registry modifications."
            ),
        },
        "credential_access_hunter": {
            "role": "Credential Access Hunter",
            "goal": (
                "Detect credential theft and abuse including credential dumping, "
                "Kerberoasting, pass-the-hash, brute force, and password spraying."
            ),
        },
        "lateral_movement_hunter": {
            "role": "Lateral Movement Hunter",
            "goal": (
                "Detect lateral movement including RDP/SMB/SSH fan-out, "
                "credential misuse, pass-the-hash, and WinRM exploitation."
            ),
        },
        "collection_exfiltration_hunter": {
            "role": "Collection & Exfiltration Hunter",
            "goal": (
                "Detect data collection and exfiltration including staging, "
                "cloud uploads, DNS exfiltration, and covert channels."
            ),
        },
        "defense_evasion_hunter": {
            "role": "Defense Evasion Hunter",
            "goal": (
                "Detect defense evasion techniques including log deletion, "
                "security tool tampering, process injection, and timestomping."
            ),
        },
        "impact_hunter": {
            "role": "Impact Hunter",
            "goal": (
                "Detect impact activities including cryptomining, ransomware "
                "SMB patterns, DDoS, and resource exhaustion."
            ),
        },
    }

    for name, cfg in _SPECIALIST_MAP.items():
        backstory = AGENT_SYSTEM_PROMPTS.get(name, cfg["goal"])
        agents[name] = Agent(
            role=cfg["role"],
            goal=cfg["goal"],
            backstory=backstory,
            tools=tools,
            llm=llm,
            verbose=True,
            allow_delegation=False,
        )

    return agents


# ---------------------------------------------------------------------------
# Task definitions
# ---------------------------------------------------------------------------

def _build_tasks(
    agents: Dict[str, Any],
    hunting_data: Dict[str, Any],
    network_state: Optional[NetworkState],
    detector_findings: Optional[List[Any]] = None,
) -> List[Any]:
    """Build the CrewAI Task list for a single hunt cycle."""

    data_summary = format_hunting_data_summary(hunting_data)
    state_text = format_network_state(network_state) if network_state else ""

    # Build a summary of ML detector findings so the LLM has them upfront
    findings_block = ""
    _findings_by_agent: Dict[str, str] = {}
    if detector_findings:
        lines = ["=== ML DETECTOR FINDINGS (run before LLM analysis) ==="]
        for output in detector_findings:
            agent_lines = []
            agent_name = getattr(output, 'agent_name', 'unknown')
            if output.findings:
                agent_lines.append(
                    f"\n[{agent_name}] "
                    f"{len(output.findings)} finding(s), "
                    f"confidence={output.confidence:.2f}"
                )
                for f in output.findings:
                    desc = f.description[:300] if hasattr(f, 'description') else str(f)[:300]
                    agent_lines.append(f"  - [{f.activity_type}] {desc}")
                    if hasattr(f, 'indicators') and f.indicators:
                        agent_lines.append(
                            f"    Indicators: {', '.join(str(i) for i in f.indicators[:5])}"
                        )
            elif output.confidence > 0:
                agent_lines.append(
                    f"\n[{agent_name}] No findings but confidence={output.confidence:.2f}"
                )
            if agent_lines:
                agent_text = "\n".join(agent_lines)
                lines.extend(agent_lines)
                _findings_by_agent[agent_name] = agent_text
        if len(lines) > 1:
            findings_block = "\n".join(lines) + "\n"
        else:
            findings_block = "\n=== ML DETECTORS: No findings this cycle ===\n"

    context_block = f"{state_text}\n\n{data_summary}\n\n{findings_block}"

    # 1. Hypothesis generation (lead analyst)
    hypothesis_desc = (
        f"Analyse the following network state, hunting data, and ML "
        f"detector findings, then generate 3-6 threat hypotheses.  For "
        f"each hypothesis specify the type (kill_chain_stage, ttp_pattern, "
        f"anomaly_investigation, insider_threat, apt_campaign), priority "
        f"(0-1), confidence (0-1), and which specialist hunters should "
        f"investigate.\n\n"
        f"{context_block}"
    )
    hypothesis_expected = (
        "A numbered list of threat hypotheses with type, description, "
        "priority, confidence, and assigned specialist agents."
    )
    fire_agent_activity("lead_analyst", "prompt", {
        "message": "Generating threat hypotheses from network state and ML findings",
        "prompt_text": hypothesis_desc[:4000],
        "expected_output": hypothesis_expected,
    })
    hypothesis_task = Task(
        description=hypothesis_desc,
        expected_output=hypothesis_expected,
        agent=agents["lead_analyst"],
    )

    # 2. Specialist investigations (one task per hunter)
    specialist_tasks = []
    for name in ("c2_hunter", "reconnaissance_hunter",
                 "initial_access_hunter", "execution_persistence_hunter",
                 "credential_access_hunter", "lateral_movement_hunter",
                 "collection_exfiltration_hunter", "defense_evasion_hunter",
                 "impact_hunter"):
        agent = agents.get(name)
        if agent is None:
            continue

        # Include this agent's ML findings directly in the task description
        agent_findings_text = _findings_by_agent.get(name, "No ML findings for this agent.")
        n_agent_findings = len(_findings_by_agent.get(name, "").split("\n")) - 1

        specialist_desc = (
            f"Investigate your domain based on the lead analyst's "
            f"hypotheses and the ML detector findings below.\n\n"
            f"YOUR ML DETECTOR RESULTS:\n{agent_findings_text}\n\n"
            f"Steps:\n"
            f"1. Review the ML detector findings above for your domain.\n"
            f"2. Call search_past_findings with a summary of any findings "
            f"   to check for historical context.\n"
            f"3. Call search_threat_intel if indicators match known threats.\n"
            f"4. Call query_network_baseline to filter out normal behaviour.\n"
            f"5. Optionally call run_detector with '{name}' for a fresh "
            f"   run if you need more detail.\n"
            f"6. Produce your assessment: for each finding, state whether "
            f"   it is a true positive or false positive, your confidence "
            f"   (0-1), MITRE techniques, and recommended actions.\n"
            f"   Also note any patterns the detector missed."
        )
        specialist_expected = (
            "A structured analysis with: findings (true/false positive "
            "assessment, confidence, MITRE techniques, evidence), "
            "missed patterns, and recommended actions."
        )

        # Log task assignment with actual prompt so it shows in the agent monitor
        fire_agent_activity(name, "prompt", {
            "message": f"Assigned investigation task "
                       f"({n_agent_findings} ML findings to review)",
            "prompt_text": specialist_desc[:4000],
            "expected_output": specialist_expected,
        })

        task = Task(
            description=specialist_desc,
            expected_output=specialist_expected,
            agent=agent,
            context=[hypothesis_task],
        )
        specialist_tasks.append(task)

    # 3. Synthesis (lead analyst aggregates all specialist results)
    synthesis_desc = (
        "Synthesise the specialist investigations into a unified threat "
        "assessment.  Steps:\n"
        "1. Review all specialist findings.\n"
        "2. Identify correlations across agents (e.g., recon followed "
        "   by lateral movement).\n"
        "3. Assess kill chain progression.\n"
        "4. Flag likely false positives.\n"
        "5. Produce a final report with: threat narrative, overall "
        "   severity (low/medium/high/critical), overall confidence "
        "   (0-1), correlated findings, false positives, and "
        "   prioritised response actions."
    )
    synthesis_expected = (
        "A unified threat assessment with: threat_narrative, "
        "overall_severity, overall_confidence, correlated_findings, "
        "likely_false_positives, and recommended_actions."
    )
    fire_agent_activity("lead_analyst", "prompt", {
        "message": f"Assigned synthesis task — aggregating "
                   f"{len(specialist_tasks)} specialist investigations",
        "prompt_text": synthesis_desc,
        "expected_output": synthesis_expected,
    })
    synthesis_task = Task(
        description=synthesis_desc,
        expected_output=synthesis_expected,
        agent=agents["lead_analyst"],
        context=specialist_tasks,
    )

    return [hypothesis_task] + specialist_tasks + [synthesis_task]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class CrewOrchestrator:
    """Manages a CrewAI-based hunting crew.

    Drop-in alternative to ``MetaLearnerCoordinator.hunt()`` — call
    ``hunt()`` with the same arguments and get back the same assessment
    dict structure.
    """

    def __init__(
        self,
        detectors: Dict[str, Any],
        rag_store: Optional[Any] = None,
        llm_model: str = "ollama/llama3.1",
        process: str = "sequential",
        verbose: bool = True,
        num_ctx: Optional[int] = None,
    ):
        """
        Args:
            detectors: Dict mapping agent_name -> BaseAgent instances
                       (the existing threshold-based detectors).
            rag_store: Optional RAGStore for retrieval-augmented context.
            llm_model: Model string for CrewAI agents.  For Ollama use
                       ``"ollama/<model>"`` (e.g. ``"ollama/llama3.1"``).
            process: CrewAI process type — "sequential" or "hierarchical".
            verbose: Enable verbose CrewAI logging.
            num_ctx: Ollama context window size (default from OLLAMA_NUM_CTX
                     env var or 131072).
        """
        if not _CREWAI_AVAILABLE:
            raise ImportError(
                "crewai is not installed.  Install with: "
                "pip install crewai crewai-tools"
            )

        self.detectors = detectors
        self.rag_store = rag_store
        self.llm_model = llm_model

        # Build a proper CrewAI LLM instance so LiteLLM knows the
        # Ollama base URL (passing a bare string fails silently).
        ollama_base = os.environ.get(
            "OLLAMA_API_BASE",
            os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        )
        self.num_ctx = num_ctx or int(
            os.environ.get("OLLAMA_NUM_CTX", "131072")
        )
        self.llm = LLM(
            model=llm_model,
            base_url=ollama_base,
            num_ctx=self.num_ctx,
        )

        self.process = (
            Process.hierarchical if process == "hierarchical"
            else Process.sequential
        )
        self.verbose = verbose
        logger.info(
            f"CrewOrchestrator initialised (model={llm_model}, "
            f"base_url={ollama_base}, process={process}, "
            f"num_ctx={self.num_ctx}, "
            f"rag={'enabled' if rag_store else 'disabled'})"
        )

    def hunt(
        self,
        data: Dict[str, Any],
        network_state: Optional[NetworkState] = None,
        pre_computed_outputs: Optional[List[Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Run a CrewAI-orchestrated hunt cycle.

        Returns an assessment dict compatible with the existing
        ``MetaLearnerCoordinator.hunt()`` output.

        If *pre_computed_outputs* is provided, those ML detector outputs
        are used directly (avoiding a duplicate detector run).
        """
        start = time.time()
        logger.info("Starting CrewAI hunt cycle")
        fire_agent_activity("coordinator", "stage", {
            "message": "Starting CrewAI hunt cycle",
            "stage": 0,
        })

        # 1. Use pre-computed ML outputs or run detectors now
        if pre_computed_outputs is not None:
            agent_outputs = pre_computed_outputs
            total_findings = sum(len(o.findings) for o in agent_outputs)
            logger.info(f"Using {len(agent_outputs)} pre-computed ML outputs")
            fire_agent_activity("coordinator", "stage", {
                "message": f"Using {len(agent_outputs)} pre-computed ML "
                           f"outputs ({total_findings} findings)",
                "stage": 1,
            })
        else:
            logger.info("Running ML detectors before LLM synthesis...")
            fire_agent_activity("coordinator", "stage", {
                "message": "Running ML detectors",
                "stage": 1,
            })
            agent_outputs = self._run_detectors(data, network_state)
            detector_elapsed = time.time() - start
            total_findings = sum(len(o.findings) for o in agent_outputs)
            logger.info(
                f"ML detectors completed in {detector_elapsed:.1f}s: "
                f"{total_findings} findings from {len(agent_outputs)} agents"
            )
            fire_agent_activity("coordinator", "stage", {
                "message": f"ML detectors done: {total_findings} findings "
                           f"from {len(agent_outputs)} agents "
                           f"({detector_elapsed:.1f}s)",
                "stage": 1.5,
            })

        # 2. Build tools with current hunt context (detectors still
        #    available as tools for deeper investigation if the LLM wants)
        tools = _make_tools(
            self.rag_store, self.detectors, data, network_state
        )

        # 3. Build agents and tasks, injecting ML findings as context
        crew_agents = _build_agents(self.llm, tools)
        tasks = _build_tasks(
            crew_agents, data, network_state,
            detector_findings=agent_outputs,
        )

        agent_names = list(crew_agents.keys())
        fire_agent_activity("coordinator", "stage", {
            "message": f"Assembled crew: {len(agent_names)} agents, "
                       f"{len(tasks)} tasks",
            "stage": 2,
            "agents": agent_names,
        })

        # 4. Assemble and run the CrewAI crew for LLM synthesis
        manager_llm = None
        if self.process == Process.hierarchical:
            manager_llm = self.llm

        # CrewAI callbacks → agent monitoring.
        # Callbacks are fired SYNCHRONOUSLY by CrewAI during kickoff(),
        # so DB writes must be non-blocking to avoid SQLite lock contention
        # causing the entire hunt to stall.
        import threading as _threading

        def _fire_bg(agent_name, activity_type, detail):
            """Fire agent activity in a background daemon thread."""
            t = _threading.Thread(
                target=fire_agent_activity,
                args=(agent_name, activity_type, detail),
                daemon=True,
            )
            t.start()

        def _step_callback(step_output):
            """Fires after each agent reasoning step (non-blocking)."""
            try:
                agent_name = "unknown"
                text = str(step_output)[:2000]
                if hasattr(step_output, 'agent'):
                    agent_name = getattr(step_output.agent, 'role', 'unknown')

                # Extract thought/action from step if available
                thought = ""
                action = ""
                if hasattr(step_output, 'thought'):
                    thought = str(step_output.thought)[:1000]
                if hasattr(step_output, 'action'):
                    action = str(step_output.action)[:500]

                _fire_bg(agent_name, "response", {
                    "message": f"Step: {text[:200]}",
                    "output_preview": text[:2000],
                    "thought": thought,
                    "action": action,
                })
            except Exception:
                pass

        def _task_callback(task_output):
            """Fires after each CrewAI task completes (non-blocking)."""
            try:
                desc = ""
                if hasattr(task_output, 'description'):
                    desc = str(task_output.description)[:200]
                raw = str(task_output.raw)[:2000] if hasattr(task_output, 'raw') else str(task_output)[:2000]
                agent_role = ""
                if hasattr(task_output, 'agent'):
                    agent_role = str(task_output.agent)[:50]

                _fire_bg(agent_role or "crew", "response", {
                    "message": f"Task complete: {desc}",
                    "output_preview": raw,
                })
            except Exception:
                pass

        crew = Crew(
            agents=list(crew_agents.values()),
            tasks=tasks,
            process=self.process,
            manager_llm=manager_llm,
            verbose=self.verbose,
            step_callback=_step_callback,
            task_callback=_task_callback,
        )

        fire_agent_activity("coordinator", "stage", {
            "message": f"Kicking off CrewAI crew ({self.process})",
            "stage": 3,
        })

        result = crew.kickoff()

        elapsed = time.time() - start
        logger.info(f"CrewAI hunt completed in {elapsed:.1f}s")
        fire_agent_activity("coordinator", "stage", {
            "message": f"CrewAI hunt completed in {elapsed:.1f}s",
            "stage": 5,
        })

        # Build assessment dict matching the existing format
        assessment = self._build_assessment(result, agent_outputs, elapsed)

        # Index findings into RAG for future hunts
        self._index_to_rag(agent_outputs, data)

        return assessment

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_detectors(
        self, data: Dict[str, Any], network_state: Optional[NetworkState],
    ) -> List[AgentOutput]:
        """Run all threshold detectors and collect structured outputs."""
        outputs = []
        for name, det in self.detectors.items():
            try:
                output = det.analyze(data, network_state)
                if output.findings or output.confidence > 0:
                    outputs.append(output)
            except Exception as e:
                logger.error(f"Detector {name} failed: {e}")
        return outputs

    def _build_assessment(
        self,
        crew_result: Any,
        agent_outputs: List[AgentOutput],
        elapsed: float,
    ) -> Dict[str, Any]:
        """Convert CrewAI result + detector outputs into a standard assessment."""
        # Extract text from crew result
        crew_text = str(crew_result)

        # Determine severity from detector outputs
        max_confidence = max(
            (o.confidence for o in agent_outputs), default=0.0
        )
        total_findings = sum(len(o.findings) for o in agent_outputs)

        if max_confidence >= 0.8:
            severity = Severity.CRITICAL
        elif max_confidence >= 0.6:
            severity = Severity.HIGH
        elif max_confidence >= 0.4:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return {
            "final_confidence": max_confidence,
            "severity": severity,
            "recommendations": [],
            "agent_outputs": agent_outputs,
            "llm_synthesis": {
                "threat_narrative": crew_text,
                "overall_severity": severity.value if hasattr(severity, "value") else str(severity),
                "overall_confidence": max_confidence,
                "correlated_findings": [],
                "likely_false_positives": [],
                "recommended_actions": [],
                "orchestration": "crewai",
            },
            "correlation_score": 0.5,
            "metadata": {
                "orchestration": "crewai",
                "process": str(self.process),
                "elapsed_seconds": elapsed,
                "total_findings": total_findings,
            },
        }

    def _index_to_rag(
        self, agent_outputs: List[AgentOutput], data: Dict[str, Any],
    ):
        """Index hunt findings into the RAG store for future retrieval."""
        if self.rag_store is None or not self.rag_store.available:
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
                    "mitre_techniques": f.mitre_techniques,
                    "agent_name": output.agent_name,
                    "confidence": output.confidence,
                    "timestamp": datetime.utcnow().isoformat(),
                })

        # Build a baseline snapshot from data counts
        counts = data.get("_counts", {})
        if counts:
            baseline = {
                "type": "hunt_cycle",
                "scope": "global",
                "total_connections": counts.get("network_connections", 0),
                "total_dns": counts.get("dns_queries", 0),
                "total_ntlm": counts.get("ntlm_logs", 0),
                "description": format_hunting_data_summary(data)[:500],
            }
        else:
            baseline = None

        indexed = self.rag_store.index_hunt_results(findings, baseline)
        logger.info(f"Indexed {indexed} items to RAG store post-hunt")
