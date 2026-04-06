"""
Hunt Effectiveness Evaluator — monitors LLM agent productivity during
CrewAI hunts and intervenes when analysis becomes unproductive.

Combines heuristic metrics (diversity, repetition, information gain) with
periodic LLM-based evaluation to build a reward signal that can be used
for reinforcement-learning-style feedback.

Architecture
------------
- **HuntEffectivenessEvaluator**: Tracks every tool call and reasoning
  step during a hunt.  Computes a rolling effectiveness score (0-1).
- **Heuristic signals** (cheap, every step):
    - Query diversity: are Splunk queries exploring new angles or repeating?
    - Information gain: are results getting richer or returning 0 rows?
    - Progress rate: are new findings/insights being generated?
    - Repetition detection: is the LLM stuck in a loop?
- **LLM evaluation** (expensive, periodic):
    - Every N steps, a lightweight LLM call asks: "Given the investigation
      so far, is the agent making productive progress or spinning?"
    - Returns a structured score + reasoning.
- **Intervention**: When effectiveness drops below threshold for sustained
  period, signals the Splunk tool to inject a redirect prompt and logs
  an alert.  Does NOT kill the hunt — nudges the LLM to change approach.
- **Persistence**: Effectiveness scores are saved per-cycle for RL-style
  learning across hunt cycles.
"""

import hashlib
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("artemis.llm.effectiveness")


@dataclass
class ToolCall:
    """Record of a single tool invocation during a hunt."""
    timestamp: float
    tool_name: str
    input_summary: str  # first 200 chars of input
    output_summary: str  # first 200 chars of output
    result_count: int  # rows returned (for Splunk), items found, etc.
    elapsed_seconds: float
    input_hash: str  # hash of full input for dedup detection


@dataclass
class EffectivenessSnapshot:
    """Point-in-time effectiveness measurement."""
    timestamp: float
    score: float  # 0.0 (spinning) to 1.0 (highly productive)
    query_diversity: float  # 0-1: how varied are the queries?
    info_gain: float  # 0-1: are results returning useful data?
    progress_rate: float  # 0-1: new insights per unit time
    repetition_penalty: float  # 0-1: how much looping detected?
    reasoning: str  # human-readable explanation
    is_llm_evaluated: bool  # was this from an LLM eval or heuristic-only?


class HuntEffectivenessEvaluator:
    """Monitors and scores the effectiveness of LLM-driven analysis.

    Usage::

        evaluator = HuntEffectivenessEvaluator(cycle=5)

        # Call from step_callback:
        evaluator.record_step(step_text)

        # Call from tool wrapper:
        evaluator.record_tool_call("query_splunk", input_str, output_str,
                                   result_count=42, elapsed=3.5)

        # Check if we should intervene:
        if evaluator.should_intervene():
            # inject guidance into next tool response
            guidance = evaluator.get_intervention_guidance()
    """

    # --- Configuration (overridable via env vars) ---
    EVAL_INTERVAL_STEPS = int(os.environ.get(
        "HUNT_EVAL_INTERVAL", "10"))  # evaluate every N steps
    LLM_EVAL_INTERVAL_STEPS = int(os.environ.get(
        "HUNT_LLM_EVAL_INTERVAL", "20"))  # LLM eval every N steps
    INTERVENE_THRESHOLD = float(os.environ.get(
        "HUNT_INTERVENE_THRESHOLD", "0.25"))  # score below this = intervene
    INTERVENE_SUSTAIN_COUNT = int(os.environ.get(
        "HUNT_INTERVENE_SUSTAIN", "3"))  # must be low for N evals before act
    MAX_DUPLICATE_QUERIES = int(os.environ.get(
        "HUNT_MAX_DUPLICATE_QUERIES", "3"))  # same query N times = penalty

    def __init__(
        self,
        cycle: int = 0,
        llm_eval_fn: Optional[Callable] = None,
        on_activity: Optional[Callable] = None,
    ):
        """
        Args:
            cycle: Current hunt cycle number.
            llm_eval_fn: Optional callable(prompt: str) -> str for LLM evals.
                         If None, only heuristic scoring is used.
            on_activity: Optional callable(agent, type, detail) to fire
                         agent activity events for the monitoring dashboard.
        """
        self.cycle = cycle
        self._llm_eval_fn = llm_eval_fn
        self._on_activity = on_activity

        # Tracking state
        self._tool_calls: List[ToolCall] = []
        self._steps: List[str] = []  # reasoning step summaries
        self._step_count = 0
        self._query_hashes: Dict[str, int] = {}  # hash -> count
        self._snapshots: List[EffectivenessSnapshot] = []
        self._low_score_streak = 0
        self._intervened = False
        self._intervention_count = 0
        self._start_time = time.monotonic()

        # Rolling windows for rate calculations
        self._recent_result_counts = deque(maxlen=20)
        self._recent_step_times = deque(maxlen=20)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_step(self, step_text: str):
        """Record a reasoning step from the step_callback."""
        self._step_count += 1
        self._steps.append(step_text[:500])
        self._recent_step_times.append(time.monotonic())

        # Periodic evaluation
        if self._step_count % self.EVAL_INTERVAL_STEPS == 0:
            use_llm = (
                self._llm_eval_fn is not None and
                self._step_count % self.LLM_EVAL_INTERVAL_STEPS == 0
            )
            self._evaluate(use_llm=use_llm)

    def record_tool_call(
        self,
        tool_name: str,
        input_str: str,
        output_str: str,
        result_count: int = 0,
        elapsed: float = 0.0,
    ):
        """Record a tool invocation and its outcome."""
        input_hash = hashlib.sha256(input_str.encode()).hexdigest()[:16]

        tc = ToolCall(
            timestamp=time.monotonic(),
            tool_name=tool_name,
            input_summary=input_str[:200],
            output_summary=output_str[:200],
            result_count=result_count,
            elapsed_seconds=elapsed,
            input_hash=input_hash,
        )
        self._tool_calls.append(tc)
        self._recent_result_counts.append(result_count)

        # Track query repetition
        if tool_name == "query_splunk":
            self._query_hashes[input_hash] = (
                self._query_hashes.get(input_hash, 0) + 1
            )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _evaluate(self, use_llm: bool = False) -> EffectivenessSnapshot:
        """Compute current effectiveness score."""
        diversity = self._calc_query_diversity()
        info_gain = self._calc_info_gain()
        progress = self._calc_progress_rate()
        repetition = self._calc_repetition_penalty()

        # Weighted combination
        heuristic_score = (
            0.25 * diversity +
            0.30 * info_gain +
            0.25 * progress +
            0.20 * (1.0 - repetition)  # invert: high repetition = low score
        )

        reasoning = (
            f"diversity={diversity:.2f}, info_gain={info_gain:.2f}, "
            f"progress={progress:.2f}, repetition={repetition:.2f}"
        )

        # Optional LLM evaluation for richer signal
        llm_evaluated = False
        if use_llm and self._llm_eval_fn:
            try:
                llm_score, llm_reasoning = self._llm_evaluate()
                if llm_score is not None:
                    # Blend: 60% LLM, 40% heuristic
                    heuristic_score = 0.4 * heuristic_score + 0.6 * llm_score
                    reasoning += f" | LLM: {llm_reasoning}"
                    llm_evaluated = True
            except Exception as e:
                logger.debug(f"LLM effectiveness eval failed: {e}")

        snap = EffectivenessSnapshot(
            timestamp=time.monotonic(),
            score=round(heuristic_score, 3),
            query_diversity=round(diversity, 3),
            info_gain=round(info_gain, 3),
            progress_rate=round(progress, 3),
            repetition_penalty=round(repetition, 3),
            reasoning=reasoning,
            is_llm_evaluated=llm_evaluated,
        )
        self._snapshots.append(snap)

        # Track low-score streak
        if snap.score < self.INTERVENE_THRESHOLD:
            self._low_score_streak += 1
        else:
            self._low_score_streak = 0

        # Fire activity event for monitoring dashboard
        if self._on_activity:
            try:
                self._on_activity("effectiveness_evaluator", "stage", {
                    "message": (
                        f"Effectiveness: {snap.score:.0%} "
                        f"(step {self._step_count})"
                    ),
                    "score": snap.score,
                    "diversity": snap.query_diversity,
                    "info_gain": snap.info_gain,
                    "progress": snap.progress_rate,
                    "repetition": snap.repetition_penalty,
                    "step": self._step_count,
                    "tool_calls": len(self._tool_calls),
                    "low_streak": self._low_score_streak,
                    "llm_evaluated": llm_evaluated,
                })
            except Exception:
                pass

        logger.info(
            f"Effectiveness eval (step {self._step_count}): "
            f"score={snap.score:.2f}, {reasoning}"
        )

        return snap

    def _calc_query_diversity(self) -> float:
        """How varied are the Splunk queries? 1.0 = all unique, 0.0 = all same."""
        splunk_calls = [
            tc for tc in self._tool_calls if tc.tool_name == "query_splunk"
        ]
        if len(splunk_calls) < 2:
            return 1.0  # not enough data yet

        unique_hashes = len(set(tc.input_hash for tc in splunk_calls))
        return unique_hashes / len(splunk_calls)

    def _calc_info_gain(self) -> float:
        """Are tool calls returning useful data? Based on result counts."""
        if not self._recent_result_counts:
            return 0.5  # neutral if no data

        counts = list(self._recent_result_counts)
        # Fraction of recent calls that returned results
        non_zero = sum(1 for c in counts if c > 0)
        return non_zero / len(counts)

    def _calc_progress_rate(self) -> float:
        """Are new insights being generated? Based on step output diversity."""
        if len(self._steps) < 5:
            return 0.8  # assume productive early on

        # Look at the last 10 steps — how many are substantively different?
        recent = self._steps[-10:]
        hashes = set()
        for s in recent:
            # Hash first 100 chars to detect near-duplicates
            h = hashlib.sha256(s[:100].encode()).hexdigest()[:8]
            hashes.add(h)

        return len(hashes) / len(recent)

    def _calc_repetition_penalty(self) -> float:
        """Detect looping: same queries repeated, same step patterns."""
        if not self._query_hashes:
            return 0.0  # no penalty without data

        # Count queries that exceeded the duplicate threshold
        over_limit = sum(
            1 for count in self._query_hashes.values()
            if count > self.MAX_DUPLICATE_QUERIES
        )
        total_unique = len(self._query_hashes)
        if total_unique == 0:
            return 0.0

        return min(1.0, over_limit / max(total_unique, 1))

    def _llm_evaluate(self) -> tuple:
        """Ask the LLM to evaluate investigation effectiveness.

        Returns (score: float, reasoning: str) or (None, "") on failure.
        """
        # Build a compact summary of recent activity
        recent_tools = self._tool_calls[-10:]
        tool_summary = "\n".join(
            f"  - {tc.tool_name}: {tc.input_summary[:100]} → "
            f"{tc.result_count} results ({tc.elapsed_seconds:.0f}s)"
            for tc in recent_tools
        )
        recent_steps = "\n".join(
            f"  - {s[:150]}" for s in self._steps[-5:]
        )

        prompt = (
            "You are evaluating the effectiveness of a threat hunting "
            "investigation. Score it 0.0 (completely unproductive, looping) "
            "to 1.0 (highly productive, making new discoveries).\n\n"
            f"Steps completed: {self._step_count}\n"
            f"Tool calls: {len(self._tool_calls)}\n"
            f"Unique Splunk queries: {len(self._query_hashes)}\n\n"
            f"Recent tool calls:\n{tool_summary}\n\n"
            f"Recent reasoning steps:\n{recent_steps}\n\n"
            "Respond with ONLY a JSON object: "
            '{\"score\": 0.X, \"reasoning\": \"brief explanation\"}'
        )

        response = self._llm_eval_fn(prompt)
        if not response:
            return None, ""

        # Parse response
        import json
        try:
            # Try to extract JSON from response
            import re
            match = re.search(r'\{[^}]+\}', response)
            if match:
                data = json.loads(match.group())
                score = float(data.get("score", 0.5))
                score = max(0.0, min(1.0, score))
                reasoning = data.get("reasoning", "")[:200]
                return score, reasoning
        except (json.JSONDecodeError, ValueError):
            pass

        return None, ""

    # ------------------------------------------------------------------
    # Intervention
    # ------------------------------------------------------------------

    def should_intervene(self) -> bool:
        """Should we inject guidance into the next tool response?

        Returns True when effectiveness has been low for a sustained period.
        """
        return (
            self._low_score_streak >= self.INTERVENE_SUSTAIN_COUNT and
            not self._intervened
        )

    def get_intervention_guidance(self) -> str:
        """Get redirect prompt to inject into the next tool response.

        Marks intervention as delivered so it only fires once per streak.
        """
        self._intervened = True
        self._intervention_count += 1

        # Analyze what's going wrong
        issues = []
        if self._snapshots:
            latest = self._snapshots[-1]
            if latest.query_diversity < 0.4:
                issues.append(
                    "You are repeating similar Splunk queries. Try a "
                    "completely different investigation angle — different "
                    "sourcetypes, different fields, different hosts.")
            if latest.info_gain < 0.3:
                issues.append(
                    "Most of your recent queries returned 0 results. "
                    "Check that you're using the correct index, "
                    "sourcetype, and field names for this environment.")
            if latest.repetition_penalty > 0.5:
                issues.append(
                    "You appear to be in a loop. Stop and summarize what "
                    "you've found so far, then decide on ONE new "
                    "investigation direction.")
            if latest.progress_rate < 0.3:
                issues.append(
                    "Your analysis steps are not generating new insights. "
                    "Consider moving to your final synthesis based on "
                    "what you've already gathered.")

        if not issues:
            issues.append(
                "Your investigation appears to have stalled. Summarize "
                "your findings so far and proceed to your final assessment.")

        if self._on_activity:
            try:
                self._on_activity("effectiveness_evaluator", "alert", {
                    "message": (
                        f"Intervention #{self._intervention_count}: "
                        f"redirecting unproductive analysis"
                    ),
                    "issues": issues,
                    "step": self._step_count,
                    "score": self._snapshots[-1].score if self._snapshots else 0,
                })
            except Exception:
                pass

        logger.warning(
            f"Hunt effectiveness intervention #{self._intervention_count} "
            f"at step {self._step_count}: {'; '.join(issues)}"
        )

        guidance = (
            "\n\n--- EFFECTIVENESS MONITOR ---\n"
            "Your investigation effectiveness has dropped. "
            + " ".join(issues) +
            "\n--- END MONITOR ---\n"
        )
        return guidance

    def reset_intervention(self):
        """Allow intervention to fire again after score recovers."""
        self._intervened = False
        self._low_score_streak = 0

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    @property
    def current_score(self) -> float:
        """Latest effectiveness score, or 1.0 if not yet evaluated."""
        if self._snapshots:
            return self._snapshots[-1].score
        return 1.0

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of effectiveness metrics for this hunt cycle.

        Suitable for persisting to the DB as an RL reward signal.
        """
        splunk_calls = [
            tc for tc in self._tool_calls if tc.tool_name == "query_splunk"
        ]
        total_splunk_time = sum(tc.elapsed_seconds for tc in splunk_calls)
        successful_queries = sum(
            1 for tc in splunk_calls if tc.result_count > 0
        )

        scores = [s.score for s in self._snapshots]
        avg_score = sum(scores) / len(scores) if scores else 1.0

        return {
            "cycle": self.cycle,
            "total_steps": self._step_count,
            "total_tool_calls": len(self._tool_calls),
            "total_splunk_queries": len(splunk_calls),
            "unique_splunk_queries": len(self._query_hashes),
            "successful_queries": successful_queries,
            "total_splunk_time_seconds": round(total_splunk_time, 1),
            "avg_effectiveness_score": round(avg_score, 3),
            "min_effectiveness_score": round(min(scores), 3) if scores else 1.0,
            "max_effectiveness_score": round(max(scores), 3) if scores else 1.0,
            "intervention_count": self._intervention_count,
            "total_elapsed_seconds": round(
                time.monotonic() - self._start_time, 1),
            "evaluations": len(self._snapshots),
            "final_score": self.current_score,
            "snapshots": [
                {
                    "step": i * self.EVAL_INTERVAL_STEPS,
                    "score": s.score,
                    "reasoning": s.reasoning[:200],
                }
                for i, s in enumerate(self._snapshots)
            ],
        }
