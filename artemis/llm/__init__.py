"""
Artemis LLM Layer — Two-tier LLM architecture for intelligent threat hunting.

Tier 1 (Coordinator): Claude Sonnet reasons about network state, generates
    threat hypotheses, directs agents, and synthesizes results.

Tier 2 (Agent Specialists): Claude Haiku provides domain-specific analysis
    for each hunting agent, enriching threshold-based detections with
    contextual reasoning and false-positive filtering.
"""

from artemis.llm.client import LLMClient
from artemis.llm.coordinator_llm import CoordinatorLLM
from artemis.llm.agent_llm import AgentLLM

__all__ = ["LLMClient", "CoordinatorLLM", "AgentLLM"]
