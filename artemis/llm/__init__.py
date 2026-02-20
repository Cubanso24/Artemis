"""
Artemis LLM Layer — intelligent threat hunting with RAG and CrewAI.

Components
----------
- **LLMClient**: Backend abstraction (Anthropic / Ollama).
- **CoordinatorLLM**: Hypothesis generation, agent directives, synthesis.
- **AgentLLM**: Per-agent specialist enrichment.
- **RAGStore**: ChromaDB vector store for historical findings, baselines,
  and threat intel.
- **CrewOrchestrator**: CrewAI-based multi-agent orchestration (optional).
"""

from artemis.llm.client import LLMClient
from artemis.llm.coordinator_llm import CoordinatorLLM
from artemis.llm.agent_llm import AgentLLM
from artemis.llm.rag import RAGStore

__all__ = ["LLMClient", "CoordinatorLLM", "AgentLLM", "RAGStore"]
