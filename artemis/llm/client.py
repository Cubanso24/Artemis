"""
LLM client abstraction for the Artemis threat hunting system.

Wraps the Anthropic API with:
- Graceful degradation when API key is not set or package is missing
- Separate model configs for coordinator (Sonnet) and agent (Haiku) tiers
- JSON response parsing with fallback extraction
- Error handling that never breaks the hunting pipeline
"""

import os
import json
from typing import Optional, Dict, Any, List

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from artemis.utils.logging_config import ArtemisLogger


class LLMClient:
    """
    Two-tier LLM client for Artemis.

    - coordinator model (Sonnet): high-level reasoning, hypothesis generation,
      agent direction, result synthesis
    - agent model (Haiku): fast domain-specific analysis for each hunting agent
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        coordinator_model: str = "claude-sonnet-4-5-20250929",
        agent_model: str = "claude-haiku-4-5-20251001",
    ):
        self.logger = ArtemisLogger.setup_logger("artemis.llm.client")
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.coordinator_model = coordinator_model
        self.agent_model = agent_model
        self._client: Optional[Any] = None

        if not ANTHROPIC_AVAILABLE:
            self.logger.warning(
                "anthropic package not installed — LLM features disabled. "
                "Install with: pip install anthropic"
            )
        elif not self.api_key:
            self.logger.warning(
                "ANTHROPIC_API_KEY not set — LLM features disabled. "
                "Set the environment variable to enable LLM-powered hunting."
            )
        else:
            try:
                self._client = Anthropic(api_key=self.api_key)
                self.logger.info(
                    f"LLM client initialized "
                    f"(coordinator={coordinator_model}, agent={agent_model})"
                )
            except Exception as e:
                self.logger.warning(f"Failed to initialize Anthropic client: {e}")

    @property
    def available(self) -> bool:
        """Whether the LLM client is ready to make API calls."""
        return self._client is not None

    # ------------------------------------------------------------------
    # Core completion methods
    # ------------------------------------------------------------------

    def complete(
        self,
        messages: List[Dict[str, str]],
        system: str = "",
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> Optional[str]:
        """
        Send a completion request.

        Returns the text response, or None if the client is unavailable
        or the call fails.
        """
        if not self.available:
            return None

        try:
            response = self._client.messages.create(
                model=model or self.coordinator_model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=messages,
            )
            return response.content[0].text
        except Exception as e:
            self.logger.error(f"LLM completion failed: {e}")
            return None

    def complete_json(
        self,
        messages: List[Dict[str, str]],
        system: str = "",
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> Optional[Dict[str, Any]]:
        """
        Send a completion request expecting a JSON response.

        Parses the response text as JSON with fallback extraction.
        Returns None on failure.
        """
        text = self.complete(messages, system, model, temperature, max_tokens)
        if text is None:
            return None
        return self._parse_json(text)

    # ------------------------------------------------------------------
    # Tier-specific convenience methods
    # ------------------------------------------------------------------

    def coordinator_complete(self, messages, system="", **kwargs) -> Optional[str]:
        """Completion using the coordinator model (Sonnet)."""
        return self.complete(
            messages, system, model=self.coordinator_model, **kwargs
        )

    def coordinator_json(self, messages, system="", **kwargs) -> Optional[Dict]:
        """JSON completion using the coordinator model."""
        return self.complete_json(
            messages, system, model=self.coordinator_model, **kwargs
        )

    def agent_complete(self, messages, system="", **kwargs) -> Optional[str]:
        """Completion using the agent model (Haiku)."""
        return self.complete(
            messages, system, model=self.agent_model, **kwargs
        )

    def agent_json(self, messages, system="", **kwargs) -> Optional[Dict]:
        """JSON completion using the agent model."""
        return self.complete_json(
            messages, system, model=self.agent_model, **kwargs
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json(text: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from LLM response, handling markdown code fences."""
        text = text.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract the outermost JSON object
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            return None
