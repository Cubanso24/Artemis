"""
LLM client abstraction for the Artemis threat hunting system.

Supports two backends:
- **anthropic**: Uses the Anthropic API (requires ANTHROPIC_API_KEY)
- **ollama**: Uses a locally-hosted Ollama instance (no API key needed)

Both backends support:
- Graceful degradation when the backend is unavailable
- Separate model configs for coordinator and agent tiers
- JSON response parsing with fallback extraction
- Error handling that never breaks the hunting pipeline
"""

import os
import json
from typing import Optional, Dict, Any, List

import requests as _requests

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from artemis.utils.logging_config import ArtemisLogger


# Default Ollama models — good general-purpose choices
_DEFAULT_OLLAMA_MODEL = "llama3.1"
_DEFAULT_OLLAMA_URL = "http://localhost:11434"
_DEFAULT_OLLAMA_NUM_CTX = 262144  # 256k context (requires >= 48 GiB VRAM)


class LLMClient:
    """
    Two-tier LLM client for Artemis.

    Supports both Anthropic (cloud) and Ollama (local) backends.

    - coordinator model: high-level reasoning, hypothesis generation,
      agent direction, result synthesis
    - agent model: fast domain-specific analysis for each hunting agent
    """

    def __init__(
        self,
        backend: str = "auto",
        api_key: Optional[str] = None,
        coordinator_model: Optional[str] = None,
        agent_model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        ollama_num_ctx: Optional[int] = None,
        priority: str = "hunt",
    ):
        """
        Initialize the LLM client.

        Args:
            backend: "anthropic", "ollama", or "auto" (tries anthropic first,
                     then ollama)
            api_key: Anthropic API key (only for anthropic backend)
            coordinator_model: Model for coordinator tier
            agent_model: Model for agent tier
            ollama_url: Ollama server URL (default http://localhost:11434)
            ollama_num_ctx: Context window size for Ollama (default 131072)
            priority: "hunt" (default, high priority) or "chat" (low,
                      yields to active hunts).  Only meaningful for the
                      Ollama backend where a single model serves one
                      request at a time.
        """
        self.logger = ArtemisLogger.setup_logger("artemis.llm.client")
        self.backend = backend.lower()
        self.priority = priority
        self.ollama_url = (
            ollama_url
            or os.getenv("OLLAMA_URL", _DEFAULT_OLLAMA_URL)
        ).rstrip("/")

        self._anthropic_client: Optional[Any] = None
        self._ollama_ok = False
        self.ollama_num_ctx = (
            ollama_num_ctx
            or int(os.getenv("OLLAMA_NUM_CTX", str(_DEFAULT_OLLAMA_NUM_CTX)))
        )

        # ----------------------------------------------------------
        # Resolve backend
        # ----------------------------------------------------------
        if self.backend == "auto":
            # Try Anthropic first, fall back to Ollama
            api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if ANTHROPIC_AVAILABLE and api_key:
                self.backend = "anthropic"
            else:
                self.backend = "ollama"

        # ----------------------------------------------------------
        # Initialize chosen backend
        # ----------------------------------------------------------
        if self.backend == "anthropic":
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            self.coordinator_model = coordinator_model or "claude-sonnet-4-5-20250929"
            self.agent_model = agent_model or "claude-haiku-4-5-20251001"

            if not ANTHROPIC_AVAILABLE:
                self.logger.warning(
                    "anthropic package not installed — LLM features disabled. "
                    "Install with: pip install anthropic"
                )
            elif not self.api_key:
                self.logger.warning(
                    "ANTHROPIC_API_KEY not set — LLM features disabled. "
                    "Set the environment variable or switch to ollama backend."
                )
            else:
                try:
                    self._anthropic_client = Anthropic(api_key=self.api_key)
                    self.logger.info(
                        f"LLM client initialized [anthropic] "
                        f"(coordinator={self.coordinator_model}, "
                        f"agent={self.agent_model})"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to initialize Anthropic client: {e}"
                    )

        elif self.backend == "ollama":
            ollama_model = (
                os.getenv("OLLAMA_MODEL", _DEFAULT_OLLAMA_MODEL)
            )
            self.coordinator_model = coordinator_model or ollama_model
            self.agent_model = agent_model or ollama_model
            self._ollama_ok = self._check_ollama()

        else:
            self.logger.warning(
                f"Unknown LLM backend '{self.backend}' — "
                f"LLM features disabled. Use 'anthropic' or 'ollama'."
            )

    # ------------------------------------------------------------------
    # Ollama health check
    # ------------------------------------------------------------------

    def _check_ollama(self) -> bool:
        """Verify that Ollama is reachable and the model is available."""
        try:
            resp = _requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                self.logger.warning(
                    f"Ollama server at {self.ollama_url} returned "
                    f"status {resp.status_code} — LLM features disabled. "
                    f"Make sure Ollama is running: ollama serve"
                )
                return False

            models = [
                m.get("name", "").split(":")[0]
                for m in resp.json().get("models", [])
            ]
            # Also keep full name:tag for exact match
            models_full = [m.get("name", "") for m in resp.json().get("models", [])]

            for model_name in set([self.coordinator_model, self.agent_model]):
                if (model_name not in models
                        and model_name not in models_full):
                    self.logger.warning(
                        f"Ollama model '{model_name}' not found locally. "
                        f"Pull it with: ollama pull {model_name}\n"
                        f"Available models: {', '.join(models_full) or '(none)'}"
                    )
                    return False

            self.logger.info(
                f"LLM client initialized [ollama @ {self.ollama_url}] "
                f"(coordinator={self.coordinator_model}, "
                f"agent={self.agent_model}, "
                f"num_ctx={self.ollama_num_ctx})"
            )
            return True

        except _requests.ConnectionError:
            self.logger.warning(
                f"Cannot connect to Ollama at {self.ollama_url} — "
                f"LLM features disabled. Start Ollama with: ollama serve"
            )
            return False
        except Exception as e:
            self.logger.warning(f"Ollama health check failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """Whether the LLM client is ready to make API calls."""
        if self.backend == "anthropic":
            return self._anthropic_client is not None
        if self.backend == "ollama":
            return self._ollama_ok
        return False

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

        if self.backend == "anthropic":
            return self._complete_anthropic(
                messages, system, model, temperature, max_tokens
            )
        if self.backend == "ollama":
            return self._complete_ollama(
                messages, system, model, temperature, max_tokens
            )
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
        # For Ollama, append a JSON instruction to the system prompt
        if self.backend == "ollama" and system:
            system = (
                system + "\n\nIMPORTANT: You MUST respond with valid JSON only. "
                "No markdown fences, no explanatory text — just the JSON object."
            )

        text = self.complete(messages, system, model, temperature, max_tokens)
        if text is None:
            return None
        return self._parse_json(text)

    # ------------------------------------------------------------------
    # Tier-specific convenience methods
    # ------------------------------------------------------------------

    def coordinator_complete(self, messages, system="", **kwargs) -> Optional[str]:
        """Completion using the coordinator model."""
        return self.complete(
            messages, system, model=self.coordinator_model, **kwargs
        )

    def coordinator_json(self, messages, system="", **kwargs) -> Optional[Dict]:
        """JSON completion using the coordinator model."""
        return self.complete_json(
            messages, system, model=self.coordinator_model, **kwargs
        )

    def agent_complete(self, messages, system="", **kwargs) -> Optional[str]:
        """Completion using the agent model."""
        return self.complete(
            messages, system, model=self.agent_model, **kwargs
        )

    def agent_json(self, messages, system="", **kwargs) -> Optional[Dict]:
        """JSON completion using the agent model."""
        return self.complete_json(
            messages, system, model=self.agent_model, **kwargs
        )

    # ------------------------------------------------------------------
    # Backend: Anthropic
    # ------------------------------------------------------------------

    def _complete_anthropic(
        self, messages, system, model, temperature, max_tokens,
    ) -> Optional[str]:
        try:
            response = self._anthropic_client.messages.create(
                model=model or self.coordinator_model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=messages,
            )
            return response.content[0].text
        except Exception as e:
            self.logger.error(f"Anthropic completion failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Backend: Ollama
    # ------------------------------------------------------------------

    def _complete_ollama(
        self, messages, system, model, temperature, max_tokens,
    ) -> Optional[str]:
        """Call the Ollama /api/chat endpoint.

        Wraps the HTTP call in a priority lock so hunt operations are
        never blocked by lower-priority analyst chat queries.
        """
        from artemis.llm.priority import (
            llm_priority_hunt,
            llm_priority_chat,
            LLMBusyError,
        )

        ollama_messages = []
        if system:
            ollama_messages.append({"role": "system", "content": system})
        for m in messages:
            ollama_messages.append({
                "role": m.get("role", "user"),
                "content": m.get("content", ""),
            })

        payload = {
            "model": model or self.coordinator_model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": self.ollama_num_ctx,
            },
        }

        ctx = (
            llm_priority_hunt()
            if self.priority == "hunt"
            else llm_priority_chat()
        )

        try:
            with ctx:
                resp = _requests.post(
                    f"{self.ollama_url}/api/chat",
                    json=payload,
                    timeout=300,  # 5 min — long enough for big prompts, short enough to detect freezes
                )
        except LLMBusyError:
            self.logger.warning("LLM busy with hunt operations — chat deferred")
            raise
        except _requests.Timeout:
            self.logger.error("Ollama request timed out (300s)")
            return None
        except _requests.ConnectionError:
            self.logger.error(
                f"Lost connection to Ollama at {self.ollama_url}"
            )
            self._ollama_ok = False
            return None
        except Exception as e:
            self.logger.error(f"Ollama completion failed: {e}")
            return None

        if resp.status_code != 200:
            self.logger.error(
                f"Ollama returned status {resp.status_code}: "
                f"{resp.text[:200]}"
            )
            return None

        data = resp.json()
        content = data.get("message", {}).get("content", "")
        if not content:
            self.logger.warning("Ollama returned empty response")
            return None
        return content

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
