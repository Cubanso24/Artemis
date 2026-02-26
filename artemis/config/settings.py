"""
Configuration settings for the Artemis threat hunting system.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any
import json
import os


@dataclass
class ArtemisConfig:
    """
    Central configuration for Artemis.

    Provides configurable settings for all components.
    """

    # Meta-learner settings
    deployment_mode: str = "adaptive"  # adaptive, parallel, sequential
    enable_parallel_execution: bool = True
    max_workers: int = 4

    # Agent settings
    enable_all_agents: bool = True
    baseline_agents: List[str] = field(default_factory=lambda: [
        "c2_hunter",
        "reconnaissance_hunter"
    ])

    # Confidence thresholds
    critical_threshold: float = 0.9
    high_threshold: float = 0.7
    medium_threshold: float = 0.5

    # Logging
    log_level: str = "INFO"
    log_file: str = "artemis.log"

    # Resource allocation
    compute_budget: float = 1.0  # 0.0 to 1.0 (percentage of available resources)

    # Adaptive learning
    enable_adaptive_learning: bool = True
    enable_playbooks: bool = True

    # Context assessment
    historical_state_limit: int = 100
    anomaly_detection_enabled: bool = True

    # Performance
    cache_enabled: bool = True
    cache_ttl_seconds: int = 300

    # LLM layer
    llm_enabled: bool = True  # Set False to disable LLM entirely
    llm_api_key: str = ""  # Defaults to ANTHROPIC_API_KEY env var
    llm_coordinator_model: str = "claude-sonnet-4-5-20250929"
    llm_agent_model: str = "claude-haiku-4-5-20251001"

    # GPU LLM (Ollama) — for local inference on GPU server
    llm_backend: str = "auto"  # "auto", "ollama", "anthropic"
    ollama_url: str = "http://localhost:11434"
    ollama_coordinator_model: str = "qwen2.5:72b"
    ollama_agent_model: str = "qwen2.5:32b"
    ollama_num_gpu: int = -1  # -1 = all layers on GPU
    ollama_context_length: int = 32768

    # Autonomous case generation
    auto_case_enabled: bool = True
    auto_case_threshold: float = 0.60       # min confidence to create any case
    auto_respond_threshold: float = 0.95    # auto-escalate + notify SOC
    auto_investigate_threshold: float = 0.80  # auto-create + recommend actions
    case_dedup_window_hours: int = 1        # group findings within window

    # Hunt scheduler
    scheduler_enabled: bool = True
    scheduler_interval_minutes: int = 15
    scheduler_auto_start: bool = False      # auto-start on server boot
    scheduler_max_concurrent_hunts: int = 1

    # DFIR-IRIS integration
    iris_enabled: bool = False
    iris_url: str = ""                      # e.g., https://iris.company.com
    iris_api_key: str = ""
    iris_sync_interval_minutes: int = 5
    iris_auto_push_cases: bool = True       # auto-push high-confidence cases
    iris_auto_push_threshold: float = 0.80

    @classmethod
    def from_file(cls, filepath: str) -> 'ArtemisConfig':
        """Load configuration from JSON file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Config file not found: {filepath}")

        with open(filepath, 'r') as f:
            config_dict = json.load(f)

        return cls(**config_dict)

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'ArtemisConfig':
        """Create configuration from dictionary."""
        return cls(**config_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "deployment_mode": self.deployment_mode,
            "enable_parallel_execution": self.enable_parallel_execution,
            "max_workers": self.max_workers,
            "enable_all_agents": self.enable_all_agents,
            "baseline_agents": self.baseline_agents,
            "critical_threshold": self.critical_threshold,
            "high_threshold": self.high_threshold,
            "medium_threshold": self.medium_threshold,
            "log_level": self.log_level,
            "log_file": self.log_file,
            "compute_budget": self.compute_budget,
            "enable_adaptive_learning": self.enable_adaptive_learning,
            "enable_playbooks": self.enable_playbooks,
            "historical_state_limit": self.historical_state_limit,
            "anomaly_detection_enabled": self.anomaly_detection_enabled,
            "cache_enabled": self.cache_enabled,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "llm_enabled": self.llm_enabled,
            "llm_api_key": self.llm_api_key,
            "llm_coordinator_model": self.llm_coordinator_model,
            "llm_agent_model": self.llm_agent_model,
            "llm_backend": self.llm_backend,
            "ollama_url": self.ollama_url,
            "ollama_coordinator_model": self.ollama_coordinator_model,
            "ollama_agent_model": self.ollama_agent_model,
            "ollama_num_gpu": self.ollama_num_gpu,
            "ollama_context_length": self.ollama_context_length,
            "auto_case_enabled": self.auto_case_enabled,
            "auto_case_threshold": self.auto_case_threshold,
            "auto_respond_threshold": self.auto_respond_threshold,
            "auto_investigate_threshold": self.auto_investigate_threshold,
            "case_dedup_window_hours": self.case_dedup_window_hours,
            "scheduler_enabled": self.scheduler_enabled,
            "scheduler_interval_minutes": self.scheduler_interval_minutes,
            "scheduler_auto_start": self.scheduler_auto_start,
            "scheduler_max_concurrent_hunts": self.scheduler_max_concurrent_hunts,
            "iris_enabled": self.iris_enabled,
            "iris_url": self.iris_url,
            "iris_api_key": self.iris_api_key,
            "iris_sync_interval_minutes": self.iris_sync_interval_minutes,
            "iris_auto_push_cases": self.iris_auto_push_cases,
            "iris_auto_push_threshold": self.iris_auto_push_threshold,
        }

    def save(self, filepath: str):
        """Save configuration to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def validate(self) -> bool:
        """Validate configuration settings."""
        if self.deployment_mode not in ["adaptive", "parallel", "sequential"]:
            return False

        if not 0.0 <= self.compute_budget <= 1.0:
            return False

        if not 0.0 <= self.critical_threshold <= 1.0:
            return False

        return True
