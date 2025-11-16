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
        "reconnaissance_hunter",
        "defense_evasion_hunter"
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
            "cache_ttl_seconds": self.cache_ttl_seconds
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
