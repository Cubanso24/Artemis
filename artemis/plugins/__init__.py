"""
Artemis Plugin System

Plugins extend Artemis functionality without requiring restarts.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class ArtemisPlugin(ABC):
    """Base class for all Artemis plugins."""

    DESCRIPTION = "Base plugin"

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize plugin with configuration.

        Args:
            config: Plugin-specific configuration dictionary
        """
        self.config = config
        self.enabled = False

    @abstractmethod
    def initialize(self):
        """
        Initialize plugin resources.
        Called when plugin is enabled.
        """
        pass

    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute plugin functionality.

        Args:
            **kwargs: Context-specific parameters

        Returns:
            Dict with results
        """
        pass

    @abstractmethod
    def cleanup(self):
        """
        Clean up plugin resources.
        Called when plugin is disabled.
        """
        pass

    def get_status(self) -> Dict[str, Any]:
        """Get current plugin status."""
        return {
            'name': self.__class__.__name__,
            'enabled': self.enabled,
            'description': self.DESCRIPTION
        }
