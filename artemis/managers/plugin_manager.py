"""Plugin manager for Artemis."""

import logging
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger("artemis.plugins")


class PluginManager:
    """Manages Artemis plugins/modules."""

    def __init__(self):
        self.plugins = {}
        self.plugin_dir = Path("artemis/plugins")
        self.plugin_dir.mkdir(exist_ok=True)

    def register_plugin(self, name: str, plugin_class):
        """Register a plugin."""
        self.plugins[name] = {
            'class': plugin_class,
            'instance': None,
            'enabled': False
        }
        logger.info(f"Registered plugin: {name}")

    def enable_plugin(self, name: str, config: Dict = None):
        """Enable and initialize a plugin."""
        if name not in self.plugins:
            raise ValueError(f"Plugin not found: {name}")

        if self.plugins[name]['instance'] is None:
            self.plugins[name]['instance'] = self.plugins[name]['class'](config or {})
            if hasattr(self.plugins[name]['instance'], 'initialize'):
                self.plugins[name]['instance'].initialize()

        self.plugins[name]['enabled'] = True
        logger.info(f"Enabled plugin: {name}")

    def disable_plugin(self, name: str):
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name]['enabled'] = False
            logger.info(f"Disabled plugin: {name}")

    def get_plugin(self, name: str):
        """Get plugin instance."""
        if name in self.plugins and self.plugins[name]['enabled']:
            return self.plugins[name]['instance']
        return None

    def list_plugins(self) -> List[Dict]:
        """List all registered plugins."""
        result = []
        for name, info in self.plugins.items():
            plugin_info = {
                'name': name,
                'enabled': info['enabled'],
                'description': getattr(info['class'], 'DESCRIPTION', 'No description'),
            }
            instance = info['instance']
            if instance and hasattr(instance, 'rules'):
                plugin_info['rules_loaded'] = len(instance.rules)
            result.append(plugin_info)
        return result

    def reload_from_disk(self, plugin_names):
        """Re-initialize plugin instances so they load results written by a
        hunt subprocess (network map on disk, sigma results, etc.)."""
        for name in plugin_names:
            plugin = self.get_plugin(name)
            if plugin and hasattr(plugin, 'initialize'):
                try:
                    plugin.initialize()
                    logger.info(f'Reloaded plugin "{name}" from disk')
                except Exception as e:
                    logger.warning(f'Failed to reload plugin "{name}": {e}')
