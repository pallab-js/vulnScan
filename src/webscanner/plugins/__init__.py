"""
Plugin system for WebScanner
"""

import importlib
import os
import sys
from typing import List, Type, Dict, Optional
from pathlib import Path

from ..checks.base import BaseCheck
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PluginManager:
    """Plugin manager for loading custom checks"""

    def __init__(self):
        self.plugins: Dict[str, Type[BaseCheck]] = {}
        self.plugin_dirs: List[str] = []

    def add_plugin_dir(self, directory: str):
        """Add directory to plugin search paths"""
        if directory not in self.plugin_dirs:
            self.plugin_dirs.append(directory)

    def load_plugins(self):
        """Load all plugins from configured directories"""
        for plugin_dir in self.plugin_dirs:
            self._load_plugins_from_dir(plugin_dir)

    def _load_plugins_from_dir(self, directory: str):
        """Load plugins from a specific directory"""
        if not os.path.exists(directory):
            return

        # Add to Python path if not already there
        if directory not in sys.path:
            sys.path.insert(0, directory)

        # Find Python files in directory
        for file_path in Path(directory).glob('*.py'):
            if file_path.name.startswith('_'):
                continue

            module_name = file_path.stem
            try:
                module = importlib.import_module(module_name)
                self._register_plugin_checks(module)
            except ImportError as e:
                logger.warning(f"Could not load plugin {module_name}: {e}")

    def _register_plugin_checks(self, module):
        """Register check classes from a plugin module"""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)

            # Check if it's a check class
            if (isinstance(attr, type) and
                issubclass(attr, BaseCheck) and
                attr != BaseCheck):

                check_name = getattr(attr, 'PLUGIN_NAME', None)
                if not check_name:
                    check_name = attr.__name__.lower()

                self.plugins[check_name] = attr
                logger.info(f"Loaded plugin check: {check_name}")

    def get_plugin_checks(self) -> Dict[str, Type[BaseCheck]]:
        """Get all loaded plugin checks"""
        return self.plugins.copy()

    def get_plugin_check(self, name: str) -> Optional[Type[BaseCheck]]:
        """Get a specific plugin check by name"""
        return self.plugins.get(name)


# Global plugin manager instance
plugin_manager = PluginManager()

# Add default plugin directories
plugin_manager.add_plugin_dir(os.path.expanduser('~/.webscanner/plugins'))
plugin_manager.add_plugin_dir(os.path.join(os.getcwd(), 'plugins'))

# Load plugins
plugin_manager.load_plugins()