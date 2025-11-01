"""
Configuration management for WebScanner
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """Configuration manager for WebScanner"""

    DEFAULT_CONFIG = {
        'scanner': {
            'threads': 10,
            'timeout': 30,
            'delay': 0.1,
            'max_retries': 3,
            'user_agent': None,  # Will use random from list
            'verify_ssl': True,
        },
        'checks': {
            'enabled': ['header_checks', 'server_info_checks', 'file_checks', 'misc_checks'],
            'disabled': [],
        },
        'output': {
            'format': 'console',
            'file': None,
            'colors': True,
        },
        'logging': {
            'level': 'WARNING',
            'file': None,
        },
        'network': {
            'proxies': {},
            'headers': {},
        }
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration

        Args:
            config_file: Path to configuration file (JSON format)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_file = config_file

        if config_file and Path(config_file).exists():
            self.load_config(config_file)

    def load_config(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)

            # Deep merge user config with defaults
            self._merge_config(self.config, user_config)

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
            print("Using default configuration.")

    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]):
        """Deep merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value

        Args:
            key: Dot-separated key path (e.g., 'scanner.threads')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any):
        """
        Set configuration value

        Args:
            key: Dot-separated key path
            value: Value to set
        """
        keys = key.split('.')
        config = self.config

        # Navigate to parent dict
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        # Set value
        config[keys[-1]] = value

    def save_config(self, config_file: Optional[str] = None):
        """Save current configuration to file"""
        file_path = config_file or self.config_file
        if not file_path:
            raise ValueError("No config file specified")

        with open(file_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return self.config.copy()


# Global configuration instance
config = Config()

# Try to load from default locations
default_config_files = [
    os.path.expanduser('~/.webscanner/config.json'),
    os.path.join(os.getcwd(), 'webscanner.json'),
    os.path.join(os.getcwd(), '.webscanner.json')
]

for config_file in default_config_files:
    if os.path.exists(config_file):
        config.load_config(config_file)
        break