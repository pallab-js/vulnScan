"""
Vulnerability checks for WebScanner
"""

from typing import Dict, Type
from .base import BaseCheck
from .header_checks import HeaderChecks
from .server_info_checks import ServerInfoChecks
from .file_checks import FileChecks
from .misc_checks import MiscChecks
from ..plugins import plugin_manager


def get_all_checks() -> Dict[str, Type[BaseCheck]]:
    """Get all available check classes (built-in + plugins)"""
    # Start with built-in checks
    checks = {
        'header_checks': HeaderChecks,
        'server_info_checks': ServerInfoChecks,
        'file_checks': FileChecks,
        'misc_checks': MiscChecks,
    }

    # Add plugin checks
    plugin_checks = plugin_manager.get_plugin_checks()
    checks.update(plugin_checks)

    return checks