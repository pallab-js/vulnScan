"""
Reporting modules for different output formats
"""

from typing import Type
from .base import BaseReporter
from .console import ConsoleReporter
from .json_reporter import JSONReporter
from .xml_reporter import XMLReporter
from .csv_reporter import CSVReporter


def get_reporter(format_name: str) -> BaseReporter:
    """Get reporter instance for specified format"""
    reporters = {
        'console': ConsoleReporter,
        'json': JSONReporter,
        'xml': XMLReporter,
        'csv': CSVReporter
    }

    reporter_class = reporters.get(format_name.lower())
    if not reporter_class:
        raise ValueError(f"Unknown output format: {format_name}")

    return reporter_class()