"""
Base reporter class
"""

from abc import ABC, abstractmethod
from typing import List
from ..core.scanner import ScannerResult


class BaseReporter(ABC):
    """Base class for all reporters"""

    @abstractmethod
    def generate(self, results: List[ScannerResult], target_url: str) -> str:
        """
        Generate report from scan results

        Args:
            results: List of scan results
            target_url: Target URL that was scanned

        Returns:
            Formatted report as string
        """
        pass