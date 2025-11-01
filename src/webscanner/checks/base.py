"""
Base check class for all vulnerability checks
"""

from abc import ABC, abstractmethod
from typing import List
import logging

from ..core.scanner import ScannerResult
from ..utils.http_client import HttpClient

logger = logging.getLogger(__name__)


class BaseCheck(ABC):
    """Base class for all vulnerability checks"""

    def __init__(self, http_client: HttpClient, base_url: str):
        """
        Initialize check

        Args:
            http_client: HTTP client instance
            base_url: Target base URL
        """
        self.http_client = http_client
        self.base_url = base_url
        self.results: List[ScannerResult] = []

    @abstractmethod
    def run(self) -> List[ScannerResult]:
        """
        Run the vulnerability check

        Returns:
            List of scan results
        """
        pass

    def add_result(self, url: str, check_name: str, severity: str,
                   description: str, evidence: str = "", recommendation: str = ""):
        """
        Add a scan result

        Args:
            url: URL where issue was found
            check_name: Name of the check
            severity: Severity level (info, low, medium, high, critical)
            description: Description of the finding
            evidence: Evidence supporting the finding
            recommendation: Recommended remediation
        """
        result = ScannerResult(url, check_name, severity, description, evidence, recommendation)
        self.results.append(result)
        logger.debug(f"Added result: {check_name} - {severity} - {description}")

    def make_request(self, method: str, url: str, **kwargs):
        """
        Make HTTP request with error handling

        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional request parameters

        Returns:
            Response object or None if failed
        """
        try:
            return self.http_client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug(f"Request failed: {method} {url} - {e}")
            return None