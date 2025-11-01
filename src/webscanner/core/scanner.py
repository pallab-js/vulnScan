"""
Core scanner engine for WebScanner
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional
import logging

from ..utils.http_client import HttpClient
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ScannerResult:
    """Represents a single scan result"""

    def __init__(self, url: str, check_name: str, severity: str,
                 description: str, evidence: str = "", recommendation: str = ""):
        self.url = url
        self.check_name = check_name
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'check_name': self.check_name,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'timestamp': self.timestamp
        }


class WebScanner:
    """Main web vulnerability scanner class"""

    def __init__(self, base_url: str, max_threads: int = 10,
                 timeout: int = 30, delay: float = 0.1,
                 user_agent: Optional[str] = None):
        """
        Initialize the web scanner

        Args:
            base_url: Target URL to scan
            max_threads: Maximum concurrent threads
            timeout: Request timeout in seconds
            delay: Delay between requests
            user_agent: Custom user agent string
        """
        self.base_url = base_url.rstrip('/')
        self.max_threads = max_threads
        self.timeout = timeout
        self.delay = delay

        # Validate URL
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {base_url}")

        self.http_client = HttpClient(
            timeout=timeout,
            user_agent=user_agent,
            delay=delay
        )

        self.results: List[ScannerResult] = []
        self._stop_event = threading.Event()

        logger.info(f"Initialized scanner for {base_url}")

    def scan(self, checks: List[Any]) -> List[ScannerResult]:
        """
        Perform vulnerability scan using provided checks

        Args:
            checks: List of check classes to run

        Returns:
            List of scan results
        """
        logger.info(f"Starting scan with {len(checks)} checks")

        # Initialize check instances
        check_instances = []
        for check_class in checks:
            try:
                check_instance = check_class(self.http_client, self.base_url)
                check_instances.append(check_instance)
            except Exception as e:
                logger.error(f"Failed to initialize check {check_class.__name__}: {e}")

        # Run checks in parallel
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_check = {
                executor.submit(self._run_check, check): check
                for check in check_instances
            }

            for future in as_completed(future_to_check):
                if self._stop_event.is_set():
                    break

                check = future_to_check[future]
                try:
                    results = future.result()
                    self.results.extend(results)
                    logger.debug(f"Check {check.__class__.__name__} completed with {len(results)} findings")
                except Exception as e:
                    logger.error(f"Check {check.__class__.__name__} failed: {e}")

        logger.info(f"Scan completed. Found {len(self.results)} potential issues")
        return self.results

    def _run_check(self, check) -> List[ScannerResult]:
        """Run a single check and return results"""
        try:
            return check.run()
        except Exception as e:
            logger.error(f"Check {check.__class__.__name__} failed: {e}")
            return []

    def stop(self):
        """Stop the scanning process"""
        self._stop_event.set()
        logger.info("Scan stop requested")