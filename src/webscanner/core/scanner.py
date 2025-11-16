"""
Core scanner engine for WebScanner
"""

import requests
import time
import threading
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional
import logging
from tqdm import tqdm

from ..utils.http_client import HttpClient
from ..utils.logger import get_logger

logger = get_logger(__name__)


def _is_private_ip(host: str | None) -> bool:
    """Check if hostname resolves to a private IP address"""
    if not host:
        return False
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)

        # Check if private
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except (socket.gaierror, ValueError):
        # If can't resolve, assume not private
        return False


def _validate_url(url: str):
    """Validate URL for security scanning"""
    parsed = urlparse(url)

    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        raise ValueError(f"Invalid scheme '{parsed.scheme}'. Only http and https are supported.")

    if not parsed.netloc:
        raise ValueError(f"Invalid URL: missing netloc in {url}")

    # Check for localhost/127.0.0.1
    host = parsed.hostname or ""
    if host.lower() in ['localhost', '127.0.0.1', '::1']:
        raise ValueError("Scanning localhost is not allowed for security reasons.")

    # Check for private IPs
    if _is_private_ip(host):
        raise ValueError(f"Scanning private IP addresses is not allowed: {host}")

    # Additional checks can be added here


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
                  user_agent: Optional[str] = None, max_retries: int = 3,
                  requests_per_second: float = 0, custom_headers: Optional[Dict[str, str]] = None):
        """Initialize scanner"""
        self.base_url = base_url.rstrip('/')
        self.max_threads = max_threads
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.requests_per_second = requests_per_second
        self.custom_headers = custom_headers

        # Validate URL
        _validate_url(base_url)

        self.http_client = HttpClient(
            timeout=timeout,
            user_agent=user_agent,
            delay=delay,
            max_retries=max_retries,
            requests_per_second=requests_per_second,
            custom_headers=custom_headers
        )

        self.results: List[ScannerResult] = []
        self._stop_event = threading.Event()
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.request_count = 0

        logger.info(f"Initialized scanner for {base_url}")

    def scan(self, checks: List[Any]) -> List[ScannerResult]:
        """Run scan"""
        self.start_time = time.time()
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

            with tqdm(total=len(future_to_check), desc="Scanning", unit="check") as pbar:
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
                    pbar.update(1)

        self.end_time = time.time()
        duration = self.end_time - self.start_time
        request_count = self.http_client.request_count
        logger.info(f"Scan completed. Found {len(self.results)} potential issues in {duration:.2f}s ({request_count} requests)")
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

    def save_results(self, file_path: str):
        """Save scan results to file"""
        import json
        data = {
            'base_url': self.base_url,
            'timestamp': time.time(),
            'results': [result.to_dict() for result in self.results]
        }
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Results saved to {file_path}")

    def load_results(self, file_path: str):
        """Load scan results from file"""
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
        self.base_url = data['base_url']
        self.results = [ScannerResult(**r) for r in data['results']]
        logger.info(f"Results loaded from {file_path}")