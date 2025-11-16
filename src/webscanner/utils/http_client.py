"""
HTTP client utilities for WebScanner
"""

import requests
import time
import random
import threading
from typing import Optional, Dict, Any, Tuple
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class HttpClient:
    """Enhanced HTTP client with built-in features for security scanning"""

    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]

    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None,
                  delay: float = 0.1, proxies: Optional[Dict[str, str]] = None,
                  verify_ssl: bool = True, max_retries: int = 3,
                  requests_per_second: float = 0, custom_headers: Optional[Dict[str, str]] = None):
        """
        Initialize HTTP client

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent (random if None)
            delay: Delay between requests
            proxies: Proxy configuration
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.delay = delay
        self.proxies = proxies
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.requests_per_second = requests_per_second
        self.custom_headers = custom_headers or {}
        self._last_request_time = 0.0
        self._rate_lock = threading.Lock()
        self.request_count = 0
        self._count_lock = threading.Lock()
        self.rotate_after = 10  # Rotate user agent every N requests

        self.user_agent = user_agent or random.choice(self.DEFAULT_USER_AGENTS)
        self.session = requests.Session()

        # Configure session
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Add custom headers
        self.session.headers.update(self.custom_headers)

        if proxies:
            self.session.proxies.update(proxies)

        logger.info(f"HTTP client initialized with timeout={timeout}s, delay={delay}s")

    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform GET request with built-in delay"""
        self._apply_delay()
        return self.session.get(url, timeout=self.timeout,
                              verify=self.verify_ssl, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """Perform HEAD request with built-in delay"""
        self._apply_delay()
        return self.session.head(url, timeout=self.timeout,
                               verify=self.verify_ssl, **kwargs)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> requests.Response:
        """Perform POST request with built-in delay"""
        self._apply_delay()
        return self.session.post(url, data=data, timeout=self.timeout,
                               verify=self.verify_ssl, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Perform custom request with built-in delay and retry logic"""
        self._apply_delay()
        self._apply_rate_limit()

        with self._count_lock:
            self.request_count += 1
            if self.request_count % self.rotate_after == 0:
                self.rotate_user_agent()

        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                return self.session.request(method, url, timeout=self.timeout,
                                           verify=self.verify_ssl, **kwargs)
            except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                last_exception = e
                if attempt < self.max_retries:
                    # Exponential backoff: 1s, 2s, 4s, etc.
                    backoff_time = 2 ** attempt
                    logger.debug(f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}), retrying in {backoff_time}s: {e}")
                    time.sleep(backoff_time)
                else:
                    logger.debug(f"Request failed after {self.max_retries + 1} attempts: {e}")
                    raise last_exception

    def _apply_delay(self):
        """Apply delay between requests"""
        if self.delay > 0:
            time.sleep(self.delay)

    def _apply_rate_limit(self):
        """Apply rate limiting"""
        if self.requests_per_second > 0:
            with self._rate_lock:
                current_time = time.time()
                min_interval = 1.0 / self.requests_per_second
                time_since_last = current_time - self._last_request_time
                if time_since_last < min_interval:
                    sleep_time = min_interval - time_since_last
                    time.sleep(sleep_time)
                self._last_request_time = time.time()

    def rotate_user_agent(self):
        """Rotate to a different user agent"""
        self.user_agent = random.choice(self.DEFAULT_USER_AGENTS)
        self.session.headers['User-Agent'] = self.user_agent
        logger.debug(f"Rotated user agent to: {self.user_agent}")

    def build_url(self, base_url: str, path: str) -> str:
        """Build full URL from base URL and path"""
        if path.startswith('/'):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        else:
            return urljoin(base_url + '/', path)

    def test_connection(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Test connection to target URL

        Returns:
            Tuple of (success, error_message)
        """
        try:
            response = self.get(url)
            return True, None
        except requests.exceptions.RequestException as e:
            return False, str(e)
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"