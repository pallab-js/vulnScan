"""
HTTP client utilities for WebScanner
"""

import requests
import time
import random
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
                 verify_ssl: bool = True):
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
        """Perform custom request with built-in delay"""
        self._apply_delay()
        return self.session.request(method, url, timeout=self.timeout,
                                  verify=self.verify_ssl, **kwargs)

    def _apply_delay(self):
        """Apply delay between requests"""
        if self.delay > 0:
            time.sleep(self.delay)

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