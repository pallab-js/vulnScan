"""
Miscellaneous security checks
"""

import logging
from typing import List

from .base import BaseCheck
from ..core.scanner import ScannerResult

logger = logging.getLogger(__name__)


class MiscChecks(BaseCheck):
    """Miscellaneous security checks"""

    def run(self) -> List[ScannerResult]:
        """Run miscellaneous security checks"""
        logger.info("Running miscellaneous security checks")

        # Check for HTTP methods
        self._check_http_methods()

        # Check for default pages
        self._check_default_pages()

        # Check for SSL/TLS issues
        self._check_ssl_config()

        # Check for cookie security
        self._check_cookie_security()

        return self.results

    def _check_http_methods(self):
        """Check allowed HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']

        for method in dangerous_methods:
            try:
                response = self.http_client.request(method, self.base_url)
                if response and response.status_code not in [405, 501]:  # Method Not Allowed or Not Implemented
                    self.add_result(
                        self.base_url,
                        'dangerous_method_allowed',
                        'medium',
                        f"Dangerous HTTP method allowed: {method}",
                        f"Method: {method}\nStatus: {response.status_code}",
                        f"Disable {method} method in web server configuration if not required"
                    )
            except Exception:
                # Method not supported by requests library or other error
                continue

        # Check for TRACE method specifically (potential XSS via HTTP response splitting)
        try:
            response = self.http_client.request('TRACE', self.base_url)
            if response and response.status_code == 200:
                self.add_result(
                    self.base_url,
                    'trace_method_enabled',
                    'high',
                    "TRACE method enabled - potential for XSS attacks",
                    "TRACE method allows attackers to steal cookies and other headers",
                    "Disable TRACE method in web server configuration"
                )
        except Exception:
            pass

    def _check_default_pages(self):
        """Check for default or test pages"""
        default_pages = [
            '/default.aspx', '/default.asp', '/index.asp', '/index.aspx',
            '/test.php', '/test.asp', '/test.aspx', '/test.html',
            '/phpinfo.php', '/server-status', '/server-info',
            '/welcome.php', '/hello.php', '/example.php'
        ]

        for page in default_pages:
            url = self.http_client.build_url(self.base_url, page)
            response = self.make_request('GET', url)

            if response and response.status_code == 200:
                content = response.text.lower()

                # Check if it's actually a default/test page
                default_indicators = [
                    'welcome', 'test page', 'default page', 'phpinfo',
                    'server status', 'apache', 'nginx', 'iis',
                    'test script', 'example page'
                ]

                if any(indicator in content for indicator in default_indicators):
                    self.add_result(
                        url,
                        'default_page_exposed',
                        'low',
                        f"Default or test page exposed: {page}",
                        f"Status: {response.status_code}\nContent contains: {' | '.join(default_indicators)}",
                        f"Remove or replace default page {page}"
                    )

    def _check_ssl_config(self):
        """Check SSL/TLS configuration"""
        if self.base_url.startswith('https://'):
            # Check for SSL stripping vulnerability (redirect from HTTPS to HTTP)
            http_url = self.base_url.replace('https://', 'http://')
            try:
                response = self.http_client.request('GET', http_url, allow_redirects=False)
                if response and response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    if location.startswith('http://'):
                        self.add_result(
                            self.base_url,
                            'ssl_stripping_vulnerable',
                            'high',
                            "Potential SSL stripping vulnerability",
                            f"HTTP URL redirects to: {location}",
                            "Ensure all HTTP requests redirect to HTTPS permanently"
                        )
            except Exception:
                pass

    def _check_cookie_security(self):
        """Check cookie security attributes"""
        response = self.make_request('GET', self.base_url)
        if not response:
            return

        cookies = response.cookies

        for cookie in cookies:
            issues = []

            # Check for missing Secure flag on HTTPS
            if self.base_url.startswith('https://') and not cookie.secure:
                issues.append("Missing Secure flag")

            # Check for missing HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly') and not hasattr(cookie, '_rest') or 'HttpOnly' not in str(cookie._rest):
                issues.append("Missing HttpOnly flag")

            # Check for missing SameSite attribute
            if not cookie.has_nonstandard_attr('SameSite') and not hasattr(cookie, '_rest') or 'SameSite' not in str(cookie._rest):
                issues.append("Missing SameSite attribute")

            if issues:
                self.add_result(
                    self.base_url,
                    'insecure_cookie',
                    'medium',
                    f"Insecure cookie: {cookie.name}",
                    f"Issues: {', '.join(issues)}\nCookie: {cookie.name}={cookie.value}",
                    "Set Secure, HttpOnly, and SameSite attributes on cookies"
                )