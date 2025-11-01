"""
Security header checks
"""

import logging
from typing import List

from .base import BaseCheck
from ..core.scanner import ScannerResult

logger = logging.getLogger(__name__)


class HeaderChecks(BaseCheck):
    """Check for security headers and their configurations"""

    # Security headers to check for
    SECURITY_HEADERS = {
        'X-Frame-Options': {
            'required': True,
            'description': 'Prevents clickjacking attacks',
            'recommendation': 'Set to DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'required': True,
            'description': 'Prevents MIME type sniffing',
            'recommendation': 'Set to nosniff'
        },
        'X-XSS-Protection': {
            'required': False,
            'description': 'Enables XSS filtering in browsers',
            'recommendation': 'Set to 1; mode=block'
        },
        'Strict-Transport-Security': {
            'required': True,
            'description': 'Enforces HTTPS connections',
            'recommendation': 'Set with appropriate max-age'
        },
        'Content-Security-Policy': {
            'required': False,
            'description': 'Prevents XSS and other injection attacks',
            'recommendation': 'Implement appropriate CSP policy'
        },
        'Referrer-Policy': {
            'required': False,
            'description': 'Controls referrer information sent in requests',
            'recommendation': 'Set to strict-origin-when-cross-origin or similar'
        },
        'Permissions-Policy': {
            'required': False,
            'description': 'Controls browser features and APIs',
            'recommendation': 'Restrict unnecessary permissions'
        }
    }

    def run(self) -> List[ScannerResult]:
        """Run header security checks"""
        logger.info("Running header security checks")

        # Test root path
        self._check_headers(self.base_url)

        # Test common paths that might have different headers
        common_paths = ['/admin', '/login', '/api', '/static']
        for path in common_paths:
            url = self.http_client.build_url(self.base_url, path)
            self._check_headers(url)

        return self.results

    def _check_headers(self, url: str):
        """Check security headers for a specific URL"""
        response = self.make_request('GET', url)
        if not response:
            return

        headers = response.headers

        # Check for missing security headers
        for header, config in self.SECURITY_HEADERS.items():
            if config['required'] and header.lower() not in [h.lower() for h in headers.keys()]:
                self.add_result(
                    url=url,
                    check_name='missing_security_header',
                    severity='medium',
                    description=f"Missing security header: {header}",
                    evidence=f"Header not present in response",
                    recommendation=config['recommendation']
                )

        # Check specific header values
        self._check_x_frame_options(url, headers)
        self._check_hsts(url, headers)
        self._check_csp(url, headers)
        self._check_server_header(url, headers)

    def _check_x_frame_options(self, url: str, headers):
        """Check X-Frame-Options header"""
        header_name = 'X-Frame-Options'
        if header_name in headers:
            value = headers[header_name].upper()
            if value not in ['DENY', 'SAMEORIGIN']:
                self.add_result(
                    url=url,
                    check_name='weak_x_frame_options',
                    severity='low',
                    description=f"Weak X-Frame-Options value: {value}",
                    evidence=f"X-Frame-Options: {headers[header_name]}",
                    recommendation="Set to 'DENY' or 'SAMEORIGIN'"
                )

    def _check_hsts(self, url: str, headers):
        """Check Strict-Transport-Security header"""
        header_name = 'Strict-Transport-Security'
        if header_name in headers:
            value = headers[header_name]
            if 'max-age=' not in value:
                self.add_result(
                    url=url,
                    check_name='weak_hsts',
                    severity='medium',
                    description="HSTS header missing max-age directive",
                    evidence=f"Strict-Transport-Security: {value}",
                    recommendation="Include max-age directive (e.g., max-age=31536000)"
                )
            elif 'max-age=0' in value:
                self.add_result(
                    url=url,
                    check_name='hsts_disabled',
                    severity='high',
                    description="HSTS is disabled (max-age=0)",
                    evidence=f"Strict-Transport-Security: {value}",
                    recommendation="Remove max-age=0 or set appropriate max-age value"
                )

    def _check_csp(self, url: str, headers):
        """Check Content-Security-Policy header"""
        header_name = 'Content-Security-Policy'
        if header_name in headers:
            value = headers[header_name]
            # Check for overly permissive policies
            if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                self.add_result(
                    url=url,
                    check_name='permissive_csp',
                    severity='medium',
                    description="CSP contains unsafe directives",
                    evidence=f"Content-Security-Policy: {value}",
                    recommendation="Remove 'unsafe-inline' and 'unsafe-eval' from CSP"
                )

    def _check_server_header(self, url: str, headers):
        """Check Server header for information disclosure"""
        if 'Server' in headers:
            server_info = headers['Server']
            # Flag detailed server information
            if any(word in server_info.lower() for word in ['apache', 'nginx', 'iis', 'tomcat']):
                if '/' in server_info or any(char in server_info for char in ['(', ')', '[', ']']):
                    self.add_result(
                        url=url,
                        check_name='server_info_disclosure',
                        severity='low',
                        description=f"Server header reveals detailed version information: {server_info}",
                        evidence=f"Server: {server_info}",
                        recommendation="Configure server to hide version details in Server header"
                    )