"""
Server information and version detection checks
"""

import re
import logging
from typing import List, Dict, Any

from .base import BaseCheck
from ..core.scanner import ScannerResult

logger = logging.getLogger(__name__)


class ServerInfoChecks(BaseCheck):
    """Check server information and detect versions"""

    # Known server signatures and their patterns
    SERVER_SIGNATURES = {
        'Apache': {
            'patterns': [r'Apache/([\d.]+)', r'Apache[/ ]?([\d.]+)'],
            'vulnerable_versions': {
                '2.4.49': 'Path traversal vulnerability (CVE-2021-41773)',
                '2.4.50': 'Path traversal vulnerability (CVE-2021-42013)',
            }
        },
        'nginx': {
            'patterns': [r'nginx/([\d.]+)', r'nginx[/ ]?([\d.]+)'],
            'vulnerable_versions': {
                '1.20.0': 'Request smuggling vulnerability',
                '1.21.0': 'Request smuggling vulnerability',
            }
        },
        'IIS': {
            'patterns': [r'Microsoft-IIS/([\d.]+)', r'IIS/([\d.]+)'],
            'vulnerable_versions': {}
        },
        'Tomcat': {
            'patterns': [r'Apache-Coyote/([\d.]+)', r'Tomcat/([\d.]+)'],
            'vulnerable_versions': {}
        }
    }

    def run(self) -> List[ScannerResult]:
        """Run server information checks"""
        logger.info("Running server information checks")

        # Check server headers
        self._check_server_headers()

        # Try to detect server via common files
        self._check_server_files()

        # Check for version disclosure in various places
        self._check_version_disclosure()

        return self.results

    def _check_server_headers(self):
        """Check server-related headers"""
        response = self.make_request('GET', self.base_url)
        if not response:
            return

        headers = response.headers

        # Check Server header
        if 'Server' in headers:
            server_header = headers['Server']
            self._analyze_server_header(server_header)

        # Check X-Powered-By header
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            self.add_result(
                self.base_url,
                'powered_by_disclosure',
                'low',
                f"X-Powered-By header reveals technology: {powered_by}",
                f"X-Powered-By: {powered_by}",
                "Remove or obfuscate X-Powered-By header"
            )

        # Check X-AspNet-Version header
        if 'X-AspNet-Version' in headers:
            aspnet_version = headers['X-AspNet-Version']
            self.add_result(
                self.base_url,
                'aspnet_version_disclosure',
                'low',
                f"ASP.NET version disclosed: {aspnet_version}",
                f"X-AspNet-Version: {aspnet_version}",
                "Configure ASP.NET to hide version information"
            )

    def _analyze_server_header(self, server_header: str):
        """Analyze server header for known vulnerabilities"""
        detected_servers = []

        for server_name, config in self.SERVER_SIGNATURES.items():
            for pattern in config['patterns']:
                match = re.search(pattern, server_header, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    detected_servers.append((server_name, version))

                    # Check for known vulnerabilities
                    if version in config['vulnerable_versions']:
                        vuln_desc = config['vulnerable_versions'][version]
                        self.add_result(
                            self.base_url,
                            'vulnerable_server_version',
                            'high',
                            f"Vulnerable {server_name} version detected: {version} - {vuln_desc}",
                            f"Server: {server_header}",
                            f"Upgrade {server_name} to a patched version"
                        )
                    else:
                        self.add_result(
                            self.base_url,
                            'server_version_detected',
                            'info',
                            f"{server_name} version {version} detected",
                            f"Server: {server_header}",
                            ""
                        )
                    break

        if not detected_servers:
            # Unknown server, but still flag the disclosure
            self.add_result(
                self.base_url,
                'server_info_disclosure',
                'low',
                f"Server header reveals information: {server_header}",
                f"Server: {server_header}",
                "Configure server to hide or obfuscate server information"
            )

    def _check_server_files(self):
        """Check for server-specific files that might reveal information"""
        server_files = [
            '/server-status',
            '/server-info',
            '/phpinfo.php',
            '/test.php',
            '/info.php',
            '/wp-config.php',
            '/.env',
            '/.git/config',
            '/.svn/entries',
            '/WEB-INF/web.xml',
            '/META-INF/MANIFEST.MF'
        ]

        for file_path in server_files:
            url = self.http_client.build_url(self.base_url, file_path)
            response = self.make_request('GET', url)

            if response and response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()

                # Skip if it's an image or binary file
                if any(skip_type in content_type for skip_type in ['image/', 'application/octet-stream']):
                    continue

                content_preview = response.text[:200] + "..." if len(response.text) > 200 else response.text

                severity = 'high' if any(critical in file_path.lower() for critical in ['config', 'env', 'web.xml']) else 'medium'

                self.add_result(
                    url,
                    'sensitive_file_exposed',
                    severity,
                    f"Sensitive file exposed: {file_path}",
                    f"Status: {response.status_code}\nContent-Type: {content_type}\nPreview: {content_preview}",
                    f"Remove or protect access to {file_path}"
                )

    def _check_version_disclosure(self):
        """Check for version disclosure in various locations"""
        # Check common version disclosure endpoints
        version_paths = [
            '/version',
            '/api/version',
            '/status',
            '/health',
            '/readme.txt',
            '/changelog.txt',
            '/VERSION',
            '/version.json'
        ]

        for path in version_paths:
            url = self.http_client.build_url(self.base_url, path)
            response = self.make_request('GET', url)

            if response and response.status_code == 200:
                content = response.text.lower()

                # Look for version patterns
                version_patterns = [
                    r'version[\s:]+([\d.]+)',
                    r'v([\d.]+)',
                    r'release[\s:]+([\d.]+)',
                    r'build[\s:]+([\d.]+)'
                ]

                for pattern in version_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        for version in matches[:3]:  # Limit to first 3 matches
                            self.add_result(
                                url,
                                'version_disclosure',
                                'low',
                                f"Version information disclosed: {version}",
                                f"Found in: {path}\nPattern: {pattern}",
                                "Review and remove unnecessary version disclosures"
                            )