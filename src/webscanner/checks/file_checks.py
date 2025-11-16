"""
File and directory enumeration checks
"""

import logging
from typing import List

from .base import BaseCheck
from ..core.scanner import ScannerResult

logger = logging.getLogger(__name__)


class FileChecks(BaseCheck):
    """Check for common vulnerable files and directories"""

    # Common files to check (organized by category)
    COMMON_FILES = {
        'backup_files': [
            'backup.sql', 'backup.tar.gz', 'backup.zip',
            'db.sql', 'database.sql', 'dump.sql',
            '.backup', '.bak', '.old', '.orig',
            'www.sql', 'site.sql', 'data.sql'
        ],
        'config_files': [
            'config.php', 'config.inc.php', 'config.ini',
            'settings.php', 'database.php', 'db.php',
            'configuration.php', 'config.json', 'settings.json',
            'web.config', 'application.properties',
            '.env', '.env.local', '.env.production'
        ],
        'admin_panels': [
            'admin/', 'admin.php', 'administrator/', 'adminpanel/',
            'cpanel/', 'controlpanel/', 'manage/', 'manager/',
            'admin-login.php', 'admin_login.php', 'login.php'
        ],
        'log_files': [
            'error.log', 'access.log', 'debug.log',
            'error_log', 'access_log', 'debug_log',
            'logs/error.log', 'logs/access.log'
        ],
        'source_code': [
            '.git/', '.svn/', '.hg/', '.bzr/',
            '.gitignore', '.gitattributes',
            'composer.json', 'package.json', 'requirements.txt',
            'web.config', 'htaccess', '.htaccess'
        ],
        'temporary_files': [
            'tmp/', 'temp/', 'cache/', 'logs/',
            'session/', 'sessions/', 'upload/',
            'uploads/', 'files/', 'images/'
        ],
        'documentation': [
            'readme.txt', 'README.txt', 'readme.md', 'README.md',
            'changelog.txt', 'CHANGELOG.txt', 'changelog.md',
            'install.txt', 'INSTALL.txt', 'install.md',
            'license.txt', 'LICENSE.txt', 'license.md'
        ]
    }

    # Files that should never be accessible
    CRITICAL_FILES = [
        '.env', '.git/config', '.svn/entries', 'web.config',
        'application.properties', 'database.properties',
        'wp-config.php', 'config.php', 'settings.php'
    ]

    def run(self) -> List[ScannerResult]:
        """Run file enumeration checks"""
        logger.info("Running file enumeration checks")

        # Check critical files first
        self._check_critical_files()

        # Check common vulnerable files
        self._check_common_files()

        # Check directory listing
        self._check_directory_listing()

        return self.results

    def _check_critical_files(self):
        """Check for critical files that should never be accessible"""
        for file_path in self.CRITICAL_FILES:
            url = self.http_client.build_url(self.base_url, file_path)
            response = self.make_request('GET', url)

            if response and response.status_code == 200:
                # Skip binary files and images
                content_type = response.headers.get('content-type', '').lower()
                if any(skip_type in content_type for skip_type in ['image/', 'application/octet-stream']):
                    content_preview = "[Binary content]"
                else:
                    content_preview = response.text[:500] + "..." if len(response.text) > 500 else response.text

                self.add_result(
                    url,
                    'critical_file_exposed',
                    'critical',
                    f"Critical configuration file exposed: {file_path}",
                    f"Status: {response.status_code}\nContent-Type: {content_type}\nContent preview: {content_preview}",
                    f"Immediately secure or remove {file_path} from web accessible directory"
                )

    def _check_common_files(self):
        """Check for common vulnerable files"""
        for category, files in self.COMMON_FILES.items():
            for file_path in files:
                url = self.http_client.build_url(self.base_url, file_path)
                response = self.make_request('GET', url)

                if response and response.status_code == 200:
                    # Skip binary files and images
                    content_type = response.headers.get('content-type', '').lower()
                    if any(skip_type in content_type for skip_type in ['image/', 'application/octet-stream']):
                        continue

                    severity = self._determine_file_severity(file_path, category)

                    content_preview = response.text[:200] + "..." if len(response.text) > 200 else response.text

                    self.add_result(
                        url,
                        'vulnerable_file_exposed',
                        severity,
                        f"Potentially sensitive file exposed: {file_path}",
                        f"Category: {category}\nStatus: {response.status_code}\nContent-Type: {content_type}\nPreview: {content_preview}",
                        self._get_file_recommendation(file_path, category)
                    )

    def _check_directory_listing(self):
        """Check for directory listing vulnerabilities"""
        test_dirs = [
            'backup/', 'backups/', 'old/', 'archive/',
            'tmp/', 'temp/', 'cache/', 'logs/',
            'upload/', 'uploads/', 'files/', 'images/',
            'css/', 'js/', 'assets/', 'static/'
        ]

        for dir_path in test_dirs:
            url = self.http_client.build_url(self.base_url, dir_path)
            response = self.make_request('GET', url)

            if response and response.status_code == 200:
                content = response.text.lower()

                # Check for directory listing indicators
                listing_indicators = [
                    'index of', 'parent directory', 'directory listing',
                    '<title>index of', '<h1>index of',
                    'name', 'last modified', 'size', 'description'
                ]

                if any(indicator in content for indicator in listing_indicators):
                    self.add_result(
                        url,
                        'directory_listing_enabled',
                        'medium',
                        f"Directory listing enabled: {dir_path}",
                        f"Directory contents visible\nStatus: {response.status_code}",
                        f"Disable directory listing in web server configuration or add index file to {dir_path}"
                    )

    def _determine_file_severity(self, file_path: str, category: str) -> str:
        """Determine severity level for exposed file"""
        if category in ['backup_files', 'config_files'] or file_path in self.CRITICAL_FILES:
            return 'high'
        elif category in ['admin_panels', 'source_code']:
            return 'medium'
        else:
            return 'low'

    def _get_file_recommendation(self, file_path: str, category: str) -> str:
        """Get recommendation for exposed file"""
        if category == 'backup_files':
            return f"Remove backup file {file_path} from web directory or restrict access"
        elif category == 'config_files':
            return f"Move configuration file {file_path} outside web root or restrict access"
        elif category == 'admin_panels':
            return f"Secure admin panel at {file_path} with proper authentication and access controls"
        elif category == 'log_files':
            return f"Move log file {file_path} outside web root or restrict access"
        elif category == 'source_code':
            return f"Remove or protect source code repository files/directories at {file_path}"
        else:
            return f"Review and secure access to {file_path}"