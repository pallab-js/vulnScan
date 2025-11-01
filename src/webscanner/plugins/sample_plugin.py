"""
Sample plugin demonstrating custom check implementation
"""

from webscanner.checks.base import BaseCheck
from webscanner.core.scanner import ScannerResult


class SampleCustomCheck(BaseCheck):
    """Sample custom security check"""

    PLUGIN_NAME = 'sample_custom_check'

    def run(self):
        """Run custom security check"""
        # Example: Check for a custom endpoint vulnerability

        # Check a custom endpoint
        custom_url = f"{self.base_url}/api/debug"
        response = self.make_request('GET', custom_url)

        if response and response.status_code == 200:
            content = response.text.lower()

            # Look for debug information
            if 'debug' in content or 'stack trace' in content:
                self.add_result(
                    url=custom_url,
                    check_name=self.PLUGIN_NAME,
                    severity='medium',
                    description='Debug information exposed in API endpoint',
                    evidence=f"Debug content found in response: {content[:100]}...",
                    recommendation='Remove debug endpoints or protect them with authentication'
                )

        # Check another custom pattern
        test_urls = [
            f"{self.base_url}/.well-known/security.txt",
            f"{self.base_url}/security.txt"
        ]

        for url in test_urls:
            response = self.make_request('GET', url)
            if response and response.status_code == 200:
                self.add_result(
                    url=url,
                    check_name=self.PLUGIN_NAME,
                    severity='low',
                    description='Security.txt file found',
                    evidence='Security contact information available',
                    recommendation='Review security.txt content for accuracy'
                )

        return self.results