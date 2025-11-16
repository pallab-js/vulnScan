#!/usr/bin/env python3
"""
Basic tests for WebScanner
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os
import requests

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from webscanner.core.scanner import WebScanner, ScannerResult
from webscanner.checks.base import BaseCheck
from webscanner.utils.http_client import HttpClient


class TestWebScanner(unittest.TestCase):

    def setUp(self):
        self.base_url = "http://example.com"
        self.scanner = WebScanner(self.base_url, max_threads=1, timeout=5)

    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        self.assertEqual(self.scanner.base_url, "http://example.com/")
        self.assertEqual(self.scanner.max_threads, 1)
        self.assertEqual(self.scanner.timeout, 5)

    def test_scanner_result_creation(self):
        """Test ScannerResult creation"""
        result = ScannerResult(
            url="http://example.com/test",
            check_name="test_check",
            severity="high",
            description="Test vulnerability",
            evidence="Test evidence",
            recommendation="Fix it"
        )

        self.assertEqual(result.url, "http://example.com/test")
        self.assertEqual(result.check_name, "test_check")
        self.assertEqual(result.severity, "high")

    def test_http_client_initialization(self):
        """Test HTTP client initializes correctly"""
        client = HttpClient(timeout=10, delay=0.5)
        self.assertEqual(client.timeout, 10)
        self.assertEqual(client.delay, 0.5)
        self.assertIsNotNone(client.user_agent)

    def test_base_check_initialization(self):
        """Test base check initializes correctly"""
        client = HttpClient()
        check = BaseCheck(client, self.base_url)
        self.assertEqual(check.base_url, self.base_url)
        self.assertEqual(check.http_client, client)
        self.assertEqual(check.results, [])

    def test_url_validation(self):
        """Test URL validation"""
        from webscanner.core.scanner import _validate_url

        # Valid URLs
        _validate_url("http://example.com")
        _validate_url("https://example.com")

        # Invalid schemes
        with self.assertRaises(ValueError):
            _validate_url("ftp://example.com")

        # Private IPs
        with self.assertRaises(ValueError):
            _validate_url("http://192.168.1.1")

        # Localhost
        with self.assertRaises(ValueError):
            _validate_url("http://localhost")

    def test_http_client_retry(self):
        """Test HTTP client retry logic"""
        client = HttpClient(max_retries=2)

        with patch('requests.Session.request') as mock_request:
            mock_request.side_effect = [requests.exceptions.Timeout(), requests.exceptions.Timeout(), Mock(status_code=200)]

            # Should succeed after retries
            response = client.request('GET', 'http://example.com')
            self.assertEqual(mock_request.call_count, 3)

    def test_config_loading(self):
        """Test configuration loading"""
        from webscanner.config import Config
        import tempfile
        import json

        config_data = {
            'scanner': {
                'threads': 5,
                'timeout': 20
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        config = Config(config_file)
        self.assertEqual(config.get('scanner.threads'), 5)
        self.assertEqual(config.get('scanner.timeout'), 20)

        import os
        os.unlink(config_file)


class MockCheck(BaseCheck):
    """Mock check for testing"""

    def run(self):
        self.add_result(
            self.base_url,
            "mock_check",
            "info",
            "Mock check result",
            "Mock evidence"
        )
        return self.results


class TestScannerIntegration(unittest.TestCase):

    def setUp(self):
        self.base_url = "http://httpbin.org"
        self.scanner = WebScanner(self.base_url, max_threads=1, timeout=10)

    @patch('requests.Session.get')
    def test_scanner_with_mock_check(self, mock_get):
        """Test scanner with mock check"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'TestServer/1.0'}
        mock_get.return_value = mock_response

        # Run scanner with mock check
        results = self.scanner.scan([MockCheck])

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].check_name, "mock_check")
        self.assertEqual(results[0].severity, "info")


if __name__ == '__main__':
    unittest.main()