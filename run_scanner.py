#!/usr/bin/env python3
"""
Simple script to run WebScanner for testing
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from webscanner.core.scanner import WebScanner
from webscanner.checks import get_all_checks
from webscanner.reporters import get_reporter

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_scanner.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]

    print(f"Starting WebScanner against {target_url}")

    # Initialize scanner
    scanner = WebScanner(
        base_url=target_url,
        max_threads=5,
        timeout=10,
        delay=0.2
    )

    # Get all checks
    all_checks = get_all_checks()
    checks_to_run = list(all_checks.values())

    print(f"Running {len(checks_to_run)} checks...")

    # Run scan
    results = scanner.scan(checks_to_run)

    # Generate console report
    reporter = get_reporter('console')
    report = reporter.generate(results, target_url)

    print("\n" + "="*80)
    print(report)

if __name__ == '__main__':
    main()