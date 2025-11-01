#!/usr/bin/env python3
"""
Main CLI interface for WebScanner
"""

import argparse
import sys
import os
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from webscanner.core.scanner import WebScanner
from webscanner.checks import get_all_checks
from webscanner.reporters import get_reporter
from webscanner.utils.logger import get_logger, set_log_level
from webscanner import __version__

logger = get_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CLI"""
    parser = argparse.ArgumentParser(
        description="WebScanner - A powerful CLI-based web security vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  webscanner http://example.com
  webscanner https://example.com -o json -v
  webscanner http://example.com --checks header_checks,file_checks --threads 5
  webscanner http://example.com --user-agent "Custom Scanner/1.0"
        """
    )

    # Required arguments
    parser.add_argument(
        'url',
        help='Target URL to scan'
    )

    # Output options
    parser.add_argument(
        '-o', '--output',
        choices=['console', 'json', 'xml', 'csv'],
        default='console',
        help='Output format (default: console)'
    )

    parser.add_argument(
        '-f', '--output-file',
        help='Output file path'
    )

    # Scan options
    parser.add_argument(
        '-c', '--checks',
        help='Comma-separated list of checks to run (default: all)',
        default='all'
    )

    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )

    parser.add_argument(
        '--delay',
        type=float,
        default=0.1,
        help='Delay between requests in seconds (default: 0.1)'
    )

    # HTTP options
    parser.add_argument(
        '--user-agent',
        help='Custom User-Agent string'
    )

    parser.add_argument(
        '--proxy',
        help='Proxy URL (http://proxy:port or https://proxy:port)'
    )

    parser.add_argument(
        '--no-ssl-verify',
        action='store_true',
        help='Skip SSL certificate verification'
    )

    # Logging options
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (use -vv for debug)'
    )

    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress all output except results'
    )

    # Other options
    parser.add_argument(
        '--version',
        action='version',
        version=f'WebScanner {__version__}'
    )

    return parser


def parse_checks(check_string: str) -> List[str]:
    """Parse check selection string"""
    if check_string.lower() == 'all':
        return ['all']
    return [check.strip() for check in check_string.split(',') if check.strip()]


def setup_logging(verbose: int, quiet: bool):
    """Setup logging configuration"""
    if quiet:
        level = logging.ERROR
    elif verbose == 0:
        level = logging.WARNING
    elif verbose == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    set_log_level(logging.getLevelName(level))


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose, args.quiet)

    try:
        # Validate URL
        if not args.url.startswith(('http://', 'https://')):
            args.url = f'http://{args.url}'

        logger.info(f"Starting WebScanner {__version__} against {args.url}")

        # Initialize scanner
        scanner = WebScanner(
            base_url=args.url,
            max_threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent
        )

        # Configure HTTP client
        proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
        scanner.http_client.proxies = proxies
        scanner.http_client.verify_ssl = not args.no_ssl_verify

        # Get available checks
        all_checks = get_all_checks()
        selected_checks = parse_checks(args.checks)

        if 'all' not in selected_checks:
            # Filter checks
            checks_to_run = []
            for check_name in selected_checks:
                if check_name in all_checks:
                    checks_to_run.append(all_checks[check_name])
                else:
                    logger.warning(f"Unknown check: {check_name}")
        else:
            checks_to_run = list(all_checks.values())

        if not checks_to_run:
            logger.error("No valid checks selected")
            sys.exit(1)

        logger.info(f"Running {len(checks_to_run)} checks")

        # Run scan
        results = scanner.scan(checks_to_run)

        # Generate report
        reporter = get_reporter(args.output)
        report = reporter.generate(results, args.url)

        # Output results
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            logger.info(f"Results written to {args.output_file}")
        else:
            print(report)

        # Summary
        severity_counts = {}
        for result in results:
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1

        logger.info(f"Scan completed. Found {len(results)} issues")
        if severity_counts:
            logger.info("Severity breakdown: " + ", ".join(
                f"{sev}: {count}" for sev, count in severity_counts.items()
            ))

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()