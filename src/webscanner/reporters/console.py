"""
Console reporter for human-readable output
"""

from typing import List, Dict
from datetime import datetime
from ..core.scanner import ScannerResult
from .base import BaseReporter


class ConsoleReporter(BaseReporter):
    """Console reporter with colored, human-readable output"""

    SEVERITY_COLORS = {
        'critical': '\033[91m',  # Red
        'high': '\033[91m',     # Red
        'medium': '\033[93m',   # Yellow
        'low': '\033[94m',      # Blue
        'info': '\033[92m'      # Green
    }
    RESET_COLOR = '\033[0m'

    def generate(self, results: List[ScannerResult], target_url: str) -> str:
        """Generate console-formatted report"""
        output_lines = []

        # Header
        output_lines.append("=" * 80)
        output_lines.append("WebScanner Security Report")
        output_lines.append("=" * 80)
        output_lines.append(f"Target: {target_url}")
        output_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output_lines.append(f"Total Issues Found: {len(results)}")
        output_lines.append("")

        if not results:
            output_lines.append("? No security issues found!")
            return "\n".join(output_lines)

        # Severity summary
        severity_counts = self._count_severities(results)
        output_lines.append("Severity Summary:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = self.SEVERITY_COLORS.get(severity, '')
                output_lines.append(f"  {color}{severity.upper()}: {count}{self.RESET_COLOR}")
        output_lines.append("")

        # Group results by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_results = [r for r in results if r.severity == severity]
            if severity_results:
                output_lines.append(f"{severity.upper()} SEVERITY ISSUES:")
                output_lines.append("-" * 40)

                for result in severity_results:
                    output_lines.append(self._format_result(result))
                    output_lines.append("")

        # Footer
        output_lines.append("=" * 80)
        output_lines.append("Scan completed.")
        output_lines.append("=" * 80)

        return "\n".join(output_lines)

    def _count_severities(self, results: List[ScannerResult]) -> Dict[str, int]:
        """Count results by severity"""
        counts = {}
        for result in results:
            counts[result.severity] = counts.get(result.severity, 0) + 1
        return counts

    def _format_result(self, result: ScannerResult) -> str:
        """Format a single result for console output"""
        color = self.SEVERITY_COLORS.get(result.severity, '')

        lines = [
            f"{color}[{result.severity.upper()}]{self.RESET_COLOR} {result.check_name}",
            f"URL: {result.url}",
            f"Description: {result.description}"
        ]

        if result.evidence:
            lines.append(f"Evidence: {result.evidence}")

        if result.recommendation:
            lines.append(f"Recommendation: {result.recommendation}")

        return "\n".join(f"  {line}" for line in lines)