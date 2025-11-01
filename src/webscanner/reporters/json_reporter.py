"""
JSON reporter for structured output
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from ..core.scanner import ScannerResult
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """JSON reporter for machine-readable output"""

    def generate(self, results: List[ScannerResult], target_url: str) -> str:
        """Generate JSON-formatted report"""
        # Build report structure
        report = {
            'scanner': 'WebScanner',
            'version': '1.0.0',
            'target_url': target_url,
            'scan_date': datetime.now().isoformat(),
            'summary': self._build_summary(results),
            'results': [result.to_dict() for result in results]
        }

        return json.dumps(report, indent=2, ensure_ascii=False)

    def _build_summary(self, results: List[ScannerResult]) -> Dict[str, Any]:
        """Build summary statistics"""
        severity_counts = {}
        check_counts = {}

        for result in results:
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
            check_counts[result.check_name] = check_counts.get(result.check_name, 0) + 1

        return {
            'total_issues': len(results),
            'severity_breakdown': severity_counts,
            'check_breakdown': check_counts
        }