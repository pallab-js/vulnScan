"""
CSV reporter for spreadsheet analysis
"""

import csv
import io
from typing import List
from datetime import datetime
from ..core.scanner import ScannerResult
from .base import BaseReporter


class CSVReporter(BaseReporter):
    """CSV reporter for spreadsheet analysis"""

    def generate(self, results: List[ScannerResult], target_url: str) -> str:
        """Generate CSV-formatted report"""
        output = io.StringIO()

        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'URL', 'Check Name', 'Severity', 'Description',
            'Evidence', 'Recommendation', 'Timestamp'
        ])

        # Write results
        for result in results:
            writer.writerow([
                result.url,
                result.check_name,
                result.severity,
                result.description,
                result.evidence,
                result.recommendation,
                datetime.fromtimestamp(result.timestamp).isoformat()
            ])

        return output.getvalue()