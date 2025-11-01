"""
XML reporter for structured output
"""

import xml.etree.ElementTree as ET
import xml.dom.minidom
from typing import List
from datetime import datetime
from ..core.scanner import ScannerResult
from .base import BaseReporter


class XMLReporter(BaseReporter):
    """XML reporter for structured output"""

    def generate(self, results: List[ScannerResult], target_url: str) -> str:
        """Generate XML-formatted report"""
        # Create root element
        root = ET.Element('webscanner-report')

        # Add metadata
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'scanner').text = 'WebScanner'
        ET.SubElement(metadata, 'version').text = '1.0.0'
        ET.SubElement(metadata, 'target-url').text = target_url
        ET.SubElement(metadata, 'scan-date').text = datetime.now().isoformat()
        ET.SubElement(metadata, 'total-issues').text = str(len(results))

        # Add summary
        summary = ET.SubElement(root, 'summary')
        severity_counts = self._count_severities(results)
        for severity, count in severity_counts.items():
            ET.SubElement(summary, f'{severity}-count').text = str(count)

        # Add results
        results_elem = ET.SubElement(root, 'results')
        for result in results:
            result_elem = ET.SubElement(results_elem, 'result')

            ET.SubElement(result_elem, 'url').text = result.url
            ET.SubElement(result_elem, 'check-name').text = result.check_name
            ET.SubElement(result_elem, 'severity').text = result.severity
            ET.SubElement(result_elem, 'description').text = result.description
            ET.SubElement(result_elem, 'evidence').text = result.evidence
            ET.SubElement(result_elem, 'recommendation').text = result.recommendation
            ET.SubElement(result_elem, 'timestamp').text = str(result.timestamp)

        # Pretty print XML
        rough_string = ET.tostring(root, encoding='unicode')
        reparsed = xml.dom.minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent='  ')

    def _count_severities(self, results: List[ScannerResult]) -> dict:
        """Count results by severity"""
        counts = {}
        for result in results:
            counts[result.severity] = counts.get(result.severity, 0) + 1
        return counts