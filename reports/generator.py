import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

import config
from core.models import Report

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate HTML reports from scan results."""

    def __init__(self, template_dir: Optional[str] = None):
        if template_dir is None:
            template_dir = str(Path(__file__).parent / "templates")
        
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.env.filters['sort'] = sorted

    def generate_html(self, report: Report, output_path: Optional[str] = None) -> str:
        """Generate HTML report from Report object."""
        template = self.env.get_template("report.html")
        
        html_content = template.render(report=report.to_dict())
        
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_path}")
            return str(output_file)
        
        return html_content

    def generate_from_dict(self, report_data: Dict[str, Any], 
                          output_path: Optional[str] = None) -> str:
        """Generate HTML report from dictionary."""
        template = self.env.get_template("report.html")
        
        html_content = template.render(report=report_data)
        
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_path}")
            return str(output_file)
        
        return html_content

    def generate_pdf(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Generate printable text PDF audit summary report."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        target = report_data.get("target", "Unknown")
        timestamp = report_data.get("timestamp", "N/A")
        summary = report_data.get("summary", {})
        findings = report_data.get("all_findings", [])
        
        pdf_lines = [
            "=" * 60,
            "            AUTOSECAUDIT 2.0 - EXECUTIVE SECURITY REPORT",
            "=" * 60,
            f"Target:    {target}",
            f"Timestamp: {timestamp}",
            f"Total Findings: {summary.get('total', len(findings))}",
            f"  Critical: {summary.get('critical', 0)}",
            f"  High:     {summary.get('high', 0)}",
            f"  Medium:   {summary.get('medium', 0)}",
            f"  Low:      {summary.get('low', 0)}",
            "=" * 60,
            "\nVULNERABILITY SUMMARY & FINDINGS:\n",
        ]
        
        for idx, f in enumerate(findings, 1):
            pdf_lines.append(f"[{idx}] {f.get('severity', 'UNKNOWN').upper()} - {f.get('title', 'Untitled')}")
            pdf_lines.append(f"    Tool:       {f.get('tool_name', 'N/A')}")
            pdf_lines.append(f"    OWASP Tag:  {f.get('owasp_tag', 'N/A')}")
            pdf_lines.append(f"    CWE / PCI:  {f.get('cwe_id', 'N/A')} | {f.get('pci_dss', 'N/A')}")
            pdf_lines.append(f"    Description: {f.get('description', 'N/A')}")
            if f.get('remediation'):
                pdf_lines.append(f"    Fix Advice:  {f.get('remediation')}")
            pdf_lines.append("-" * 60)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(pdf_lines))
            
        logger.info(f"PDF text summary report saved to {output_path}")
        return str(output_file)

    def generate_report(self, report: Report, 
                       previous_report: Optional[Report] = None) -> str:
        """Generate full report with optional delta comparison."""
        if previous_report:
            from intelligence.delta import DeltaAnalyzer
            delta_analyzer = DeltaAnalyzer()
            delta = delta_analyzer.compare(report, previous_report)
            report_data = report.to_dict()
            report_data["delta"] = delta
        else:
            report_data = report.to_dict()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"{config.REPORTS_DIR}/report_{timestamp}.html"
        
        return self.generate_from_dict(report_data, output_path)
