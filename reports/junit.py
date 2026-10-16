"""
JUnit XML Report Generator for AutoSecAudit.
Produces well-formed JUnit XML reports for CI test runners and dashboards.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from core.models import Report, Finding


SEVERITIES_ORDER = ["info", "low", "medium", "high", "critical"]


def _clean_text(val: Optional[str]) -> str:
    """Sanitize string values for XML."""
    return str(val or "").strip()


def generate_junit_report(report: Report, output_path: str, fail_on: Optional[str] = None) -> str:
    """
    Generate JUnit XML from a Report object.

    Args:
        report: Scan report containing findings.
        output_path: Path where JUnit XML will be saved.
        fail_on: Severity threshold ('critical', 'high', 'medium', 'low', 'info').
                 If None, all findings are treated as failures.
                 If set, findings at or above this severity are failures; others pass.

    Returns:
        The generated XML string.
    """
    findings = report.all_findings or []
    total_tests = len(findings)

    threshold_idx = None
    if fail_on:
        f_lower = fail_on.lower()
        if f_lower in SEVERITIES_ORDER:
            threshold_idx = SEVERITIES_ORDER.index(f_lower)

    # Calculate failures
    def is_failure(finding: Finding) -> bool:
        if threshold_idx is None:
            # When no threshold is set, all findings are failures
            return True
        sev = (finding.severity or "info").lower()
        if sev in SEVERITIES_ORDER:
            return SEVERITIES_ORDER.index(sev) >= threshold_idx
        return False

    failures_count = sum(1 for f in findings if is_failure(f))

    # Build XML tree
    testsuite = ET.Element("testsuite", {
        "name": "AutoSecAudit",
        "tests": str(total_tests),
        "failures": str(failures_count),
        "errors": "0",
        "skipped": "0",
    })

    for f in findings:
        title = _clean_text(f.title) or _clean_text(f.id) or "Finding"
        v_type = _clean_text(f.vuln_type) or "vulnerability"
        sev = _clean_text(f.severity) or "Medium"
        desc = _clean_text(f.description)

        testcase = ET.SubElement(testsuite, "testcase", {
            "name": title,
            "classname": v_type,
        })

        if is_failure(f):
            fail_el = ET.SubElement(testcase, "failure", {
                "message": title,
                "type": sev,
            })
            fail_el.text = desc

    # Write to file
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(testsuite)
    
    # Generate XML with declaration
    ET.indent(tree, space="  ", level=0)
    tree.write(str(out_file), encoding="utf-8", xml_declaration=True)

    with open(out_file, "r", encoding="utf-8") as fp:
        xml_str = fp.read()

    return xml_str
