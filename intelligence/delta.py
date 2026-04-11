import logging
from typing import List, Dict, Any, Optional

from core.models import Finding, Report

logger = logging.getLogger(__name__)


class DeltaAnalyzer:
    """Compare current scan with previous scan for delta analysis."""

    def __init__(self):
        pass

    def compare(self, current_report: Report, previous_report: Report) -> Dict[str, Any]:
        """Compare current findings with previous findings."""
        current_ids = {f.id for f in current_report.all_findings}
        previous_ids = {f.id for f in previous_report.all_findings}

        new_issues = current_ids - previous_ids
        fixed_issues = previous_ids - current_ids
        unchanged = current_ids & previous_ids

        current_map = {f.id: f for f in current_report.all_findings}
        previous_map = {f.id: f for f in previous_report.all_findings}

        new_findings = [current_map[fid] for fid in new_issues if fid in current_map]
        fixed_findings = [previous_map[fid] for fid in fixed_issues if fid in previous_map]
        unchanged_findings = [current_map[fid] for fid in unchanged if fid in current_map]

        delta = {
            "new_issues": [f.to_dict() for f in new_findings],
            "fixed_issues": [f.to_dict() for f in fixed_findings],
            "unchanged_issues": [f.to_dict() for f in unchanged_findings],
            "summary": {
                "new_count": len(new_findings),
                "fixed_count": len(fixed_findings),
                "unchanged_count": len(unchanged_findings)
            }
        }

        logger.info(f"Delta: {len(new_findings)} new, {len(fixed_findings)} fixed, {len(unchanged_findings)} unchanged")

        return delta

    def compare_with_dict(self, current_findings: List[Dict], 
                         previous_report: Dict[str, Any]) -> Dict[str, Any]:
        """Compare current findings with previous report dictionary."""
        previous_findings = previous_report.get("all_findings", [])
        previous_ids = {f["id"] for f in previous_findings}
        current_ids = {f["id"] for f in current_findings}

        new_issues = current_ids - previous_ids
        fixed_issues = previous_ids - current_ids

        current_map = {f["id"]: f for f in current_findings}
        previous_map = {f["id"]: f for f in previous_findings}

        return {
            "new_issues": [current_map[fid] for fid in new_issues if fid in current_map],
            "fixed_issues": [previous_map[fid] for fid in fixed_issues if fid in previous_map],
            "summary": {
                "new_count": len(new_issues),
                "fixed_count": len(fixed_issues)
            }
        }
