import logging
from typing import List, Dict, Any, Optional

from core.models import Finding, Report

logger = logging.getLogger(__name__)


class DeltaAnalyzer:
    """Compare current scan with previous scan for delta analysis."""

    def __init__(self):
        pass

    def _get_fingerprint(self, finding: Any) -> str:
        """Get or compute fingerprint for a Finding object."""
        fp = getattr(finding, "fingerprint", None)
        if fp:
            return fp
        if hasattr(finding, "compute_fingerprint"):
            fp = finding.compute_fingerprint()
            finding.fingerprint = fp
            return fp
        from core.models import compute_finding_fingerprint
        return compute_finding_fingerprint(
            tool=getattr(finding, "tool_name", None),
            vuln_type=getattr(finding, "vuln_type", None),
            method=getattr(finding, "method", None),
            endpoint=getattr(finding, "endpoint", None),
            param=getattr(finding, "param", None),
            title=getattr(finding, "title", None),
        )

    def _get_dict_fingerprint(self, d: Dict[str, Any]) -> str:
        """Get or compute fingerprint for a finding dictionary."""
        if d.get("fingerprint"):
            return d["fingerprint"]
        from core.models import compute_finding_fingerprint
        fp = compute_finding_fingerprint(
            tool=d.get("tool_name") or d.get("tool"),
            vuln_type=d.get("vuln_type"),
            method=d.get("method"),
            endpoint=d.get("endpoint"),
            param=d.get("param"),
            title=d.get("title"),
        )
        d["fingerprint"] = fp
        return fp

    def compare(self, current_report: Report, previous_report: Report) -> Dict[str, Any]:
        """Compare current findings with previous findings by fingerprint."""
        if not current_report or not hasattr(current_report, "all_findings"):
            current_findings_list = []
        else:
            current_findings_list = [
                f for f in current_report.all_findings
                if f and (getattr(f, "fingerprint", None) or getattr(f, "id", None) or getattr(f, "title", None))
            ]

        if not previous_report or not hasattr(previous_report, "all_findings"):
            previous_findings_list = []
        else:
            previous_findings_list = [
                f for f in previous_report.all_findings
                if f and (getattr(f, "fingerprint", None) or getattr(f, "id", None) or getattr(f, "title", None))
            ]

        current_fps = {self._get_fingerprint(f) for f in current_findings_list}
        previous_fps = {self._get_fingerprint(f) for f in previous_findings_list}

        new_issues = current_fps - previous_fps
        fixed_issues = previous_fps - current_fps
        unchanged = current_fps & previous_fps

        current_map = {self._get_fingerprint(f): f for f in current_findings_list}
        previous_map = {self._get_fingerprint(f): f for f in previous_findings_list}

        new_findings = [current_map[fp] for fp in new_issues if fp in current_map]
        fixed_findings = [previous_map[fp] for fp in fixed_issues if fp in previous_map]
        unchanged_findings = [current_map[fp] for fp in unchanged if fp in current_map]

        delta = {
            "new_issues": [f.to_dict() for f in new_findings],
            "fixed_issues": [f.to_dict() for f in fixed_findings],
            "unchanged_issues": [f.to_dict() for f in unchanged_findings],
            "summary": {
                "new_count": len(new_findings),
                "fixed_count": len(fixed_findings),
                "unchanged_count": len(unchanged_findings),
            }
        }

        logger.info(f"Delta: {len(new_findings)} new, {len(fixed_findings)} fixed, {len(unchanged_findings)} unchanged")

        return delta

    def compare_with_dict(self, current_findings: List[Dict], 
                         previous_report: Dict[str, Any]) -> Dict[str, Any]:
        """Compare current findings with previous report dictionary by fingerprint."""
        if not isinstance(previous_report, dict):
            previous_report = {}
        if not isinstance(current_findings, list):
            current_findings = []

        previous_findings = [
            f for f in previous_report.get("all_findings", [])
            if isinstance(f, dict) and (f.get("fingerprint") or f.get("id"))
        ]
        valid_current_findings = [
            f for f in current_findings
            if isinstance(f, dict) and (f.get("fingerprint") or f.get("id"))
        ]

        previous_fps = {self._get_dict_fingerprint(f) for f in previous_findings}
        current_fps = {self._get_dict_fingerprint(f) for f in valid_current_findings}

        new_issues = current_fps - previous_fps
        fixed_issues = previous_fps - current_fps
        unchanged = current_fps & previous_fps

        current_map = {self._get_dict_fingerprint(f): f for f in valid_current_findings}
        previous_map = {self._get_dict_fingerprint(f): f for f in previous_findings}

        return {
            "new_issues": [current_map[fp] for fp in new_issues if fp in current_map],
            "fixed_issues": [previous_map[fp] for fp in fixed_issues if fp in previous_map],
            "unchanged_issues": [current_map[fp] for fp in unchanged if fp in current_map],
            "summary": {
                "new_count": len(new_issues),
                "fixed_count": len(fixed_issues),
                "unchanged_count": len(unchanged),
            }
        }
