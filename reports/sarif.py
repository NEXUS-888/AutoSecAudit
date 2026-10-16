"""
SARIF (Static Analysis Results Interchange Format) Report Generator for AutoSecAudit.
Produces valid SARIF 2.1.0 JSON reports for CI/CD pipelines and GitHub Code Scanning.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional

from core.models import Report, Finding
from intelligence.taxonomy import TAXONOMY_ENTRIES, normalize_vuln_type_key


SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _clean_text(text: Optional[str]) -> str:
    """Ensure text is a safe string without None."""
    return str(text or "").strip()


def generate_sarif_report(report: Report, output_path: str) -> Dict[str, Any]:
    """
    Generate a SARIF 2.1.0 document from a Report object and save it to output_path.

    Returns the SARIF dictionary.
    """
    findings = report.all_findings or []

    # Map distinct vuln_types to SARIF rules
    rules_dict = {}
    for f in findings:
        v_type = f.vuln_type or "generic"
        if v_type not in rules_dict:
            tax_entry = TAXONOMY_ENTRIES.get(v_type)
            cwe = getattr(f, "cwe_id", None) or (tax_entry.cwe if tax_entry else None)
            
            rule_name = v_type.replace("_", " ").title()
            short_desc = f"{rule_name} Vulnerability"
            if tax_entry and tax_entry.remediation_key:
                short_desc = f"{rule_name} ({tax_entry.remediation_key})"

            rule_obj: Dict[str, Any] = {
                "id": v_type,
                "name": rule_name.replace(" ", ""),
                "shortDescription": {
                    "text": short_desc
                },
                "properties": {}
            }
            if cwe:
                rule_obj["properties"]["cwe"] = cwe

            rules_dict[v_type] = rule_obj

    rules_list = list(rules_dict.values())

    # Build results list
    results = []
    for f in findings:
        v_type = f.vuln_type or "generic"
        sev = (f.severity or "medium").lower()
        level = SEVERITY_TO_SARIF_LEVEL.get(sev, "warning")

        msg_text = _clean_text(f.title) or _clean_text(f.description) or "Security finding"
        uri_path = f.endpoint or "/"
        # Ensure URI is relative or well-formed path for artifactLocation
        if uri_path.startswith("http://") or uri_path.startswith("https://"):
            from urllib.parse import urlparse
            p = urlparse(uri_path).path
            uri_path = p or "/"

        result_obj: Dict[str, Any] = {
            "ruleId": v_type,
            "level": level,
            "message": {
                "text": msg_text
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri_path
                        }
                    }
                }
            ],
            "properties": {
                "severity": f.severity or "Medium",
                "confidence": f.confidence or "medium"
            }
        }
        results.append(result_obj)

    sarif_data: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AutoSecAudit",
                        "version": "2.0",
                        "informationUri": "https://github.com/autosecaudit/autosecaudit",
                        "rules": rules_list
                    }
                },
                "results": results
            }
        ]
    }

    # Save to disk
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(sarif_data, fp, indent=2)

    return sarif_data
