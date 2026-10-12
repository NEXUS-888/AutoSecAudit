import logging
import re
from typing import List, Dict, Any, Tuple, Optional

from core.models import Finding
from intelligence.taxonomy import (
    TAXONOMY_ENTRIES,
    get_taxonomy,
    infer_taxonomy_from_text,
)

logger = logging.getLogger(__name__)

OWASP_MAPPING = {
    "A01:2021": {
        "name": "Broken Access Control",
        "keywords": ["access control", "authorization", "privilege", "idor", 
                     "vertical privilege", "horizontal privilege", "access control bypass", "privilege bypass"]
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "keywords": ["crypto", "encryption", "ssl", "tls", "certificate", 
                    "hash", "md5", "sha1", "weak cipher", "cryptographic"]
    },
    "A03:2021": {
        "name": "Injection",
        "keywords": ["sql injection", "sqli", "xss", "cross-site scripting",
                     "command injection", "code injection", "ldap", "nosql",
                     "injection", "script injection"]
    },
    "A04:2021": {
        "name": "Insecure Design",
        "keywords": ["insecure design", "design flaw", "missing authorization",
                     "business logic", "threat modeling"]
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "keywords": ["misconfiguration", "default credential", "default password",
                     "missing hardening", "verbose error", "error disclosure",
                     "directory listing", "information disclosure"]
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "keywords": ["outdated", "vulnerable component", "old version",
                     "deprecated", "unpatched", "cve"]
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "keywords": ["authentication", "brute force", "credential", "session",
                     "login", "password", "2fa", "mfa", "weak credential"]
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "keywords": ["integrity", "deserialization", "unsafe deserial",
                     "ci/cd", "supply chain", "unverified"]
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "keywords": ["logging", "monitoring", "log injection", "missing log",
                     "no audit", "detection"]
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery",
        "keywords": ["ssrf", "server-side request forgery", "webhook",
                     "url fetch", "blind ssrf"]
    }
}


class ComplianceMapper:
    """Map findings to compliance frameworks like OWASP Top 10, CWE, and PCI-DSS v4.0."""

    def __init__(self):
        self.owasp_mapping = OWASP_MAPPING
        self.cwe_mapping = {
            "sqli": ("CWE-89", "PCI-DSS 6.2.4"),
            "xss": ("CWE-79", "PCI-DSS 6.2.4"),
            "command injection": ("CWE-78", "PCI-DSS 6.2.4"),
            "ssrf": ("CWE-918", "PCI-DSS 6.2.4"),
            "path traversal": ("CWE-22", "PCI-DSS 6.2.4"),
            "ssti": ("CWE-1336", "PCI-DSS 6.2.4"),
            "jwt": ("CWE-347", "PCI-DSS 8.3.1"),
            "cors": ("CWE-942", "PCI-DSS 6.4.1"),
            "dirbrute": ("CWE-538", "PCI-DSS 6.5.1"),
            "auth": ("CWE-287", "PCI-DSS 8.2.1"),
            "misconfig": ("CWE-16", "PCI-DSS 2.2.1"),
            "api_abuse": ("CWE-285", "PCI-DSS 6.5.8")
        }

    def map_findings(self, findings: List[Finding]) -> List[Finding]:
        """Map each finding to OWASP, CWE, and PCI-DSS categories without overwriting existing plugin tags."""
        for f in findings:
            tax = None
            if f.vuln_type:
                tax = get_taxonomy(f.vuln_type)
            if not tax:
                text = f"{f.title or ''} {f.description or ''} {f.tool_name or ''}"
                tax = infer_taxonomy_from_text(text)

            # Never overwrite existing plugin tags!
            if not f.owasp_tag:
                if tax:
                    f.owasp_tag = tax.owasp
                else:
                    owasp_tag = self._find_owasp_category(f)
                    if owasp_tag:
                        f.owasp_tag = owasp_tag

            if not f.cwe_id:
                if tax:
                    f.cwe_id = tax.cwe
                else:
                    cwe, _ = self._find_cwe_pci(f)
                    if cwe:
                        f.cwe_id = cwe

            if not f.pci_dss:
                if tax:
                    f.pci_dss = tax.pci
                else:
                    _, pci = self._find_cwe_pci(f)
                    if pci:
                        f.pci_dss = pci

        return findings

    def _find_cwe_pci(self, finding: Finding) -> tuple:
        text = f"{finding.title or ''} {finding.description or ''} {finding.tool_name or ''}"
        for key, (cwe, pci) in self.cwe_mapping.items():
            pattern = rf"\b{re.escape(key)}\b"
            if re.search(pattern, text, re.IGNORECASE):
                return cwe, pci
        return None, None

    def _find_owasp_category(self, finding: Finding) -> str:
        text = f"{finding.title or ''} {finding.description or ''}"

        for category_id, category_info in self.owasp_mapping.items():
            for keyword in category_info["keywords"]:
                pattern = rf"\b{re.escape(keyword)}\b"
                if re.search(pattern, text, re.IGNORECASE):
                    return category_id

        return self._infer_from_severity(finding)

    def _infer_from_severity(self, finding: Finding) -> str:
        if finding.cve_id:
            return "A06:2021"
        return ""

    def get_compliance_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate compliance summary for all findings."""
        summary = {cat_id: 0 for cat_id in self.owasp_mapping.keys()}
        
        for f in findings:
            if f.owasp_tag and f.owasp_tag in summary:
                summary[f.owasp_tag] += 1

        return {
            "owasp_top_10": [
                {
                    "id": cat_id,
                    "name": self.owasp_mapping[cat_id]["name"],
                    "count": count
                }
                for cat_id, count in summary.items() if count > 0
            ]
        }
