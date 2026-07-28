import logging
from typing import List, Dict, Any

from core.models import Finding

logger = logging.getLogger(__name__)

OWASP_MAPPING = {
    "A01:2021": {
        "name": "Broken Access Control",
        "keywords": ["access control", "authorization", "privilege", "idor", 
                     "vertical privilege", "horizontal privilege", "bypass"]
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
                     "injection", "script"]
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
        """Map each finding to OWASP, CWE, and PCI-DSS categories."""
        for f in findings:
            owasp_tag = self._find_owasp_category(f)
            if owasp_tag:
                f.owasp_tag = owasp_tag

            cwe, pci = self._find_cwe_pci(f)
            if cwe:
                f.cwe_id = cwe
            if pci:
                f.pci_dss = pci

        return findings

    def _find_cwe_pci(self, finding: Finding) -> tuple:
        text = f"{finding.title} {finding.description} {finding.tool_name}".lower()
        for key, (cwe, pci) in self.cwe_mapping.items():
            if key in text:
                return cwe, pci
        return None, None

    def _find_owasp_category(self, finding: Finding) -> str:
        text = f"{finding.title} {finding.description}".lower()

        for category_id, category_info in self.owasp_mapping.items():
            for keyword in category_info["keywords"]:
                if keyword in text:
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
