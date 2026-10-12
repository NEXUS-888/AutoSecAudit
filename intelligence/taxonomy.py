"""
Unified vulnerability taxonomy and classification metadata for AutoSecAudit.

Provides a canonical mapping from VulnType to OWASP Top 10, CWE, PCI-DSS v4.0,
business threat category, remediation key, recipe key, and default severity.
Also provides word-boundary regex fallback classifiers.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Any, Union
import re
from core.models import VulnType

# Core business threat categories (matching danger_engine)
CATEGORY_CUSTOMER_DATA = "customer_data_theft"
CATEGORY_ACCOUNT_TAKEOVER = "account_takeover"
CATEGORY_PHISHING_DEFACEMENT = "phishing_defacement"
CATEGORY_SERVER_CONTROL = "server_control"


@dataclass(frozen=True)
class TaxonomyEntry:
    vuln_type: str
    owasp: str
    cwe: str
    pci: str
    danger_category: str
    remediation_key: str
    recipe_key: str
    default_severity: str = "Medium"


# Canonical taxonomy mapping for all VulnType values
TAXONOMY_ENTRIES: Dict[str, TaxonomyEntry] = {
    VulnType.SQLI.value: TaxonomyEntry(
        vuln_type=VulnType.SQLI.value,
        owasp="A03:2021",
        cwe="CWE-89",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_CUSTOMER_DATA,
        remediation_key="sqli",
        recipe_key="sqli",
        default_severity="Critical",
    ),
    VulnType.XSS.value: TaxonomyEntry(
        vuln_type=VulnType.XSS.value,
        owasp="A03:2021",
        cwe="CWE-79",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="xss",
        recipe_key="xss",
        default_severity="High",
    ),
    VulnType.COMMAND_INJECTION.value: TaxonomyEntry(
        vuln_type=VulnType.COMMAND_INJECTION.value,
        owasp="A03:2021",
        cwe="CWE-78",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_SERVER_CONTROL,
        remediation_key="command_injection",
        recipe_key="command_injection",
        default_severity="Critical",
    ),
    VulnType.RCE.value: TaxonomyEntry(
        vuln_type=VulnType.RCE.value,
        owasp="A03:2021",
        cwe="CWE-78",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_SERVER_CONTROL,
        remediation_key="command_injection",
        recipe_key="command_injection",
        default_severity="Critical",
    ),
    VulnType.SSRF.value: TaxonomyEntry(
        vuln_type=VulnType.SSRF.value,
        owasp="A10:2021",
        cwe="CWE-918",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_SERVER_CONTROL,
        remediation_key="ssrf",
        recipe_key="ssrf",
        default_severity="High",
    ),
    VulnType.SSTI.value: TaxonomyEntry(
        vuln_type=VulnType.SSTI.value,
        owasp="A03:2021",
        cwe="CWE-1336",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_SERVER_CONTROL,
        remediation_key="ssti",
        recipe_key="ssti",
        default_severity="High",
    ),
    VulnType.IDOR.value: TaxonomyEntry(
        vuln_type=VulnType.IDOR.value,
        owasp="A01:2021",
        cwe="CWE-639",
        pci="PCI-DSS 6.5.8",
        danger_category=CATEGORY_ACCOUNT_TAKEOVER,
        remediation_key="idor",
        recipe_key="idor",
        default_severity="High",
    ),
    VulnType.BOLA_IDOR.value: TaxonomyEntry(
        vuln_type=VulnType.BOLA_IDOR.value,
        owasp="A01:2021",
        cwe="CWE-639",
        pci="PCI-DSS 6.5.8",
        danger_category=CATEGORY_ACCOUNT_TAKEOVER,
        remediation_key="idor",
        recipe_key="idor",
        default_severity="High",
    ),
    VulnType.CSRF.value: TaxonomyEntry(
        vuln_type=VulnType.CSRF.value,
        owasp="A01:2021",
        cwe="CWE-352",
        pci="PCI-DSS 6.4.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="csrf",
        recipe_key="csrf",
        default_severity="Medium",
    ),
    VulnType.OPEN_REDIRECT.value: TaxonomyEntry(
        vuln_type=VulnType.OPEN_REDIRECT.value,
        owasp="A01:2021",
        cwe="CWE-601",
        pci="PCI-DSS 6.4.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="open_redirect",
        recipe_key="open_redirect",
        default_severity="Medium",
    ),
    VulnType.PATH_TRAVERSAL.value: TaxonomyEntry(
        vuln_type=VulnType.PATH_TRAVERSAL.value,
        owasp="A01:2021",
        cwe="CWE-22",
        pci="PCI-DSS 6.2.4",
        danger_category=CATEGORY_CUSTOMER_DATA,
        remediation_key="path_traversal",
        recipe_key="path_traversal",
        default_severity="High",
    ),
    VulnType.DIR_BRUTE.value: TaxonomyEntry(
        vuln_type=VulnType.DIR_BRUTE.value,
        owasp="A05:2021",
        cwe="CWE-538",
        pci="PCI-DSS 6.5.1",
        danger_category=CATEGORY_CUSTOMER_DATA,
        remediation_key="dir_brute",
        recipe_key="dir_brute",
        default_severity="Medium",
    ),
    VulnType.SECRET_EXPOSURE.value: TaxonomyEntry(
        vuln_type=VulnType.SECRET_EXPOSURE.value,
        owasp="A05:2021",
        cwe="CWE-312",
        pci="PCI-DSS 6.5.1",
        danger_category=CATEGORY_CUSTOMER_DATA,
        remediation_key="secret_exposure",
        recipe_key="secret_exposure",
        default_severity="High",
    ),
    VulnType.MISCONFIG.value: TaxonomyEntry(
        vuln_type=VulnType.MISCONFIG.value,
        owasp="A05:2021",
        cwe="CWE-16",
        pci="PCI-DSS 2.2.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="misconfig",
        recipe_key="misconfig",
        default_severity="Low",
    ),
    VulnType.INFO_DISCLOSURE.value: TaxonomyEntry(
        vuln_type=VulnType.INFO_DISCLOSURE.value,
        owasp="A05:2021",
        cwe="CWE-200",
        pci="PCI-DSS 2.2.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="info_disclosure",
        recipe_key="info_disclosure",
        default_severity="Low",
    ),
    VulnType.CORS.value: TaxonomyEntry(
        vuln_type=VulnType.CORS.value,
        owasp="A05:2021",
        cwe="CWE-942",
        pci="PCI-DSS 6.4.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="cors",
        recipe_key="cors",
        default_severity="Medium",
    ),
    VulnType.SSL_TLS.value: TaxonomyEntry(
        vuln_type=VulnType.SSL_TLS.value,
        owasp="A02:2021",
        cwe="CWE-319",
        pci="PCI-DSS 4.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="ssl_tls",
        recipe_key="ssl_tls",
        default_severity="Low",
    ),
    VulnType.AUTH.value: TaxonomyEntry(
        vuln_type=VulnType.AUTH.value,
        owasp="A07:2021",
        cwe="CWE-287",
        pci="PCI-DSS 8.2.1",
        danger_category=CATEGORY_ACCOUNT_TAKEOVER,
        remediation_key="auth",
        recipe_key="auth",
        default_severity="High",
    ),
    VulnType.JWT.value: TaxonomyEntry(
        vuln_type=VulnType.JWT.value,
        owasp="A02:2021",
        cwe="CWE-347",
        pci="PCI-DSS 8.3.1",
        danger_category=CATEGORY_ACCOUNT_TAKEOVER,
        remediation_key="jwt",
        recipe_key="jwt",
        default_severity="High",
    ),
    VulnType.API_ABUSE.value: TaxonomyEntry(
        vuln_type=VulnType.API_ABUSE.value,
        owasp="A01:2021",
        cwe="CWE-285",
        pci="PCI-DSS 6.5.8",
        danger_category=CATEGORY_ACCOUNT_TAKEOVER,
        remediation_key="api_abuse",
        recipe_key="api_abuse",
        default_severity="Medium",
    ),
    VulnType.PORT_SCAN.value: TaxonomyEntry(
        vuln_type=VulnType.PORT_SCAN.value,
        owasp="A05:2021",
        cwe="CWE-200",
        pci="PCI-DSS 2.2.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="port_scan",
        recipe_key="port_scan",
        default_severity="Info",
    ),
    VulnType.GENERIC.value: TaxonomyEntry(
        vuln_type=VulnType.GENERIC.value,
        owasp="A05:2021",
        cwe="CWE-16",
        pci="PCI-DSS 2.2.1",
        danger_category=CATEGORY_PHISHING_DEFACEMENT,
        remediation_key="generic",
        recipe_key="generic",
        default_severity="Info",
    ),
}

# Alias dictionary for common variants and plugin keys
TAXONOMY_ALIASES: Dict[str, str] = {
    "dirbrute": VulnType.DIR_BRUTE.value,
    "dir_bruteforce": VulnType.DIR_BRUTE.value,
    "directory_bruteforce": VulnType.DIR_BRUTE.value,
    "command injection": VulnType.COMMAND_INJECTION.value,
    "cmd_injection": VulnType.COMMAND_INJECTION.value,
    "path traversal": VulnType.PATH_TRAVERSAL.value,
    "open redirect": VulnType.OPEN_REDIRECT.value,
    "sql injection": VulnType.SQLI.value,
    "cross-site scripting": VulnType.XSS.value,
    "cross site scripting": VulnType.XSS.value,
    "bola": VulnType.BOLA_IDOR.value,
    "broken object level authorization": VulnType.BOLA_IDOR.value,
    "idor": VulnType.IDOR.value,
    "tls": VulnType.SSL_TLS.value,
    "ssl": VulnType.SSL_TLS.value,
}


def normalize_vuln_type_key(key: Optional[str]) -> Optional[str]:
    """Normalize a vuln_type string or enum key."""
    if not key:
        return None
    if hasattr(key, "value"):
        key = key.value
    k = str(key).strip().lower().replace("-", "_")
    return TAXONOMY_ALIASES.get(k, k)


def get_taxonomy(vuln_type: Optional[Union[str, VulnType]]) -> Optional[TaxonomyEntry]:
    """Look up canonical taxonomy entry by vuln_type."""
    if not vuln_type:
        return None
    norm = normalize_vuln_type_key(vuln_type)
    if not norm:
        return None
    if norm in TAXONOMY_ENTRIES:
        return TAXONOMY_ENTRIES[norm]
    # Check normalized space variant
    space_norm = norm.replace("_", " ")
    if space_norm in TAXONOMY_ALIASES:
        return TAXONOMY_ENTRIES.get(TAXONOMY_ALIASES[space_norm])
    return None


# ---------------------------------------------------------------------------
# Word-boundary Regex Fallback Classifier
# ---------------------------------------------------------------------------
# Ordered by specificity to avoid false positives (e.g. sqli before generic bypass)
FALLBACK_RULES = [
    # 1. SQL Injection
    (re.compile(r"\b(sqli|sql injection|blind sql|union select)\b", re.IGNORECASE), VulnType.SQLI.value),
    # 2. Command Injection / RCE
    (re.compile(r"\b(rce|remote code execution|command injection|code injection|os command)\b", re.IGNORECASE), VulnType.COMMAND_INJECTION.value),
    # 3. SSRF
    (re.compile(r"\b(ssrf|server-side request forgery)\b", re.IGNORECASE), VulnType.SSRF.value),
    # 4. SSTI
    (re.compile(r"\b(ssti|server-side template injection|template injection)\b", re.IGNORECASE), VulnType.SSTI.value),
    # 5. XSS
    (re.compile(r"\b(xss|cross-site scripting|reflected xss|stored xss|dom xss)\b", re.IGNORECASE), VulnType.XSS.value),
    # 6. CSRF
    (re.compile(r"\b(csrf|cross-site request forgery)\b", re.IGNORECASE), VulnType.CSRF.value),
    # 7. IDOR / BOLA
    (re.compile(r"\b(idor|bola|broken object level authorization|insecure direct object reference)\b", re.IGNORECASE), VulnType.BOLA_IDOR.value),
    # 8. Open Redirect
    (re.compile(r"\b(open redirect|url redirection|open url redirect)\b", re.IGNORECASE), VulnType.OPEN_REDIRECT.value),
    # 9. Path Traversal
    (re.compile(r"\b(path traversal|directory traversal|lfi|local file inclusion)\b", re.IGNORECASE), VulnType.PATH_TRAVERSAL.value),
    # 10. JWT
    (re.compile(r"\b(jwt|json web token)\b", re.IGNORECASE), VulnType.JWT.value),
    # 11. CORS
    (re.compile(r"\b(cors|cross-origin resource sharing|cors wildcard)\b", re.IGNORECASE), VulnType.CORS.value),
    # 12. Secret Exposure (handles .env and .git without requiring preceding word character)
    (re.compile(r"(?:(?<![\w.])\.(?:env|git)\b|\b(?:secret exposure|api key leak|exposed secret|private key)\b)", re.IGNORECASE), VulnType.SECRET_EXPOSURE.value),
    # 13. Directory Brute-force / Sensitive files
    (re.compile(r"\b(dirbrute|directory brute|directory listing|sensitive path|exposed directory)\b", re.IGNORECASE), VulnType.DIR_BRUTE.value),
    # 14. SSL / TLS
    (re.compile(r"\b(ssl|tls|hsts|weak cipher|certificate)\b", re.IGNORECASE), VulnType.SSL_TLS.value),
    # 15. Authentication & Login Weakness (Strict \bauth\b to NOT match oauth)
    (re.compile(r"\b(brute force|credential stuffing|broken authentication|weak password|session fixation|login bypass)\b", re.IGNORECASE), VulnType.AUTH.value),
    (re.compile(r"\bauth\b", re.IGNORECASE), VulnType.AUTH.value),
    # 16. Misconfig & Security Headers / CSP / Clickjacking
    (
        re.compile(
            r"\b(misconfiguration|security misconfig|server header leak|"
            r"content-security-policy|csp|x-frame-options|clickjacking|security headers?|"
            r"\w+ header missing|missing [\w-]+ header|missing header)\b",
            re.IGNORECASE,
        ),
        VulnType.MISCONFIG.value,
    ),
    # 17. Info Disclosure
    (re.compile(r"\b(information disclosure|info disclosure|verbose error|stack trace leak)\b", re.IGNORECASE), VulnType.INFO_DISCLOSURE.value),
    # 18. API Abuse
    (re.compile(r"\b(api abuse|rate limit|missing rate limit)\b", re.IGNORECASE), VulnType.API_ABUSE.value),
]


def infer_taxonomy_from_text(text: str) -> Optional[TaxonomyEntry]:
    """
    Infer taxonomy entry from free text (title/description) using word-boundary regexes.
    Ignores '[Dev Environment Artifact]' tags to prevent false matches on 'env'.
    Replaces underscores with spaces so tool names like sqli_scanner match word boundaries.
    """
    if not text:
        return None
    # Clean dev environment artifact markers
    clean_text = re.sub(r"\[Dev Environment Artifact\]", "", text, flags=re.IGNORECASE)
    norm_text = clean_text.replace("_", " ")
    for pattern, vuln_key in FALLBACK_RULES:
        if pattern.search(norm_text):
            return TAXONOMY_ENTRIES.get(vuln_key)
    return None
