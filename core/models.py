from dataclasses import dataclass, field, asdict, fields
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
import hashlib
import re


class VulnType(str, Enum):
    """Documented taxonomy of vulnerability types for security findings."""
    SQLI = "sqli"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"
    RCE = "rce"
    IDOR = "idor"
    BOLA_IDOR = "bola_idor"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    MISCONFIG = "misconfig"
    SECRET_EXPOSURE = "secret_exposure"
    DIR_BRUTE = "dir_brute"
    AUTH = "auth"
    JWT = "jwt"
    API_ABUSE = "api_abuse"
    CORS = "cors"
    SSL_TLS = "ssl_tls"
    PORT_SCAN = "port_scan"
    INFO_DISCLOSURE = "info_disclosure"
    GENERIC = "generic"


def compute_finding_fingerprint(
    tool: Optional[str] = None,
    vuln_type: Optional[str] = None,
    method: Optional[str] = None,
    endpoint: Optional[str] = None,
    param: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """Compute sha256 fingerprint for a finding.
    
    Formula: sha256(tool|vuln_type|method|endpoint|param), falling back to
    sha256(tool|title) when structured fields are absent.
    """
    tool_val = tool or ""
    v = vuln_type or ""
    m = method or ""
    e = endpoint or ""
    p = param or ""
    if v or m or e or p:
        raw = f"{tool_val}|{v}|{m}|{e}|{p}"
    else:
        raw = f"{tool_val}|{title or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_endpoint_path(endpoint: Optional[str]) -> str:
    """Normalize endpoint paths, replacing numeric path segments with {id}."""
    if not endpoint:
        return "/"
    ep = str(endpoint).strip()
    if "?" in ep:
        ep = ep.split("?")[0]
    if " (" in ep:
        ep = ep.split(" (")[0]
    # Replace numeric segments: e.g. /123 -> /{id}
    ep = re.sub(r"/\d+(?=/|$)", "/{id}", ep)
    # Also normalize placeholder styles: <id>, <user_id>, {user_id}, <int:user_id> -> {id}
    ep = re.sub(r"/<[^>]+>(?=/|$)", "/{id}", ep)
    ep = re.sub(r"/\{[^}]+\}(?=/|$)", "/{id}", ep)
    if len(ep) > 1 and ep.endswith("/"):
        ep = ep.rstrip("/")
    return ep or "/"


def compute_canonical_key(
    vuln_type: Optional[str] = None,
    method: Optional[str] = None,
    endpoint: Optional[str] = None,
    param: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """Compute canonical deduplication key ignoring reporting tool.
    
    Formula: vuln_type|method|normalized_endpoint|param
    Numeric path segments in endpoint are normalized to {id}.
    """
    from intelligence.taxonomy import normalize_vuln_type_key, infer_taxonomy_from_text

    norm_ep = normalize_endpoint_path(endpoint)
    norm_method = (method or "GET").upper()

    # Strip URL-path artifacts from param
    p = (param or "").strip()
    if p == norm_ep or p.startswith("/") or p == endpoint:
        p = ""
    # Lowercase param for consistent cross-tool matching (e.g. security headers)
    p = p.lower()

    # Canonicalize vuln_type via taxonomy/alias mapping
    v = normalize_vuln_type_key(vuln_type) if vuln_type else None

    # Map generic/discovery scanner types (dir_brute, misconfig, generic, info_disclosure)
    # to specific vulnerability types via taxonomy inference from title.
    # Specific vulnerability types (such as sqli, xss, command_injection, ssrf, etc.) are preserved.
    GENERIC_DISCOVERY_TYPES = {"dir_brute", "dirbrute", "misconfig", "generic", "info_disclosure", None, ""}
    if v in GENERIC_DISCOVERY_TYPES and title:
        inferred = infer_taxonomy_from_text(title)
        if inferred and inferred.vuln_type:
            v = inferred.vuln_type

    v_str = v or "generic"
    return f"{v_str}|{norm_method}|{norm_ep}|{p}"


@dataclass
class Finding:
    """Represents a single security finding."""
    id: str
    title: str
    severity: str
    host: str
    port: int
    description: str
    raw_output: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: Optional[List[str]] = None
    owasp_tag: Optional[str] = None
    tool_name: Optional[str] = None
    confidence: str = "medium"  # high, medium, low
    remediation: Optional[str] = None  # how to fix this vulnerability
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    pci_dss: Optional[str] = None  # PCI-DSS v4.0 requirement mapping
    vuln_type: Optional[str] = None
    endpoint: Optional[str] = None
    param: Optional[str] = None
    method: Optional[str] = None
    evidence: Optional[str] = None
    fingerprint: Optional[str] = None
    original_severity: Optional[str] = None
    reporting_tools: Optional[List[str]] = None

    def __post_init__(self):
        if isinstance(self.vuln_type, Enum):
            self.vuln_type = self.vuln_type.value
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        return compute_finding_fingerprint(
            tool=self.tool_name,
            vuln_type=self.vuln_type,
            method=self.method,
            endpoint=self.endpoint,
            param=self.param,
            title=self.title,
        )

    def compute_canonical_key(self) -> str:
        return compute_canonical_key(
            vuln_type=self.vuln_type,
            method=self.method,
            endpoint=self.endpoint,
            param=self.param,
            title=self.title,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class ScanResult:
    """Represents results from a single scanner."""
    tool_name: str
    target: str
    timestamp: str
    findings: List[Finding] = field(default_factory=list)
    raw_output: Optional[str] = None
    status: str = "success"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output": self.raw_output,
            "status": self.status,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in data.get("findings", [])]
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields and k != "findings"}
        return cls(findings=findings, **filtered)


@dataclass
class Report:
    """Represents the final aggregated report."""
    target: str
    timestamp: str
    scan_results: List[ScanResult] = field(default_factory=list)
    all_findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    delta: Optional[Dict[str, Any]] = None
    previous_report_path: Optional[str] = None
    dev_environment: Optional[str] = None
    auth_status: Optional[str] = None
    throttled_requests: int = 0
    report_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "scan_results": [s.to_dict() for s in self.scan_results],
            "all_findings": [f.to_dict() for f in self.all_findings],
            "summary": self.summary,
            "delta": self.delta,
            "previous_report_path": self.previous_report_path,
            "dev_environment": self.dev_environment,
            "auth_status": self.auth_status,
            "throttled_requests": self.throttled_requests,
            "report_id": self.report_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Report":
        findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in data.get("all_findings", [])]
        results = [ScanResult.from_dict(s) if isinstance(s, dict) else s for s in data.get("scan_results", [])]
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields and k not in ("all_findings", "scan_results")}
        return cls(all_findings=findings, scan_results=results, **filtered)

