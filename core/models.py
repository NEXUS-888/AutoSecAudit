from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "scan_results": [s.to_dict() for s in self.scan_results],
            "all_findings": [f.to_dict() for f in self.all_findings],
            "summary": self.summary,
            "delta": self.delta,
            "previous_report_path": self.previous_report_path
        }
