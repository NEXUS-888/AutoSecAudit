import subprocess
import json
import logging
import re
from typing import Dict, Any, List, Optional

import config
from plugins.base_plugin import BaseScanner
from core.utils import format_severity

logger = logging.getLogger(__name__)


class NiktoPlugin(BaseScanner):
    """Nikto scanner plugin for web vulnerability scanning."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.raw_output: str = ""

    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        tool_name = self._get_tool_name()
        if not self.check_tool_available(tool_name):
            logger.warning(f"Nikto not available, skipping scan")
            return

        target = self._normalize_url(self.target)
        cmd = [
            config.NIKTO_PATH,
            "-h", target,
            "-Format", "txt",
            "-output", "-"
        ]

        try:
            logger.info(f"Running Nikto: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            self.raw_output = result.stdout
        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out")
            self.raw_output = ""
        except Exception as e:
            logger.error(f"Nikto execution error: {e}")
            self.raw_output = ""

    def parse_output(self) -> Dict[str, Any]:
        findings = []
        
        if not self.raw_output:
            return {"tool_name": "nikto", "findings": []}

        host = self._extract_host(self.target)
        
        lines = self.raw_output.split("\n")
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith("-" * 30):
                continue
            
            finding = self._parse_nikto_line(line, host)
            if finding:
                findings.append(finding)

        return {"tool_name": "nikto", "findings": findings}

    def _parse_nikto_line(self, line: str, host: str) -> Optional[Dict[str, Any]]:
        nikto_pattern = r"^\+ (.+?)(?:\s+-\s+(.+))?$"
        match = re.match(nikto_pattern, line)
        
        if not match:
            return None
        
        title = match.group(1).strip()
        description = match.group(2).strip() if match.group(2) else ""
        
        cve_id = self._extract_cve(title + " " + description)
        severity = self._assess_severity(title, description)
        
        finding_id = f"NIKTO-{len(title[:20])}"
        
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "host": host,
            "port": 80,
            "description": description,
            "cve_id": cve_id,
            "raw_output": line[:500]
        }

    def _extract_cve(self, text: str) -> Optional[str]:
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        match = re.search(cve_pattern, text)
        return match.group(0) if match else None

    def _assess_severity(self, title: str, description: str) -> str:
        text = (title + " " + description).lower()
        
        high_keywords = ["sql injection", "xss", "cross-site scripting", 
                        "command injection", "remote code", "authentication",
                        "default credential", "path traversal"]
        medium_keywords = ["information disclosure", "missing header", 
                          "clickjacking", "csrf", "cookie"]
        
        if any(kw in text for kw in high_keywords):
            return "High"
        if any(kw in text for kw in medium_keywords):
            return "Medium"
        
        return "Low"

    def _normalize_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target.rstrip("/")

    def _extract_host(self, target: str) -> str:
        target = re.sub(r"^https?://", "", target)
        target = target.split("/")[0]
        target = target.split(":")[0]
        return target

    def _get_tool_name(self) -> str:
        return config.NIKTO_PATH

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "nikto",
            "findings": [
                {
                    "id": "NIKTO-001",
                    "title": "Server may reveal internal IP via headers",
                    "severity": "Low",
                    "host": self._extract_host(self.target),
                    "port": 80,
                    "description": "The server leaks internal IP via certain headers",
                    "raw_output": "+ Server may reveal internal IP via headers - Nikto v2.1.6"
                },
                {
                    "id": "NIKTO-002",
                    "title": "Missing Content-Type header",
                    "severity": "Low",
                    "host": self._extract_host(self.target),
                    "port": 80,
                    "description": "Response lacks Content-Type header",
                    "raw_output": "+ Missing Content-Type header - Nikto v2.1.6"
                },
                {
                    "id": "NIKTO-003",
                    "title": "Directory indexing enabled",
                    "severity": "Medium",
                    "host": self._extract_host(self.target),
                    "port": 80,
                    "description": "Directory listing may be available",
                    "raw_output": "+ Directory indexing enabled - Nikto v2.1.6"
                },
                {
                    "id": "NIKTO-004",
                    "title": "XSS in query parameter",
                    "severity": "High",
                    "host": self._extract_host(self.target),
                    "port": 80,
                    "description": "Potential XSS vulnerability in query parameters",
                    "cve_id": "CVE-2021-12345",
                    "raw_output": "+ XSS via query parameter - Nikto v2.1.6"
                },
                {
                    "id": "NIKTO-005",
                    "title": "SQL Injection possible",
                    "severity": "High",
                    "host": self._extract_host(self.target),
                    "port": 80,
                    "description": "Potential SQL injection vulnerability detected",
                    "cve_id": "CVE-2021-99999",
                    "raw_output": "+ SQL Injection possible - Nikto v2.1.6"
                }
            ]
        }
