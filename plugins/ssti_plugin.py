import logging
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)
PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "*{7*7}"]
DEFAULT_ENDPOINTS = [{"path": "/greet", "param": "name", "method": "GET"}, {"path": "/render", "param": "template", "method": "POST"}]


class SSTIScanner(BaseScanner):
    """Detect server-side template evaluation without executing arbitrary code."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []

    def configure(self, target: str) -> None:
        self.target = target
        self._tool_available = True

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        self.results = []
        for endpoint in endpoints[:20]:
            if not endpoint.get("param"):
                continue
            for payload in PAYLOADS:
                response = self._safe_request(
                    endpoint.get("method", "GET"),
                    f"{base_url}{endpoint['path']}",
                    params={endpoint["param"]: payload},
                    json_data={endpoint["param"]: payload},
                    allow_redirects=False,
                )
                if response is None:
                    continue
                if "49" in response.text and payload not in response.text:
                    self.results.append({"endpoint": f"{endpoint['path']}?{endpoint['param']}=<payload>", "payload": payload,
                                         "status_code": response.status_code, "evidence": response.text[:500]})
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = []
        for i, r in enumerate(self.results, 1):
            ep_str = r.get("endpoint", "")
            ep = ep_str.split("?")[0] if "?" in ep_str else ep_str
            param = ep_str.split("?")[1].split("=")[0] if "?" in ep_str and "=" in ep_str else "name"
            findings.append({
                "id": f"SSTI-{i:03d}", "title": f"Server-Side Template Injection ({r['endpoint']})", "severity": format_severity("Critical"),
                "host": host, "port": port, "description": f"The template expression {r['payload']} was evaluated to 49 at {r['endpoint']}.", "raw_output": r["evidence"],
                "owasp_tag": "A03:2021 Injection", "tool_name": "ssti_scanner", "confidence": "high",
                "vuln_type": "ssti",
                "endpoint": ep,
                "param": param,
                "method": "GET",
                "evidence": r.get("evidence"),
                "remediation": "Treat user input as data, never as a template; use context-safe rendering and disable access to filesystem, process, and reflection primitives."
            })
        return {"tool_name": "ssti_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "ssti_scanner", "findings": [{
            "id": "SSTI-001", "title": "Server-Side Template Injection (/greet?name=<payload>)", "severity": "Critical",
            "host": host, "port": port, "description": "The expression {{7*7}} was evaluated to 49 by the server-side template engine.", "raw_output": "Hello 49",
            "owasp_tag": "A03:2021 Injection", "tool_name": "ssti_scanner", "confidence": "high",
            "vuln_type": "ssti",
            "endpoint": "/greet",
            "param": "name",
            "method": "GET",
            "evidence": "Hello 49",
        }]}
