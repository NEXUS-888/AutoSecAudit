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

    @staticmethod
    def _parse_target(target: str):
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}", parsed.hostname or "unknown", parsed.port or (443 if parsed.scheme == "https" else 80)

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        self.results = []
        for endpoint in endpoints[:20]:
            if not endpoint.get("param"):
                continue
            for payload in PAYLOADS:
                try:
                    response = requests.request(endpoint.get("method", "GET"), f"{base_url}{endpoint['path']}",
                                                params={endpoint["param"]: payload}, json={endpoint["param"]: payload},
                                                headers={"User-Agent": "AutoSecAudit/2.0"}, timeout=8,
                                                allow_redirects=False, verify=False)
                except requests.RequestException as exc:
                    logger.debug("SSTI request failed: %s", exc)
                    continue
                if "49" in response.text and payload not in response.text:
                    self.results.append({"endpoint": f"{endpoint['path']}?{endpoint['param']}=<payload>", "payload": payload,
                                         "status_code": response.status_code, "evidence": response.text[:500]})
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = [{"id": f"SSTI-{i:03d}", "title": f"Server-Side Template Injection ({r['endpoint']})", "severity": format_severity("Critical"),
            "host": host, "port": port, "description": f"The template expression {r['payload']} was evaluated to 49 at {r['endpoint']}.", "raw_output": r["evidence"],
            "owasp_tag": "A03:2021 Injection", "tool_name": "ssti_scanner", "confidence": "high",
            "remediation": "Treat user input as data, never as a template; use context-safe rendering and disable access to filesystem, process, and reflection primitives."}
            for i, r in enumerate(self.results, 1)]
        return {"tool_name": "ssti_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "ssti_scanner", "findings": [{"id": "SSTI-001", "title": "Server-Side Template Injection (/greet?name=<payload>)", "severity": "Critical",
            "host": host, "port": port, "description": "The expression {{7*7}} was evaluated to 49 by the server-side template engine.", "raw_output": "Hello 49",
            "owasp_tag": "A03:2021 Injection", "tool_name": "ssti_scanner", "confidence": "high"}]}
