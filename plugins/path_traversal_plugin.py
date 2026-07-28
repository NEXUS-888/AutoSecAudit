import logging
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)
PARAM_NAMES = {"file", "path", "page", "doc", "document", "template", "include", "filename", "download"}
PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
DEFAULT_ENDPOINTS = [{"path": "/download", "param": "file", "method": "GET"}, {"path": "/page", "param": "page", "method": "GET"}]


class PathTraversalScanner(BaseScanner):
    """Detect local file inclusion and path traversal indicators."""

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
            param = endpoint.get("param", "")
            if not param or param.lower() not in PARAM_NAMES:
                continue
            for payload in PAYLOADS:
                try:
                    response = requests.request(endpoint.get("method", "GET"), f"{base_url}{endpoint['path']}",
                                                params={param: payload}, json={param: payload},
                                                headers={"User-Agent": "AutoSecAudit/2.0"}, timeout=(3.0, 8.0),
                                                allow_redirects=False, verify=False)
                except requests.RequestException as exc:
                    logger.debug("Path traversal request failed: %s", exc)
                    continue
                body = response.text.lower()
                if "root:x:0:0:" in body or "[boot loader]" in body or "[fonts]" in body:
                    self.results.append({"endpoint": f"{endpoint['path']}?{param}=<payload>", "payload": payload,
                                         "status_code": response.status_code, "evidence": response.text[:500]})
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = [{"id": f"LFI-{i:03d}", "title": f"Local File Inclusion / Path Traversal ({r['endpoint']})", "severity": format_severity("High"),
            "host": host, "port": port, "description": f"A traversal payload returned recognizable local-file content at {r['endpoint']}. Payload: {r['payload']}.",
            "raw_output": r["evidence"], "owasp_tag": "A01:2021 Broken Access Control", "tool_name": "path_traversal_scanner", "confidence": "high",
            "remediation": "Resolve paths against a fixed base directory, reject traversal segments after decoding, and use opaque file identifiers instead of user-controlled paths."}
            for i, r in enumerate(self.results, 1)]
        return {"tool_name": "path_traversal_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "path_traversal_scanner", "findings": [{"id": "LFI-001", "title": "Local File Inclusion / Path Traversal (/download?file=<payload>)", "severity": "High",
            "host": host, "port": port, "description": "The file parameter returned /etc/passwd content after a traversal probe.", "raw_output": "root:x:0:0:root:/root:/bin/bash",
            "owasp_tag": "A01:2021 Broken Access Control", "tool_name": "path_traversal_scanner", "confidence": "high"}]}
