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
    def _has_lfi_evidence(text: str, ctrl_text: Optional[str] = None) -> bool:
        body = (text or "").lower()
        ctrl = (ctrl_text or "").lower()
        for sig in ("root:x:0:0:", "root:x:0:0", "[boot loader]", "[fonts]", "[extensions]"):
            if sig in body and sig not in ctrl:
                return True
        return False

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        self.results = []

        get_endpoints = [ep for ep in endpoints if not self._is_form_endpoint(ep)][:20]
        form_endpoints = self._select_form_targets(
            [ep for ep in endpoints if self._is_form_endpoint(ep)],
            preferred_names=PARAM_NAMES,
        )

        for endpoint in get_endpoints:
            param = endpoint.get("param", "")
            path = endpoint.get("path", "")
            method = str(endpoint.get("method") or "GET").upper()
            if not param or not path or param.lower() not in PARAM_NAMES:
                continue
            ctrl_resp = self._safe_request(
                method,
                f"{base_url}{path}",
                params={param: "readme.txt"} if method == "GET" else None,
                json_data={param: "readme.txt"} if method != "GET" else None,
                allow_redirects=False,
            )
            ctrl_text = (ctrl_resp.text or "") if ctrl_resp is not None else ""
            for payload in PAYLOADS:
                response = self._safe_request(
                    method,
                    f"{base_url}{path}",
                    params={param: payload} if method == "GET" else None,
                    json_data={param: payload} if method != "GET" else None,
                    allow_redirects=False,
                )
                if response is None:
                    continue
                if self._has_lfi_evidence(response.text, ctrl_text=ctrl_text):
                    self.results.append({
                        "endpoint": f"{path}?{param}=<payload>" if method == "GET" else path,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "status_code": response.status_code,
                        "evidence": response.text[:500],
                    })
                    break

        reported_pairs = {(r.get("endpoint", "").split("?")[0], r.get("param")) for r in self.results}
        for endpoint in form_endpoints:
            path = endpoint.get("path", "")
            param = endpoint.get("param", "")
            method = str(endpoint.get("method") or "POST").upper()
            if not path or not param or (path, param) in reported_pairs:
                continue

            ctrl_resp = self.submit_form_probe(endpoint, param, "readme.txt")
            ctrl_text = (ctrl_resp.text or "") if ctrl_resp is not None else ""

            for payload in PAYLOADS:
                response = self.submit_form_probe(endpoint, param, payload)
                if response is None:
                    continue
                if self._has_lfi_evidence(response.text, ctrl_text=ctrl_text):
                    self.results.append({
                        "endpoint": path,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "status_code": response.status_code,
                        "evidence": response.text[:500],
                    })
                    reported_pairs.add((path, param))
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = []
        for i, r in enumerate(self.results, 1):
            ep_str = r.get("endpoint", "")
            ep = ep_str.split("?")[0] if "?" in ep_str else ep_str
            param = r.get("param") or (ep_str.split("?")[1].split("=")[0] if "?" in ep_str and "=" in ep_str else "file")
            findings.append({
                "id": f"LFI-{i:03d}",
                "title": f"Local File Inclusion / Path Traversal ({r['endpoint']})",
                "severity": format_severity("High"),
                "host": host, "port": port,
                "description": f"A traversal payload returned recognizable local-file content at {r['endpoint']}. Payload: {r['payload']}.",
                "raw_output": r["evidence"], "owasp_tag": "A01:2021 Broken Access Control",
                "tool_name": "path_traversal_scanner", "confidence": "high",
                "vuln_type": "path_traversal",
                "endpoint": ep,
                "param": param,
                "method": r.get("method", "GET"),
                "evidence": r.get("evidence"),
                "remediation": "Resolve paths against a fixed base directory, reject traversal segments after decoding, and use opaque file identifiers instead of user-controlled paths."
            })
        return {"tool_name": "path_traversal_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "path_traversal_scanner", "findings": [{
            "id": "LFI-001", "title": "Local File Inclusion / Path Traversal (/download?file=<payload>)", "severity": "High",
            "host": host, "port": port, "description": "The file parameter returned /etc/passwd content after a traversal probe.", "raw_output": "root:x:0:0:root:/root:/bin/bash",
            "owasp_tag": "A01:2021 Broken Access Control", "tool_name": "path_traversal_scanner", "confidence": "high",
            "vuln_type": "path_traversal",
            "endpoint": "/download",
            "param": "file",
            "method": "GET",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
        }]}
