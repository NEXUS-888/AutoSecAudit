import logging
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)
# Each payload multiplies two distinctive 4-digit numbers so the evaluated result (SSTI_MARKER) is a
# 7-digit string that is very unlikely to appear by chance in page markup, ids, hashes or timestamps.
# The old "7*7 -> 49" check matched the two digits "49" anywhere on the page and raised false positives.
SSTI_BASE_A = 1409
SSTI_BASE_B = 1423
SSTI_MARKER = str(SSTI_BASE_A * SSTI_BASE_B)  # "2005007"
_EXPR = f"{SSTI_BASE_A}*{SSTI_BASE_B}"
PAYLOADS = ["{{" + _EXPR + "}}", "${" + _EXPR + "}", "<%= " + _EXPR + " %>", "*{" + _EXPR + "}"]
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
        import html as _html_mod
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        self.results = []

        preferred = {"name", "template", "text", "view", "page", "content", "message", "title", "q"}
        get_endpoints = [ep for ep in endpoints if not self._is_form_endpoint(ep)][:20]
        form_endpoints = self._select_form_targets(
            [ep for ep in endpoints if self._is_form_endpoint(ep)],
            preferred_names=preferred,
        )

        for endpoint in get_endpoints:
            param = endpoint.get("param")
            path = endpoint.get("path", "")
            method = str(endpoint.get("method") or "GET").upper()
            if not param or not path:
                continue
            ctrl_resp = self._safe_request(
                method,
                f"{base_url}{path}",
                params={param: "safe123"} if method == "GET" else None,
                json_data={param: "safe123"} if method != "GET" else None,
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
                if (
                    SSTI_MARKER in response.text
                    and payload not in response.text
                    and _html_mod.escape(payload) not in response.text
                    and SSTI_MARKER not in ctrl_text
                ):
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

            ctrl_resp = self.submit_form_probe(endpoint, param, "safe123")
            ctrl_text = (ctrl_resp.text or "") if ctrl_resp is not None else ""

            for payload in PAYLOADS:
                response = self.submit_form_probe(endpoint, param, payload)
                if response is None:
                    continue
                if (
                    SSTI_MARKER in response.text
                    and payload not in response.text
                    and _html_mod.escape(payload) not in response.text
                    and SSTI_MARKER not in ctrl_text
                ):
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
            param = r.get("param") or (ep_str.split("?")[1].split("=")[0] if "?" in ep_str and "=" in ep_str else "name")
            findings.append({
                "id": f"SSTI-{i:03d}", "title": f"Server-Side Template Injection ({r['endpoint']})", "severity": format_severity("Critical"),
                "host": host, "port": port, "description": f"The template expression {r['payload']} was evaluated to 49 at {r['endpoint']}.", "raw_output": r["evidence"],
                "owasp_tag": "A03:2021 Injection", "tool_name": "ssti_scanner", "confidence": "high",
                "vuln_type": "ssti",
                "endpoint": ep,
                "param": param,
                "method": r.get("method", "GET"),
                "evidence": r.get("evidence"),
                "remediation": "Treat user input as data, never as a template; use context-safe rendering and disable access to filesystem, process, and reflection primitives."
            })
        return {"tool_name": "ssti_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "ssti_scanner", "findings": [{
            "id": "SSTI-001", "title": "Server-Side Template Injection (/greet?name=<payload>)", "severity": "Critical",
            "host": host, "port": port, "description": "The expression {{" + _EXPR + "}} was evaluated to " + SSTI_MARKER + " by the server-side template engine.", "raw_output": "Hello 49",
            "owasp_tag": "A03:2021 Injection", "tool_name": "ssti_scanner", "confidence": "high",
            "vuln_type": "ssti",
            "endpoint": "/greet",
            "param": "name",
            "method": "GET",
            "evidence": f"Hello {SSTI_MARKER}",
        }]}
