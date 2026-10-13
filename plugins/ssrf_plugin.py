import logging
import os
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)
URL_NAMES = {"url", "uri", "redirect", "dest", "destination", "src", "source", "feed", "callback", "webhook", "path", "file"}
LOOPBACK_PAYLOADS = ["http://127.0.0.1:80/", "http://localhost:80/"]
METADATA_PAYLOADS = ["http://169.254.169.254/latest/meta-data/"]
DEFAULT_ENDPOINTS = [{"path": "/fetch", "param": "url", "method": "GET"}, {"path": "/proxy", "param": "url", "method": "GET"}]


class SSRFScanner(BaseScanner):
    """Detect server-side URL fetching using safe loopback probes by default."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []

    def configure(self, target: str) -> None:
        self.target = target
        self._tool_available = True

    def _get_tool_name(self) -> str:
        return "python-requests"

    @staticmethod
    def _has_ssrf_evidence(
        response: requests.Response,
        payload: str,
        ctrl_text: Optional[str] = None,
        ctrl_status: Optional[int] = None,
    ) -> bool:
        import html as _html_mod
        body = (response.text or "").lower()
        p_lower = payload.lower()
        quoted_p = urllib.parse.quote(payload, safe="").lower()
        quoted_p_std = urllib.parse.quote(payload).lower()
        escaped_p = _html_mod.escape(payload).lower()
        body_without_payload = (
            body.replace(p_lower, "")
            .replace(quoted_p, "")
            .replace(quoted_p_std, "")
            .replace(escaped_p, "")
            .replace("127.0.0.1", "")
            .replace("localhost", "")
        )
        ctrl_lower = (ctrl_text or "").lower()
        markers = (
            "instance-id", "ami-id", "security-credentials",
            "simulated_internal_response", "ssh-", "root:x:0:0",
            "redis_version", "mysql_native_password",
            "connection refused", "failed to connect", "network unreachable",
            "internal service", "internal_banner", "private-metadata",
        )
        for marker in markers:
            if marker in body_without_payload and marker not in ctrl_lower:
                return True
        if response.status_code in (502, 504) and (ctrl_status is None or response.status_code != ctrl_status):
            return True
        return False

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        payloads = list(LOOPBACK_PAYLOADS)
        if os.environ.get("AUTOSEC_ENABLE_METADATA_PROBES", "false").lower() == "true":
            payloads += METADATA_PAYLOADS
        self.results = []

        get_endpoints = [ep for ep in endpoints if not self._is_form_endpoint(ep)][:20]
        form_endpoints = self._select_form_targets(
            [ep for ep in endpoints if self._is_form_endpoint(ep)],
            preferred_names=URL_NAMES,
        )

        for endpoint in get_endpoints:
            param = endpoint.get("param", "")
            path = endpoint.get("path", "")
            method = str(endpoint.get("method") or "GET").upper()
            if not param or not path or param.lower() not in URL_NAMES:
                continue
            url = f"{base_url}{path}"
            for payload in payloads:
                response = self._safe_request(
                    method,
                    url,
                    params={param: payload} if method == "GET" else None,
                    json_data={param: payload} if method != "GET" else None,
                    allow_redirects=False,
                )
                if response is None:
                    continue
                if self._has_ssrf_evidence(response, payload):
                    self.results.append({
                        "endpoint": f"{path}?{param}=<url>" if method == "GET" else path,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "status_code": response.status_code,
                        "evidence": response.text[:500],
                        "metadata": "169.254.169.254" in payload,
                    })
                    break

        reported_pairs = {(r.get("endpoint", "").split("?")[0], r.get("param")) for r in self.results}
        for endpoint in form_endpoints:
            path = endpoint.get("path", "")
            param = endpoint.get("param", "")
            method = str(endpoint.get("method") or "POST").upper()
            if not path or not param or (path, param) in reported_pairs:
                continue

            ctrl_resp = self.submit_form_probe(endpoint, param, "http://autosec-control.invalid/")
            ctrl_text = (ctrl_resp.text or "") if ctrl_resp is not None else ""
            ctrl_status = ctrl_resp.status_code if ctrl_resp is not None else None

            for payload in payloads:
                response = self.submit_form_probe(endpoint, param, payload)
                if response is None:
                    continue
                if self._has_ssrf_evidence(response, payload, ctrl_text=ctrl_text, ctrl_status=ctrl_status):
                    self.results.append({
                        "endpoint": path,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "status_code": response.status_code,
                        "evidence": response.text[:500],
                        "metadata": "169.254.169.254" in payload,
                    })
                    reported_pairs.add((path, param))
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = []
        for index, result in enumerate(self.results, 1):
            ep_str = result.get("endpoint", "")
            ep = ep_str.split("?")[0] if "?" in ep_str else ep_str
            param = result.get("param") or (ep_str.split("?")[1].split("=")[0] if "?" in ep_str and "=" in ep_str else "url")
            findings.append({"id": f"SSRF-{index:03d}",
                "title": f"Server-Side Request Forgery ({result['endpoint']})",
                "severity": format_severity("Critical" if result["metadata"] else "High"),
                "host": host, "port": port,
                "description": f"A URL parameter caused a response consistent with server-side access to an internal destination. Probe: {result['payload']}. HTTP {result['status_code']}.",
                "raw_output": result["evidence"], "owasp_tag": "A10:2021 Server-Side Request Forgery (SSRF)",
                "tool_name": "ssrf_scanner", "confidence": "high" if result["metadata"] else "medium",
                "vuln_type": "ssrf",
                "endpoint": ep,
                "param": param,
                "method": result.get("method", "GET"),
                "evidence": result.get("evidence"),
                "remediation": "Allowlist schemes, hosts, and ports; resolve and validate IPs after DNS resolution; block loopback, link-local, and private ranges; and disable redirects.",})
        return {"tool_name": "ssrf_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "ssrf_scanner", "findings": [{"id": "SSRF-001", "title": "SSRF via /fetch?url=<url>", "severity": "High",
            "host": host, "port": port, "description": "The URL fetcher returned content consistent with a loopback request.",
            "raw_output": "HTTP 502 upstream connection to 127.0.0.1", "owasp_tag": "A10:2021 Server-Side Request Forgery (SSRF)",
            "tool_name": "ssrf_scanner", "confidence": "medium",
            "vuln_type": "ssrf",
            "endpoint": "/fetch",
            "param": "url",
            "method": "GET",
            "evidence": "HTTP 502 upstream connection to 127.0.0.1",
        }]}
