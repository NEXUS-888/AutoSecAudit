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

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        payloads = list(LOOPBACK_PAYLOADS)
        if os.environ.get("AUTOSEC_ENABLE_METADATA_PROBES", "false").lower() == "true":
            payloads += METADATA_PAYLOADS
        self.results = []
        for endpoint in endpoints[:20]:
            param = endpoint.get("param", "")
            if not param or param.lower() not in URL_NAMES:
                continue
            url = f"{base_url}{endpoint['path']}"
            for payload in payloads:
                response = self._safe_request(
                    endpoint.get("method", "GET"),
                    url,
                    params={param: payload},
                    json_data={param: payload},
                    allow_redirects=False,
                )
                if response is None:
                    continue
                body = response.text.lower()
                p_lower = payload.lower()
                quoted_p = urllib.parse.quote(payload, safe="").lower()
                quoted_p_std = urllib.parse.quote(payload).lower()
                body_without_payload = body.replace(p_lower, "").replace(quoted_p, "").replace(quoted_p_std, "")
                markers = (
                    "instance-id", "ami-id", "security-credentials",
                    "simulated_internal_response", "ssh-", "root:x:0:0",
                    "redis_version", "mysql_native_password",
                    "connection refused", "failed to connect", "network unreachable",
                )
                evidence = any(marker in body_without_payload for marker in markers)
                if not evidence and ("127.0.0.1" in body_without_payload or "localhost" in body_without_payload):
                    evidence = True
                if evidence or response.status_code in (502, 504):
                    self.results.append({"endpoint": f"{endpoint['path']}?{param}=<url>", "payload": payload,
                                         "status_code": response.status_code, "evidence": response.text[:500],
                                         "metadata": "169.254.169.254" in payload})
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = []
        for index, result in enumerate(self.results, 1):
            ep_str = result.get("endpoint", "")
            ep = ep_str.split("?")[0] if "?" in ep_str else ep_str
            param = ep_str.split("?")[1].split("=")[0] if "?" in ep_str and "=" in ep_str else "url"
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
                "method": "GET",
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
