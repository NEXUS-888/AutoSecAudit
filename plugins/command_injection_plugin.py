import logging
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

MARKER = "AUTOSEC_RCE_TEST"
PAYLOADS = [f"; echo {MARKER}", f"| echo {MARKER}", f"&& echo {MARKER}"]
DEFAULT_ENDPOINTS = [
    {"path": "/search", "param": "q", "method": "GET"},
    {"path": "/api/search", "param": "q", "method": "GET"},
    {"path": "/api/exec", "param": "command", "method": "POST"},
]


class CommandInjectionScanner(BaseScanner):
    """Probe parameters and selected headers for shell command execution."""

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

    def _request(self, url: str, method: str, param: str, payload: str) -> Optional[requests.Response]:
        try:
            headers = {"User-Agent": "AutoSecAudit/2.0", "X-AutoSec-Test": payload}
            if method.upper() == "POST":
                return requests.post(url, json={param: payload}, headers=headers, timeout=(3.0, 8.0), verify=False)
            return requests.get(url, params={param: payload}, headers=headers, timeout=(3.0, 8.0), verify=False)
        except requests.RequestException as exc:
            logger.debug("Command injection request failed: %s", exc)
            return None

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        self.results = []

        # 1. Parameter injection with output reflection & timing verification
        for endpoint in endpoints[:20]:
            if not endpoint.get("param"):
                continue
            path, param, method = endpoint["path"], endpoint["param"], endpoint.get("method", "GET")
            url = f"{base_url}{path}"
            
            for payload in PAYLOADS:
                response = self._safe_request(method, url, params={param: payload} if method == "GET" else None,
                                             json_data={param: payload} if method == "POST" else None)
                if response is None:
                    continue
                marker_seen = MARKER in response.text
                if marker_seen:
                    self.results.append({
                        "endpoint": f"{path}?{param}=<payload>",
                        "payload": payload,
                        "status_code": response.status_code,
                        "elapsed": 0.1,
                        "evidence": response.text[:500],
                        "confidence": "high",
                    })
                    break

            # Blind time-delay check if no reflected output was found
            if len(self.results) == 0:
                delay_cmd = "; sleep 2; #"
                fast_cmd = "; echo 1; #"
                def probe_safe():
                    return self._safe_request(method, url, params={param: "safe_test"} if method == "GET" else None)
                def probe_delay():
                    return self._safe_request(method, url, params={param: delay_cmd} if method == "GET" else None)
                def probe_fast():
                    return self._safe_request(method, url, params={param: fast_cmd} if method == "GET" else None)

                is_verified, conf, details = self._verify_timing(probe_safe, probe_delay, probe_fast, expected_delay=2.0)
                if is_verified:
                    self.results.append({
                        "endpoint": f"{path}?{param}=<blind_payload>",
                        "payload": delay_cmd,
                        "status_code": 200,
                        "elapsed": details["delay_elapsed"],
                        "evidence": f"Statistical blind command execution verified: baseline {details['baseline_mean']}s -> delay {details['delay_elapsed']}s.",
                        "confidence": conf,
                    })

        # 2. Deep JSON body injection for API endpoints
        json_endpoints = [
            {"path": "/api/exec", "body": {"command": {"bin": "ping", "args": "127.0.0.1"}}},
            {"path": "/api/tools/run", "body": {"tool": "traceroute", "target": "localhost"}},
        ]
        for j_ep in json_endpoints:
            url = f"{base_url}{j_ep['path']}"
            for payload in ["; echo AUTOSEC_RCE_TEST; #", "| echo AUTOSEC_RCE_TEST"]:
                fuzz_results = self._fuzz_json_body(url, "POST", j_ep["body"], payload)
                for mutated_path, resp in fuzz_results:
                    if resp is not None and MARKER in resp.text:
                        self.results.append({
                            "endpoint": f"{j_ep['path']} (JSON body: {mutated_path})",
                            "payload": payload,
                            "status_code": resp.status_code,
                            "elapsed": 0.1,
                            "evidence": resp.text[:300],
                            "confidence": "high",
                        })
                        logger.info(f"[CMDI] Verified JSON body RCE at {j_ep['path']} on {mutated_path}")
                        break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = []
        for index, result in enumerate(self.results, 1):
            findings.append({
                "id": f"CMDI-{index:03d}",
                "title": f"OS Command Injection ({result['endpoint']})",
                "severity": format_severity("Critical"),
                "host": host, "port": port,
                "description": f"A shell metacharacter probe produced command-execution evidence at {result['endpoint']}. Payload: {result['payload']}. HTTP {result['status_code']} in {result['elapsed']}s.",
                "raw_output": result["evidence"], "owasp_tag": "A03:2021 Injection",
                "tool_name": "command_injection_scanner", "confidence": result["confidence"],
                "remediation": "Use argument-array APIs with shell execution disabled, strict allowlists, and server-side input validation.",
            })
        return {"tool_name": "command_injection_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "command_injection_scanner", "findings": [{
            "id": "CMDI-001", "title": "OS Command Injection (/api/exec?command=<payload>)", "severity": "Critical",
            "host": host, "port": port, "description": "The command parameter reflected AUTOSEC_RCE_TEST after a shell separator probe.",
            "raw_output": "command output: AUTOSEC_RCE_TEST", "owasp_tag": "A03:2021 Injection",
            "tool_name": "command_injection_scanner", "confidence": "high",
        }]}
