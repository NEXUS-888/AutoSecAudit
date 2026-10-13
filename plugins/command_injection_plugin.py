import logging
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import re
import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

MARKER = "AUTOSEC_RCE_TEST"
PAYLOAD_PROBES = [
    ("; echo AUTOSEC_$((6*7))_RCE; #", "AUTOSEC_42_RCE"),
    ("| echo AUTOSEC_$((6*7))_RCE", "AUTOSEC_42_RCE"),
    ("; echo AUTOSEC_RCE_TEST; #", "command output: AUTOSEC_RCE_TEST"),
    ("| echo AUTOSEC_RCE_TEST", "command output: AUTOSEC_RCE_TEST"),
]
PAYLOADS = [p[0] for p in PAYLOAD_PROBES]
DEFAULT_ENDPOINTS = [
    {"path": "/search", "param": "q", "method": "GET"},
    {"path": "/api/search", "param": "q", "method": "GET"},
    {"path": "/api/exec", "param": "command", "method": "POST"},
]


def check_command_exec_proof(
    resp_text: str,
    expected_output: Optional[str] = None,
    control_text: Optional[str] = None,
) -> bool:
    """Verify response contains execution proof absent from control."""
    if not resp_text:
        return False

    proof_signatures = []
    if expected_output:
        proof_signatures.append(("exact", expected_output))
    proof_signatures.extend([
        ("exact", "AUTOSEC_42_RCE"),
        ("exact", "command output: AUTOSEC_RCE_TEST"),
        ("exact", "uid=0(root)"),
        ("regex", r"uid=\d+\(\w+\)\s+gid=\d+"),
        ("exact", "root:x:0:0"),
        ("exact", "Windows IP Configuration"),
    ])

    for sig_type, sig_val in proof_signatures:
        in_resp = False
        if sig_type == "exact":
            in_resp = sig_val in resp_text
        elif sig_type == "regex":
            in_resp = bool(re.search(sig_val, resp_text))

        if in_resp:
            if control_text is not None:
                in_control = False
                if sig_type == "exact":
                    in_control = sig_val in control_text
                elif sig_type == "regex":
                    in_control = bool(re.search(sig_val, control_text))
                if in_control:
                    continue  # Proof signature was already in control, discard!
            return True

    return False


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

    def _request(self, url: str, method: str, param: str, payload: str) -> Optional[requests.Response]:
        headers = {"X-AutoSec-Test": payload}
        if method.upper() == "POST":
            return self._safe_request("POST", url, json_data={param: payload}, headers=headers, timeout=(3.0, 8.0))
        return self._safe_request("GET", url, params={param: payload}, headers=headers, timeout=(3.0, 8.0))

    def run(self) -> None:
        base_url, _, _ = self._parse_target(self.target)
        endpoints = self.discovered_endpoints or DEFAULT_ENDPOINTS
        self.results = []

        # 1. Parameter injection with output execution verification
        for endpoint in endpoints[:20]:
            if not endpoint.get("param"):
                continue
            path, param, method = endpoint["path"], endpoint["param"], endpoint.get("method", "GET")
            url = f"{base_url}{path}"
            m_upper = method.upper()

            if m_upper == "GET":
                req_modes = [lambda val, p=param: {"params": {p: val}}]
            else:
                req_modes = [
                    lambda val, p=param: {"json_data": {p: val}},
                    lambda val, p=param: {"data": {p: val}},
                ]

            inert_token = "AUTOSEC_INERT_PROBE"
            hit = False
            for make_kw in req_modes:
                if hit:
                    break
                # Measure baseline with an inert probe using the same body/param encoding
                inert_resp = self._safe_request(m_upper, url, **make_kw(inert_token))
                inert_text = inert_resp.text if inert_resp is not None else None

                for payload, expected_output in PAYLOAD_PROBES:
                    response = self._safe_request(m_upper, url, **make_kw(payload))
                    if response is None:
                        continue

                    # Execution verification: response must contain proof of execution
                    # that is absent from the inert control response.
                    has_exec_proof = check_command_exec_proof(
                        response.text,
                        expected_output=expected_output,
                        control_text=inert_text,
                    )

                    if has_exec_proof:
                        conf = "high" if inert_resp is not None else "medium"
                        self.results.append({
                            "endpoint": f"{path}?{param}=<payload>",
                            "param": param,
                            "method": m_upper,
                            "payload": payload,
                            "status_code": response.status_code,
                            "elapsed": 0.1,
                            "evidence": response.text[:500],
                            "confidence": conf,
                        })
                        hit = True
                        break

            # Blind time-delay check if no verified output was found
            if not hit and len(self.results) == 0:
                delay_cmd = "; sleep 2; #"
                fast_cmd = "; echo 1; #"
                for make_kw in req_modes:
                    def probe_safe(mk=make_kw):
                        return self._safe_request(m_upper, url, **mk("safe_test"))
                    def probe_delay(mk=make_kw):
                        return self._safe_request(m_upper, url, **mk(delay_cmd))
                    def probe_fast(mk=make_kw):
                        return self._safe_request(m_upper, url, **mk(fast_cmd))

                    is_verified, conf, details = self._verify_timing(probe_safe, probe_delay, probe_fast, expected_delay=2.0)
                    if is_verified:
                        self.results.append({
                            "endpoint": f"{path}?{param}=<blind_payload>",
                            "param": param,
                            "method": m_upper,
                            "payload": delay_cmd,
                            "status_code": 200,
                            "elapsed": details["delay_elapsed"],
                            "evidence": f"Statistical blind command execution verified: baseline {details['baseline_mean']}s -> delay {details['delay_elapsed']}s.",
                            "confidence": conf,
                        })
                        break

        # 2. Deep JSON body injection for API endpoints
        json_endpoints = [
            {"path": "/api/exec", "body": {"command": {"bin": "ping", "args": "127.0.0.1"}}},
            {"path": "/api/tools/run", "body": {"tool": "traceroute", "target": "localhost"}},
        ]
        reported_paths = {r.get("endpoint", "").split("?")[0].split(" ")[0] for r in self.results}
        for j_ep in json_endpoints:
            if j_ep["path"] in reported_paths:
                continue
            url = f"{base_url}{j_ep['path']}"
            j_inert = self._safe_request("POST", url, json_data=j_ep["body"])
            j_inert_text = j_inert.text if j_inert is not None else None
            j_hit = False
            for payload, expected_output in PAYLOAD_PROBES:
                fuzz_results = self._fuzz_json_body(url, "POST", j_ep["body"], payload)
                for mutated_path, resp in fuzz_results:
                    if resp is not None:
                        has_exec = check_command_exec_proof(
                            resp.text,
                            expected_output=expected_output,
                            control_text=j_inert_text,
                        )
                        if has_exec:
                            conf = "high" if j_inert is not None else "medium"
                            self.results.append({
                                "endpoint": f"{j_ep['path']} (JSON body: {mutated_path})",
                                "param": "command",
                                "method": "POST",
                                "payload": payload,
                                "status_code": resp.status_code,
                                "elapsed": 0.1,
                                "evidence": resp.text[:300],
                                "confidence": conf,
                            })
                            logger.info(f"[CMDI] Verified JSON body RCE at {j_ep['path']} on {mutated_path}")
                            j_hit = True
                            break
                if j_hit:
                    break

    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = []
        for index, result in enumerate(self.results, 1):
            ep = result.get("endpoint", "")
            param = result.get("param", "command")
            if "?" in ep and "=" in ep:
                param = ep.split("?")[1].split("=")[0]
            findings.append({
                "id": f"CMDI-{index:03d}",
                "title": f"OS Command Injection ({result['endpoint']})",
                "severity": format_severity("Critical"),
                "host": host, "port": port,
                "description": f"A shell metacharacter probe produced command-execution evidence at {result['endpoint']}. Payload: {result['payload']}. HTTP {result['status_code']} in {result['elapsed']}s.",
                "raw_output": result["evidence"], "owasp_tag": "A03:2021 Injection",
                "tool_name": "command_injection_scanner", "confidence": result["confidence"],
                "vuln_type": "command_injection",
                "endpoint": ep.split("?")[0].split(" (")[0],
                "param": param,
                "method": result.get("method", "POST" if "body" in str(result) else "GET"),
                "evidence": result.get("evidence"),
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
            "vuln_type": "command_injection",
            "endpoint": "/api/exec",
            "param": "command",
            "method": "GET",
            "evidence": "command output: AUTOSEC_RCE_TEST",
        }]}
