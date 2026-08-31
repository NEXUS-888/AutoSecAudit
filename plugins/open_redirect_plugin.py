"""
Open Redirect Scanner Plugin for AutoSecAudit.

Tests for Unvalidated URL Redirection vulnerabilities:
- Query parameters containing unvalidated external destination URLs
- Protocol-relative URL bypasses (//example.com)
- Backslash/forward slash bypasses (/\\example.com)
- Absolute URL redirect parameters (?next=https://attacker.com)

In mock mode, returns realistic sample findings.
"""

import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import requests

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 OpenRedirect-Scanner"}
REQUEST_TIMEOUT = (3.0, 6.0)

REDIRECT_PARAMS = [
    "redirect", "next", "url", "return_to", "target", "dest",
    "callback", "goto", "checkout_url", "continue", "ref", "forward"
]

BENIGN_PAYLOADS = [
    ("https://example.com", "Absolute external HTTPS URL"),
    ("//example.com", "Protocol-relative URL"),
    ("/\\example.com", "Backslash slash evasion"),
    ("https://attacker.example.com", "Untrusted Subdomain")
]


class OpenRedirectScanner(BaseScanner):
    """Open Redirect / Unvalidated URL Redirect Scanner."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Scan target for Open Redirect flaws."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[OpenRedirect] Scanning for open redirect flaws on {base_url}")
        self.results = []

        test_endpoints = ["/login", "/logout", "/redirect", "/auth/callback", "/navigate", "/goto"]
        if self.discovered_endpoints:
            for ep in self.discovered_endpoints[:15]:
                p = ep.get("path", "")
                if p and p not in test_endpoints:
                    test_endpoints.append(p)

        session = requests.Session()
        session.headers.update(HEADERS)

        for path in test_endpoints:
            parsed_path = urlparse(path)
            clean_path = parsed_path.path
            qs = parse_qs(parsed_path.query)

            # Probe known redirect parameters on this path
            for param in REDIRECT_PARAMS:
                for payload, desc in BENIGN_PAYLOADS:
                    test_params = dict(qs)
                    test_params[param] = payload
                    query_str = urlencode(test_params, doseq=True)
                    test_url = f"{urljoin(base_url, clean_path)}?{query_str}"

                    try:
                        resp = session.get(test_url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
                        if resp.status_code in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("Location", "")
                            if "example.com" in loc:
                                self.results.append({
                                    "path": clean_path,
                                    "param": param,
                                    "payload": payload,
                                    "location": loc,
                                    "status": resp.status_code,
                                    "desc": desc,
                                    "url": test_url
                                })
                                break  # One confirmed finding per param/path is sufficient
                    except Exception as e:
                        logger.debug(f"[OpenRedirect] Error testing {test_url}: {e}")

    def parse_output(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for res in self.results:
            key = f"{res['path']}:{res['param']}"
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "id": f"REDIR-{len(findings)+1:03d}",
                "title": f"Open Redirect via Parameter '{res['param']}' at {res['path']}",
                "severity": "Medium",
                "host": self._extract_host(),
                "port": self._extract_port(),
                "description": (
                    f"The endpoint at {res['path']} accepts an untrusted destination URL in parameter '{res['param']}' "
                    f"and issues an HTTP {res['status']} redirect directly to '{res['location']}' without validation. "
                    "Attackers can leverage this in credential phishing campaigns to lure users from legitimate domains to spoofed pages."
                ),
                "raw_output": f"Tested URL: {res['url']}\nHTTP Status: {res['status']}\nLocation Header: {res['location']}",
                "cve_id": "",
                "cvss_score": "6.1",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/601.html"
                ],
                "owasp_tag": "A01:2021-Broken Access Control",
                "tool_name": "OpenRedirectScanner",
                "confidence": "high",
                "remediation": (
                    "1. Avoid accepting user-controlled target URLs for redirection.\n"
                    "2. If redirection is necessary, enforce an allowlist of permitted relative paths (e.g. starting with a single '/' and not '//') or approved trusted domains.\n"
                    "3. Reject any redirect target containing protocol specifiers (http:, https:, javascript:)."
                )
            })

        return {
            "tool_name": "OpenRedirectScanner",
            "findings": findings,
            "raw_output": self.raw_output
        }

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "OpenRedirectScanner",
            "findings": [
                {
                    "id": "REDIR-001",
                    "title": "Open Redirect via 'next' Parameter at /login",
                    "severity": "Medium",
                    "host": self._extract_host(),
                    "port": self._extract_port(),
                    "description": (
                        "The login redirection flow at /login?next= accepts arbitrary external URLs and performs "
                        "an unvalidated HTTP 302 redirect upon successful authentication. Attackers can construct "
                        "trusted domain links that redirect victims to malicious phishing pages."
                    ),
                    "raw_output": "GET /login?next=https://attacker.example.com HTTP/1.1\nHTTP/1.1 302 Found\nLocation: https://attacker.example.com",
                    "cve_id": "",
                    "cvss_score": "6.1",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                    ],
                    "owasp_tag": "A01:2021-Broken Access Control",
                    "tool_name": "OpenRedirectScanner",
                    "confidence": "high",
                    "remediation": "Validate the 'next' parameter against an internal relative path allowlist starting with a single '/' (e.g. rejecting '//')."
                }
            ],
            "raw_output": "Open Redirect Scanner Mock Output: 1 vulnerability identified."
        }

    def _extract_host(self) -> str:
        try:
            return self.target.split("://")[-1].split("/")[0].split(":")[0]
        except Exception:
            return "localhost"

    def _extract_port(self) -> int:
        try:
            target = self.target.split("://")[-1]
            if ":" in target:
                return int(target.split(":")[1].split("/")[0])
            return 443 if "https" in self.target else 80
        except (ValueError, IndexError):
            return 80
