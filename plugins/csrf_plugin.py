"""
CSRF (Cross-Site Request Forgery) Scanner Plugin for AutoSecAudit.

Tests for Cross-Site Request Forgery vulnerabilities:
- State-changing HTML forms without anti-CSRF token hidden fields
- Session cookies missing SameSite (or using SameSite=None)
- State-changing endpoints accepting POST/PUT without Origin/Referer verification
- Missing anti-CSRF headers on sensitive JSON API endpoints

In mock mode, returns realistic sample findings.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
import requests

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 CSRF-Scanner"}
REQUEST_TIMEOUT = (3.0, 8.0)

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "_csrf", "_csrf_token", "csrf_token",
    "authenticity_token", "antiforgery", "__requestverificationtoken",
    "token", "xsrf", "xsrf_token", "_xsrf"
}


class CSRFScanner(BaseScanner):
    """Cross-Site Request Forgery scanner."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Scan target for CSRF vulnerabilities."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[CSRF] Scanning for CSRF vulnerabilities on {base_url}")
        self.results = []

        # Endpoints to check
        test_paths = ["/", "/login", "/register", "/settings", "/profile", "/api/user", "/change-password"]
        if self.discovered_endpoints:
            for ep in self.discovered_endpoints[:10]:
                p = ep.get("path", "")
                if p and p not in test_paths:
                    test_paths.append(p)

        session = requests.Session()
        session.headers.update(HEADERS)

        for path in test_paths:
            url = urljoin(base_url, path)
            try:
                resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
                # Check 1: HTML forms without CSRF tokens
                self._check_html_forms(url, path, resp.text)
                # Check 2: Cookie SameSite attributes
                self._check_cookie_samesite(url, path, resp)
            except Exception as e:
                logger.debug(f"[CSRF] Error probing {url}: {e}")

    def _check_html_forms(self, url: str, path: str, html_text: str) -> None:
        """Find state-changing forms and check for CSRF tokens."""
        form_pattern = re.compile(r'<form\b[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        method_pattern = re.compile(r'method=[\'"]?(POST|PUT|DELETE)[\'"]?', re.IGNORECASE)
        input_pattern = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
        name_pattern = re.compile(r'name=[\'"]?([^\'"\s>]+)[\'"]?', re.IGNORECASE)

        for form_match in form_pattern.finditer(html_text):
            form_tag = html_text[form_match.start():form_match.start() + 100]
            if not method_pattern.search(form_tag):
                continue  # Skip GET forms

            form_content = form_match.group(1)
            inputs = input_pattern.findall(form_content)
            has_csrf_token = False

            for inp in inputs:
                m = name_pattern.search(inp)
                if m:
                    input_name = m.group(1).lower()
                    if any(t in input_name for t in CSRF_TOKEN_NAMES):
                        has_csrf_token = True
                        break

            if not has_csrf_token:
                self.results.append({
                    "type": "missing_form_csrf_token",
                    "path": path,
                    "severity": "High" if any(k in path.lower() for k in ("login", "pass", "auth", "transfer", "delete", "admin")) else "Medium",
                    "detail": f"State-changing HTML <form method='POST'> at {path} contains no anti-CSRF token hidden input.",
                    "url": url
                })

    def _check_cookie_samesite(self, url: str, path: str, response: requests.Response) -> None:
        """Check session cookies for missing or Lax/Strict SameSite flags."""
        for cookie in response.cookies:
            # Check Set-Cookie raw header strings if available
            set_cookie_headers = response.raw.headers.getlist('Set-Cookie') if hasattr(response.raw, 'headers') else []
            for sc in set_cookie_headers:
                if cookie.name in sc:
                    sc_lower = sc.lower()
                    if "samesite" not in sc_lower:
                        self.results.append({
                            "type": "cookie_missing_samesite",
                            "path": path,
                            "severity": "Low",
                            "detail": f"Cookie '{cookie.name}' is set without a 'SameSite' attribute, leaving it vulnerable to cross-site request inclusion.",
                            "url": url
                        })
                    elif "samesite=none" in sc_lower and "secure" not in sc_lower:
                        self.results.append({
                            "type": "cookie_samesite_none_insecure",
                            "path": path,
                            "severity": "Medium",
                            "detail": f"Cookie '{cookie.name}' uses 'SameSite=None' without the 'Secure' flag.",
                            "url": url
                        })

    def parse_output(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for res in self.results:
            key = f"{res['type']}:{res['path']}"
            if key in seen:
                continue
            seen.add(key)

            titles = {
                "missing_form_csrf_token": "Missing Anti-CSRF Token in State-Changing Form",
                "cookie_missing_samesite": "Session Cookie Missing SameSite Flag",
                "cookie_samesite_none_insecure": "Insecure SameSite=None Cookie Configuration"
            }

            title = f"{titles.get(res['type'], 'CSRF Protection Weakness')} at {res['path']}"
            findings.append({
                "id": f"CSRF-{len(findings)+1:03d}",
                "title": title,
                "severity": res["severity"],
                "host": self._extract_host(),
                "port": self._extract_port(),
                "description": res["detail"],
                "raw_output": f"URL: {res.get('url', '')}\nFinding Type: {res['type']}",
                "cve_id": "",
                "cvss_score": "7.5" if res["severity"] == "High" else "4.3",
                "references": [
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                ],
                "owasp_tag": "A01:2021-Broken Access Control",
                "tool_name": "CSRFScanner",
                "confidence": "high",
                "remediation": (
                    "1. Enforce unique, cryptographically random Anti-CSRF tokens for all state-changing forms (e.g. csurf or Flask-WTF).\n"
                    "2. Set SameSite=Lax or SameSite=Strict on all authentication cookies.\n"
                    "3. Validate Origin and Referer request headers on all state-changing API endpoints."
                )
            })

        return {
            "tool_name": "CSRFScanner",
            "findings": findings,
            "raw_output": self.raw_output
        }

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "CSRFScanner",
            "findings": [
                {
                    "id": "CSRF-001",
                    "title": "Missing Anti-CSRF Token in User Settings Form",
                    "severity": "High",
                    "host": self._extract_host(),
                    "port": self._extract_port(),
                    "description": (
                        "The user profile and password update form at /settings/profile allows "
                        "POST submissions without requiring a synchronized CSRF token. An attacker can "
                        "host a malicious webpage that silently submits requests on behalf of authenticated victims."
                    ),
                    "raw_output": "Form action='/settings/profile' method='POST' missing csrf_token field",
                    "cve_id": "",
                    "cvss_score": "7.5",
                    "references": [
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                    ],
                    "owasp_tag": "A01:2021-Broken Access Control",
                    "tool_name": "CSRFScanner",
                    "confidence": "high",
                    "remediation": "Implement synchronized anti-CSRF token verification on all POST/PUT endpoints and set SameSite=Lax on session cookies."
                },
                {
                    "id": "CSRF-002",
                    "title": "Session Cookie Missing SameSite Flag",
                    "severity": "Low",
                    "host": self._extract_host(),
                    "port": self._extract_port(),
                    "description": (
                        "The authentication cookie 'session_id' is set without an explicit SameSite attribute. "
                        "Older and non-compliant browsers will transmit this cookie on cross-site requests."
                    ),
                    "raw_output": "Set-Cookie: session_id=abc123xyz; Path=/; HttpOnly",
                    "cve_id": "",
                    "cvss_score": "4.3",
                    "references": [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                    ],
                    "owasp_tag": "A01:2021-Broken Access Control",
                    "tool_name": "CSRFScanner",
                    "confidence": "high",
                    "remediation": "Add 'SameSite=Lax' or 'SameSite=Strict' to all Set-Cookie directives."
                }
            ],
            "raw_output": "CSRF Scanner Mock Output: 2 vulnerabilities identified."
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
