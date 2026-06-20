"""
CORS Misconfiguration Scanner Plugin for AutoSecAudit.

Tests for dangerous Cross-Origin Resource Sharing configurations:
- Wildcard (*) Access-Control-Allow-Origin
- Origin reflection (echoes back whatever Origin is sent)
- Null origin allowed
- Credentials with wildcard
- Subdomain wildcard matching
- Pre-flight request misconfigs

In mock mode, returns realistic sample findings.
"""

import requests
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 CORS-Scanner"}
REQUEST_TIMEOUT = 8

# Test origins to probe with
EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


class CORSScanner(BaseScanner):
    """CORS misconfiguration scanner."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Test CORS configuration on the target."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[CORS] Scanning CORS configuration on {base_url}")
        self.results = []

        parsed = urlparse(base_url)
        target_domain = parsed.hostname or ""

        # Paths to test (root + common API paths)
        test_paths = ["/", "/api/", "/api/v1/", "/rest/"]

        # Also use discovered endpoints if available
        if self.discovered_endpoints:
            for ep in self.discovered_endpoints[:5]:
                path = ep.get("path", "")
                if path and path not in test_paths:
                    test_paths.append(path)

        for path in test_paths:
            url = f"{base_url}{path}"

            # Test 1: Wildcard origin
            self._test_wildcard(url, path)

            # Test 2: Origin reflection
            for evil_origin in EVIL_ORIGINS:
                self._test_origin_reflection(url, path, evil_origin)

            # Test 3: Subdomain bypass
            self._test_subdomain_bypass(url, path, target_domain)

            # Test 4: Credentials with wildcard
            self._test_credentials_with_wildcard(url, path)

        self.raw_output = (
            f"Tested {len(test_paths)} paths with {len(EVIL_ORIGINS)} evil origins. "
            f"Found {len(self.results)} CORS misconfiguration(s)."
        )
        logger.info(f"[CORS] Finished — {self.raw_output}")

    def _test_wildcard(self, url: str, path: str) -> None:
        """Check if Access-Control-Allow-Origin is set to *."""
        try:
            resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self.results.append({
                    "path": path,
                    "type": "wildcard_origin",
                    "severity": "Medium",
                    "acao": acao,
                    "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
                    "detail": "ACAO set to wildcard (*). Any website can read responses.",
                })
        except requests.RequestException:
            pass

    def _test_origin_reflection(self, url: str, path: str, evil_origin: str) -> None:
        """Check if the server reflects back an arbitrary Origin header."""
        try:
            headers = {**HEADERS, "Origin": evil_origin}
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == evil_origin:
                severity = "Critical" if acac.lower() == "true" else "High"
                self.results.append({
                    "path": path,
                    "type": "origin_reflection",
                    "severity": severity,
                    "acao": acao,
                    "acac": acac,
                    "evil_origin": evil_origin,
                    "detail": f"Server reflects Origin '{evil_origin}' back in ACAO header"
                             + (". Credentials allowed — full account takeover possible!" if acac.lower() == "true" else "."),
                })
            elif evil_origin == "null" and acao == "null":
                self.results.append({
                    "path": path,
                    "type": "null_origin",
                    "severity": "High",
                    "acao": acao,
                    "acac": acac,
                    "evil_origin": "null",
                    "detail": "Server allows 'null' origin. Sandboxed iframes and data: URIs can exploit this.",
                })
        except requests.RequestException:
            pass

    def _test_subdomain_bypass(self, url: str, path: str, target_domain: str) -> None:
        """Check if a subdomain-like origin is accepted."""
        if not target_domain:
            return
        # Try evil.target-domain.com (not a real subdomain)
        fake_subdomain = f"https://evil.{target_domain}"
        try:
            headers = {**HEADERS, "Origin": fake_subdomain}
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == fake_subdomain:
                self.results.append({
                    "path": path,
                    "type": "subdomain_bypass",
                    "severity": "High",
                    "acao": acao,
                    "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
                    "evil_origin": fake_subdomain,
                    "detail": f"Server accepts subdomain-style origin '{fake_subdomain}'. Weak regex matching.",
                })
        except requests.RequestException:
            pass

    def _test_credentials_with_wildcard(self, url: str, path: str) -> None:
        """Check for credentials: true with wildcard (browser blocks but indicates misconfiguration)."""
        try:
            resp = requests.options(
                url,
                headers={**HEADERS, "Origin": "https://test.com",
                         "Access-Control-Request-Method": "GET"},
                timeout=REQUEST_TIMEOUT, verify=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            acam = resp.headers.get("Access-Control-Allow-Methods", "")

            if acao == "*" and acac.lower() == "true":
                self.results.append({
                    "path": path,
                    "type": "credentials_wildcard",
                    "severity": "High",
                    "acao": acao,
                    "acac": acac,
                    "detail": "ACAO=* with credentials=true. Browsers block this but it signals misconfigured CORS.",
                })

            # Bonus: Check for dangerous allowed methods
            if acam and any(m in acam.upper() for m in ["PUT", "DELETE", "PATCH"]):
                # Only report if origin was reflected
                if acao and acao != "*" and acao != "":
                    pass  # Already covered by origin reflection tests

        except requests.RequestException:
            pass

    def parse_output(self) -> Dict[str, Any]:
        """Convert results to standardized findings."""
        findings: List[Dict[str, Any]] = []
        seen_keys = set()

        for idx, result in enumerate(self.results, start=1):
            # Deduplicate by type+path
            key = f"{result['type']}:{result['path']}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            type_titles = {
                "wildcard_origin": "Wildcard CORS Origin",
                "origin_reflection": "CORS Origin Reflection",
                "null_origin": "CORS Null Origin Allowed",
                "subdomain_bypass": "CORS Subdomain Bypass",
                "credentials_wildcard": "CORS Credentials with Wildcard",
            }

            title = type_titles.get(result["type"], "CORS Misconfiguration")
            description = (
                f"{result['detail']}\n\n"
                f"Path: {result['path']}\n"
                f"Access-Control-Allow-Origin: {result['acao']}\n"
                f"Access-Control-Allow-Credentials: {result.get('acac', 'not set')}"
            )
            if result.get("evil_origin"):
                description += f"\nTested Origin: {result['evil_origin']}"

            findings.append({
                "id": f"CORS-{len(findings)+1:03d}",
                "title": f"{title} at {result['path']}",
                "severity": result["severity"],
                "host": self.target.split("://")[-1].split("/")[0].split(":")[0],
                "port": self._extract_port(),
                "description": description,
                "raw_output": f"ACAO: {result['acao']}, ACAC: {result.get('acac', '')}",
                "cve_id": "",
                "cvss_score": "",
                "references": [
                    "https://portswigger.net/web-security/cors",
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                "owasp_tag": "A05:2021 Security Misconfiguration",
                "tool_name": "CORSScanner",
                "confidence": "high" if result["type"] in ("origin_reflection", "null_origin") else "medium",
                "remediation": self._get_remediation(result["type"]),
            })

        return {
            "tool_name": "CORSScanner",
            "findings": findings,
            "raw_output": self.raw_output,
        }

    def _extract_port(self) -> int:
        try:
            target = self.target.split("://")[-1]
            if ":" in target:
                return int(target.split(":")[1].split("/")[0])
            return 443 if "https" in self.target else 80
        except (ValueError, IndexError):
            return 80

    @staticmethod
    def _get_remediation(vuln_type: str) -> str:
        remediations = {
            "wildcard_origin": (
                "Replace Access-Control-Allow-Origin: * with a specific whitelist of trusted origins.\n"
                "Example (Nginx):\n"
                "  if ($http_origin ~* '^https://(app\\.example\\.com|admin\\.example\\.com)$') {\n"
                "    add_header Access-Control-Allow-Origin $http_origin;\n  }"
            ),
            "origin_reflection": (
                "CRITICAL: Do NOT reflect the Origin header back as ACAO.\n"
                "Validate Origin against a strict whitelist:\n"
                "  ALLOWED = {'https://app.example.com', 'https://admin.example.com'}\n"
                "  if request.origin in ALLOWED:\n"
                "      response.headers['ACAO'] = request.origin"
            ),
            "null_origin": (
                "Never allow 'null' as a CORS origin. It can be spoofed via:\n"
                "  - Sandboxed iframes\n  - data: URIs\n  - Local file:// pages\n"
                "Remove 'null' from your CORS whitelist."
            ),
            "subdomain_bypass": (
                "Use exact-match origin validation, not regex with wildcards.\n"
                "Bad:  if origin.endswith('.example.com')\n"
                "Good: if origin in {'https://app.example.com', 'https://api.example.com'}"
            ),
            "credentials_wildcard": (
                "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.\n"
                "Use a specific origin whitelist when credentials are needed."
            ),
        }
        return remediations.get(vuln_type, "Review and restrict your CORS configuration.")

    def _get_mock_output(self) -> Dict[str, Any]:
        """Return realistic mock findings."""
        host = self.target.split("://")[-1].split("/")[0].split(":")[0] if self.target else "localhost"
        port = self._extract_port()

        return {
            "tool_name": "CORSScanner",
            "findings": [
                {
                    "id": "CORS-001",
                    "title": "CORS Origin Reflection at /api/",
                    "severity": "Critical",
                    "host": host, "port": port,
                    "description": "Server reflects Origin 'https://evil.com' back in ACAO header. Credentials allowed — full account takeover possible!\n\nPath: /api/\nAccess-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true",
                    "raw_output": "ACAO: https://evil.com, ACAC: true",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://portswigger.net/web-security/cors", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "CORSScanner", "confidence": "high",
                    "remediation": "CRITICAL: Do NOT reflect the Origin header. Validate against a strict whitelist.",
                },
                {
                    "id": "CORS-002",
                    "title": "CORS Null Origin Allowed at /",
                    "severity": "High",
                    "host": host, "port": port,
                    "description": "Server allows 'null' origin. Sandboxed iframes and data: URIs can exploit this.\n\nPath: /\nAccess-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true",
                    "raw_output": "ACAO: null, ACAC: true",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://portswigger.net/web-security/cors"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "CORSScanner", "confidence": "high",
                    "remediation": "Never allow 'null' as a CORS origin. Remove it from your whitelist.",
                },
                {
                    "id": "CORS-003",
                    "title": "Wildcard CORS Origin at /rest/",
                    "severity": "Medium",
                    "host": host, "port": port,
                    "description": "ACAO set to wildcard (*). Any website can read responses.\n\nPath: /rest/\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: false",
                    "raw_output": "ACAO: *, ACAC: ",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://portswigger.net/web-security/cors"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "CORSScanner", "confidence": "medium",
                    "remediation": "Replace ACAO: * with a specific whitelist of trusted origins.",
                },
            ],
            "raw_output": "Tested 4 paths with 3 evil origins. Found 3 CORS misconfiguration(s).",
        }
