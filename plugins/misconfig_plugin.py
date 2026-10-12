import requests
import re
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity
from core.dev_detector import tag_dev_artifact_finding

logger = logging.getLogger(__name__)


class MisconfigScanner(BaseScanner):
    """Security Misconfiguration vulnerability scanner.

    Tests for:
    - Missing HTTP security headers
    - CORS misconfigurations
    - Exposed sensitive files (.env, .git/config, etc.)
    - Directory listing
    - Verbose error pages / stack-trace disclosure
    - Dangerous HTTP methods
    - Information disclosure via response headers
    """

    HEADERS = {
        "User-Agent": "AutoSecAudit/2.0",
        "Accept": "text/html, application/json, */*",
    }

    REQUEST_TIMEOUT = (3.0, 8.0)

    SECURITY_HEADERS: Dict[str, Dict[str, Any]] = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": (
                "HTTP Strict-Transport-Security (HSTS) header is missing. "
                "Browsers may allow downgrade attacks from HTTPS to HTTP."
            ),
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": (
                "X-Content-Type-Options header is missing. The browser may "
                "perform MIME-type sniffing, leading to XSS vectors."
            ),
        },
        "X-Frame-Options": {
            "severity": "LOW",
            "description": (
                "X-Frame-Options header is missing. The page may be framed, "
                "enabling clickjacking attacks."
            ),
        },
        "Content-Security-Policy": {
            "severity": "LOW",
            "description": (
                "Content-Security-Policy header is missing. No CSP is "
                "enforced, increasing the risk of XSS and data injection."
            ),
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "description": (
                "X-XSS-Protection header is missing. The browser's built-in "
                "XSS filter will not be explicitly enabled."
            ),
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": (
                "Referrer-Policy header is missing. Sensitive URL data may "
                "leak through the Referer header."
            ),
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": (
                "Permissions-Policy header is missing. Browser features like "
                "camera, microphone, and geolocation are not explicitly restricted."
            ),
        },
    }

    SENSITIVE_FILES = [
        {"path": "/.env", "severity": "CRITICAL", "label": ".env configuration file"},
        {"path": "/.git/config", "severity": "CRITICAL", "label": "Git configuration"},
        {"path": "/robots.txt", "severity": "INFO", "label": "robots.txt"},
        {"path": "/package.json", "severity": "MEDIUM", "label": "package.json"},
        {"path": "/swagger.json", "severity": "MEDIUM", "label": "Swagger API spec"},
        {"path": "/api-docs", "severity": "MEDIUM", "label": "API documentation"},
        {"path": "/config.json", "severity": "HIGH", "label": "Config JSON file"},
        {"path": "/backup.sql", "severity": "CRITICAL", "label": "SQL backup file"},
    ]

    DIRECTORY_PATHS = [
        "/assets", "/uploads", "/images", "/static",
        "/backup", "/logs", "/tmp", "/data",
    ]

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.raw_output: str = ""
        self.results: List[Dict[str, Any]] = []

    def configure(self, target: str) -> None:
        self.target = target
        self._tool_available = True

    def run(self) -> None:
        """Execute all misconfiguration checks."""
        self.results = []
        base_url = self._normalize_url(self.target)

        logger.info(f"MisconfigScanner starting against {base_url}")

        self._check_security_headers(base_url)
        self._check_cors(base_url)
        self._check_sensitive_files(base_url)
        self._check_directory_listing(base_url)
        self._check_verbose_errors(base_url)
        self._check_http_methods(base_url)
        self._check_info_disclosure(base_url)

        logger.info(
            f"MisconfigScanner completed: {len(self.results)} findings"
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_security_headers(self, base_url: str) -> None:
        """Fetch the main page and verify required security headers."""
        host, port = self._extract_host_port(base_url)

        try:
            resp = self._safe_request(
                "GET",
                base_url,
                headers=self.HEADERS,
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp is None:
                return
        except requests.RequestException as exc:
            logger.warning(f"Security-header check failed: {exc}")
            return

        for header_name, meta in self.SECURITY_HEADERS.items():
            if header_name not in resp.headers:
                f_hdr = {
                    "id": f"MISCONF-HDR-{len(self.results)+1:03d}",
                    "title": f"Missing security header: {header_name}",
                    "severity": format_severity(meta["severity"]),
                    "host": host,
                    "port": port,
                    "description": meta["description"],
                    "raw_output": (
                        f"Response headers from {base_url} do not include "
                        f"'{header_name}'. Headers present: "
                        f"{', '.join(sorted(resp.headers.keys()))}"
                    ),
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": header_name,
                    "method": "GET",
                    "evidence": (
                        f"Response headers from {base_url} do not include '{header_name}'."
                    ),
                }
                if self.dev_environment:
                    f_hdr = tag_dev_artifact_finding(f_hdr, self.dev_environment)
                self.results.append(f_hdr)

    def _check_cors(self, base_url: str) -> None:
        """Send a cross-origin request and inspect CORS headers."""
        host, port = self._extract_host_port(base_url)
        evil_origin = "https://evil.autosec.test"

        try:
            cors_headers = {**self.HEADERS, "Origin": evil_origin}
            resp = self._safe_request(
                "GET",
                base_url,
                headers=cors_headers,
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp is None:
                return
        except requests.RequestException as exc:
            logger.debug(f"CORS check failed: {exc}")
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            f_cors = {
                "id": f"MISCONF-CORS-{len(self.results)+1:03d}",
                "title": "CORS wildcard Access-Control-Allow-Origin",
                "severity": format_severity("MEDIUM"),
                "host": host,
                "port": port,
                "description": (
                    "The server returns 'Access-Control-Allow-Origin: *', "
                    "allowing any origin to read responses. If credentials "
                    "are also allowed, this is a critical misconfiguration."
                ),
                "raw_output": f"Access-Control-Allow-Origin: {acao}",
                "owasp_tag": "A05:2021 Security Misconfiguration",
                "tool_name": "misconfig_scanner",
                "vuln_type": "misconfig",
                "endpoint": "/",
                "param": "acao_wildcard",
                "method": "GET",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
            }
            if self.dev_environment:
                f_cors = tag_dev_artifact_finding(f_cors, self.dev_environment)
            self.results.append(f_cors)
        elif evil_origin in acao:
            f_cors = {
                "id": f"MISCONF-CORS-{len(self.results)+1:03d}",
                "title": "CORS reflects arbitrary Origin",
                "severity": format_severity("HIGH"),
                "host": host,
                "port": port,
                "description": (
                    f"The server reflected the attacker-controlled Origin "
                    f"'{evil_origin}' in its Access-Control-Allow-Origin "
                    f"header, permitting cross-site data theft."
                ),
                "raw_output": f"Access-Control-Allow-Origin: {acao}",
                "owasp_tag": "A05:2021 Security Misconfiguration",
                "tool_name": "misconfig_scanner",
                "vuln_type": "misconfig",
                "endpoint": "/",
                "param": "origin_reflect",
                "method": "GET",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
            }
            if self.dev_environment:
                f_cors = tag_dev_artifact_finding(f_cors, self.dev_environment)
            self.results.append(f_cors)

    def _check_sensitive_files(self, base_url: str) -> None:
        """Probe for common sensitive files that should not be public."""
        host, port = self._extract_host_port(base_url)

        for entry in self.SENSITIVE_FILES:
            url = f"{base_url}{entry['path']}"
            try:
                resp = self._safe_request(
                    "GET",
                    url,
                    headers=self.HEADERS,
                    timeout=self.REQUEST_TIMEOUT,
                )
                if resp is None:
                    continue

                if resp.status_code == 200 and len(resp.text.strip()) > 0:
                    # 1. Reject SPA soft-404 catch-alls
                    if self.is_soft_404(resp):
                        continue

                    # 2. Content integrity
                    content_type = resp.headers.get("Content-Type", "").lower()
                    is_html = "html" in content_type or "<!doctype" in resp.text[:150].lower() or "<html" in resp.text[:150].lower()
                    path = entry["path"]

                    if path.endswith((".sql", ".env", "/.git/config")) and is_html:
                        continue
                    if path.endswith(".json") and (is_html or not resp.text.strip().startswith(("{", "["))):
                        continue

                    # Extra validation: avoid false positives from custom 404 pages
                    body_lower = resp.text.lower()
                    is_custom_404 = any(
                        kw in body_lower
                        for kw in ["not found", "404", "page not found"]
                    ) and len(resp.text) < 2000

                    if not is_custom_404:
                        if entry["path"] == "/robots.txt":
                            file_title = "Standard Web File: robots.txt (Informational)"
                            file_severity = "Info"
                            file_desc = (
                                f"The robots.txt file at {url} is publicly accessible "
                                f"(HTTP {resp.status_code}, {len(resp.text)} bytes). "
                                "Having a robots.txt file is standard web practice and expected. "
                                "Review any Disallow directives to ensure sensitive internal paths "
                                "are not unnecessarily advertised to web crawlers."
                            )
                        else:
                            file_title = f"Exposed sensitive file: {entry['label']}"
                            file_severity = format_severity(entry["severity"])
                            file_desc = (
                                f"The file at {url} is publicly accessible "
                                f"(HTTP {resp.status_code}, "
                                f"{len(resp.text)} bytes). It may expose "
                                f"secrets, configuration details, or source "
                                f"code information."
                            )

                        self.results.append(
                            {
                                "id": f"MISCONF-FILE-{len(self.results)+1:03d}",
                                "title": file_title,
                                "severity": file_severity,
                                "host": host,
                                "port": port,
                                "description": file_desc,
                                "raw_output": resp.text[:500],
                                "owasp_tag": "A05:2021 Security Misconfiguration",
                                "tool_name": "misconfig_scanner",
                                "vuln_type": "misconfig",
                                "endpoint": entry["path"],
                                "param": entry["path"],
                                "method": "GET",
                                "evidence": resp.text[:500],
                            }
                        )
            except requests.RequestException as exc:
                logger.debug(f"Sensitive-file check for {url} failed: {exc}")

    def _check_directory_listing(self, base_url: str) -> None:
        """Probe common directories for enabled directory listing."""
        host, port = self._extract_host_port(base_url)

        listing_indicators = [
            "index of /", "directory listing", "<pre>", "parent directory",
            "[to parent directory]",
        ]

        for path in self.DIRECTORY_PATHS:
            url = f"{base_url}{path}/"
            try:
                resp = self._safe_request(
                    "GET",
                    url,
                    headers=self.HEADERS,
                    timeout=self.REQUEST_TIMEOUT,
                )
                if resp is None:
                    continue

                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(ind in body_lower for ind in listing_indicators):
                        self.results.append(
                            {
                                "id": f"MISCONF-DIRLIST-{len(self.results)+1:03d}",
                                "title": f"Directory listing enabled on {path}/",
                                "severity": format_severity("MEDIUM"),
                                "host": host,
                                "port": port,
                                "description": (
                                    f"Directory listing is enabled at {url}. "
                                    f"Attackers can enumerate files and discover "
                                    f"sensitive resources."
                                ),
                                "raw_output": resp.text[:500],
                                "owasp_tag": "A05:2021 Security Misconfiguration",
                                "tool_name": "misconfig_scanner",
                                "vuln_type": "misconfig",
                                "endpoint": f"{path}/",
                                "param": f"{path}/",
                                "method": "GET",
                                "evidence": resp.text[:500],
                            }
                        )
            except requests.RequestException as exc:
                logger.debug(f"Directory listing check for {url} failed: {exc}")

    def _check_verbose_errors(self, base_url: str) -> None:
        """Trigger a 404 and examine the error page for stack traces."""
        host, port = self._extract_host_port(base_url)
        url = f"{base_url}/autosec_nonexistent_path_404_test"

        try:
            resp = self._safe_request(
                "GET",
                url,
                headers=self.HEADERS,
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp is None:
                return
        except requests.RequestException as exc:
            logger.debug(f"Verbose-error check failed: {exc}")
            return

        body_lower = resp.text.lower()
        stack_trace_indicators = [
            "traceback", "stack trace", "exception", "at line",
            "syntax error", "debug", "internal server error",
            "unhandled exception", "error in", "node_modules",
        ]

        if any(ind in body_lower for ind in stack_trace_indicators):
            self.results.append(
                {
                    "id": f"MISCONF-ERR-{len(self.results)+1:03d}",
                    "title": "Verbose error page exposes stack trace",
                    "severity": format_severity("MEDIUM"),
                    "host": host,
                    "port": port,
                    "description": (
                        f"The error page at {url} reveals internal "
                        f"implementation details (stack trace, framework info, "
                        f"or debug output). HTTP {resp.status_code}."
                    ),
                    "raw_output": resp.text[:500],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/autosec_nonexistent_path_404_test",
                    "param": "verbose_error",
                    "method": "GET",
                    "evidence": resp.text[:500],
                }
            )

    def _check_http_methods(self, base_url: str) -> None:
        """Send OPTIONS and look for dangerous allowed methods."""
        host, port = self._extract_host_port(base_url)

        try:
            resp = self._safe_request(
                "OPTIONS",
                base_url,
                headers=self.HEADERS,
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp is None:
                return
        except requests.RequestException as exc:
            logger.debug(f"HTTP methods check failed: {exc}")
            return

        allow_header = resp.headers.get("Allow", "")
        if not allow_header:
            allow_header = resp.headers.get("Access-Control-Allow-Methods", "")

        dangerous_methods = {"PUT", "DELETE", "TRACE", "PATCH"}
        if allow_header:
            methods = {m.strip().upper() for m in allow_header.split(",")}
            found_dangerous = methods & dangerous_methods

            if found_dangerous:
                self.results.append(
                    {
                        "id": f"MISCONF-METHOD-{len(self.results)+1:03d}",
                        "title": "Dangerous HTTP methods enabled",
                        "severity": format_severity("MEDIUM"),
                        "host": host,
                        "port": port,
                        "description": (
                            f"The server advertises support for potentially "
                            f"dangerous HTTP methods: "
                            f"{', '.join(sorted(found_dangerous))}. "
                            f"These may allow unauthorized modification or "
                            f"deletion of resources."
                        ),
                        "raw_output": f"Allow: {allow_header}",
                        "owasp_tag": "A05:2021 Security Misconfiguration",
                        "tool_name": "misconfig_scanner",
                        "vuln_type": "misconfig",
                        "endpoint": "/",
                        "param": ",".join(sorted(found_dangerous)),
                        "method": "OPTIONS",
                        "evidence": f"Allow: {allow_header}",
                    }
                )

    def _check_info_disclosure(self, base_url: str) -> None:
        """Look for Server / X-Powered-By headers that disclose technology."""
        host, port = self._extract_host_port(base_url)

        try:
            resp = self._safe_request(
                "GET",
                base_url,
                headers=self.HEADERS,
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp is None:
                return
        except requests.RequestException as exc:
            logger.debug(f"Info-disclosure check failed: {exc}")
            return

        disclosure_headers = {
            "Server": "Server header discloses web server software",
            "X-Powered-By": "X-Powered-By header discloses application framework",
        }

        for hdr_name, description_prefix in disclosure_headers.items():
            value = resp.headers.get(hdr_name)
            if value:
                self.results.append(
                    {
                        "id": f"MISCONF-INFO-{len(self.results)+1:03d}",
                        "title": f"Information disclosure: {hdr_name}",
                        "severity": format_severity("INFO"),
                        "host": host,
                        "port": port,
                        "description": (
                            f"{description_prefix}: '{value}'. This helps "
                            f"attackers fingerprint the technology stack and "
                            f"target known vulnerabilities."
                        ),
                        "raw_output": f"{hdr_name}: {value}",
                        "owasp_tag": "A05:2021 Security Misconfiguration",
                        "tool_name": "misconfig_scanner",
                        "vuln_type": "misconfig",
                        "endpoint": "/",
                        "param": hdr_name,
                        "method": "GET",
                        "evidence": f"{hdr_name}: {value}",
                    }
                )

    # ------------------------------------------------------------------
    # Output / helpers
    # ------------------------------------------------------------------

    def parse_output(self) -> Dict[str, Any]:
        for f in self.results:
            if not f.get("tool_name"):
                f["tool_name"] = "misconfig_scanner"
            if not f.get("vuln_type"):
                f["vuln_type"] = "misconfig"
            if not f.get("endpoint"):
                f["endpoint"] = "/"
            if not f.get("method"):
                f["method"] = "GET"
            if "param" not in f:
                title = f.get("title", "")
                if "Missing security header:" in title:
                    f["param"] = title.split("Missing security header:")[-1].strip()
                elif "Information disclosure:" in title:
                    f["param"] = title.split("Information disclosure:")[-1].strip()
                elif "CORS wildcard" in title:
                    f["param"] = "acao_wildcard"
                elif "CORS reflects" in title:
                    f["param"] = "origin_reflect"
                elif "Exposed sensitive file:" in title:
                    f["param"] = f.get("endpoint", "/")
                elif "Directory listing" in title:
                    f["param"] = f.get("endpoint", "/")
                elif "Dangerous HTTP methods" in title:
                    f["param"] = "dangerous_methods"
                elif "Verbose error" in title:
                    f["param"] = "verbose_error"
                else:
                    f["param"] = None
            if not f.get("evidence"):
                f["evidence"] = f.get("raw_output")
        return {"tool_name": "misconfig_scanner", "findings": self.results}

    def _get_tool_name(self) -> str:
        return "python-requests"

    def _get_mock_output(self) -> Dict[str, Any]:
        host, port = self._extract_host_port(
            self._normalize_url(self.target)
        )
        return {
            "tool_name": "misconfig_scanner",
            "findings": [
                {
                    "id": "MISCONF-HDR-001",
                    "title": "Missing security header: Strict-Transport-Security",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "HSTS header is missing. Without HSTS, browsers "
                        "may connect over plain HTTP, enabling man-in-the-"
                        "middle downgrade attacks."
                    ),
                    "raw_output": "Response headers do not include 'Strict-Transport-Security'.",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "Strict-Transport-Security",
                    "method": "GET",
                    "evidence": "Response headers do not include 'Strict-Transport-Security'.",
                },
                {
                    "id": "MISCONF-HDR-002",
                    "title": "Missing security header: Content-Security-Policy",
                    "severity": "Low",
                    "host": host,
                    "port": port,
                    "description": (
                        "No Content-Security-Policy header found. CSP "
                        "helps mitigate XSS by restricting resource loading."
                    ),
                    "raw_output": "Response headers do not include 'Content-Security-Policy'.",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "Content-Security-Policy",
                    "method": "GET",
                    "evidence": "Response headers do not include 'Content-Security-Policy'.",
                },
                {
                    "id": "MISCONF-FILE-003",
                    "title": "Exposed sensitive file: .env configuration file",
                    "severity": "Critical",
                    "host": host,
                    "port": port,
                    "description": (
                        "The file /.env is publicly accessible and appears to "
                        "contain environment variables including database "
                        "credentials and API keys."
                    ),
                    "raw_output": "DB_HOST=localhost\nDB_PASSWORD=s3cret\nAPI_KEY=abc123...",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/.env",
                    "param": "/.env",
                    "method": "GET",
                    "evidence": "DB_HOST=localhost\nDB_PASSWORD=s3cret\nAPI_KEY=abc123...",
                },
                {
                    "id": "MISCONF-CORS-004",
                    "title": "CORS wildcard Access-Control-Allow-Origin",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "The server returns 'Access-Control-Allow-Origin: *', "
                        "allowing any website to read responses. Combined "
                        "with credentials, this enables cross-site data theft."
                    ),
                    "raw_output": "Access-Control-Allow-Origin: *",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "acao_wildcard",
                    "method": "GET",
                    "evidence": "Access-Control-Allow-Origin: *",
                },
                {
                    "id": "MISCONF-INFO-005",
                    "title": "Information disclosure: X-Powered-By",
                    "severity": "Info",
                    "host": host,
                    "port": port,
                    "description": (
                        "X-Powered-By header reveals 'Express'. Attackers can "
                        "use this to identify the framework and target known "
                        "vulnerabilities."
                    ),
                    "raw_output": "X-Powered-By: Express",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "X-Powered-By",
                    "method": "GET",
                    "evidence": "X-Powered-By: Express",
                },
                {
                    "id": "MISCONF-METHOD-006",
                    "title": "Dangerous HTTP methods enabled",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "The server advertises support for PUT and DELETE "
                        "methods. These may allow unauthorized modification "
                        "or deletion of resources."
                    ),
                    "raw_output": "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "misconfig_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "PUT,DELETE",
                    "method": "OPTIONS",
                    "evidence": "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS",
                },
            ],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        return target.rstrip("/")

    def _extract_host_port(self, url: str) -> tuple:
        """Return (host, port) from a URL string."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "unknown"
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return host, port
