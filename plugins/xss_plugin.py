import requests
import re
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity
from core.dev_detector import tag_dev_artifact_finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# XSS payloads ordered from obvious to sneaky
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    # Classic reflected
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    # Event-handler variants
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    # Attribute injection
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    # Protocol handlers
    'javascript:alert(1)',
    'javascript:alert(document.cookie)',
    # Encoded variants
    '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0A1telerik%%0B2telerik%%0C3telerik%%0D4telerik%%0E5telerik%%0F6telerik%%07alert(7)//",
]

# Unique marker to reduce false positives when checking reflection
XSS_MARKER = "aUtOsEc42xSs"
MARKER_PAYLOADS = [
    f'<script>alert("{XSS_MARKER}")</script>',
    f'<img src=x onerror=alert("{XSS_MARKER}")>',
    f'<svg onload=alert("{XSS_MARKER}")>',
    f'"><script>alert("{XSS_MARKER}")</script>',
]

# ---------------------------------------------------------------------------
# Endpoints to probe
# ---------------------------------------------------------------------------
ENDPOINT_TEMPLATES: List[Dict[str, Any]] = [
    {"path": "/search",               "param": "q",      "method": "GET"},
    {"path": "/",                      "param": "q",      "method": "GET"},
    {"path": "/",                      "param": "search",  "method": "GET"},
    {"path": "/products",              "param": "search",  "method": "GET"},
    {"path": "/api/Products",          "param": "q",      "method": "GET"},
    {"path": "/rest/products/search",  "param": "q",      "method": "GET"},
    {"path": "/items",                 "param": "query",  "method": "GET"},
    {"path": "/",                      "param": "name",   "method": "GET"},
    {"path": "/",                      "param": "error",  "method": "GET"},
    {"path": "/",                      "param": "message","method": "GET"},
]

# Security headers we want to see
SECURITY_HEADERS = {
    "X-XSS-Protection":         "Missing X-XSS-Protection header",
    "Content-Security-Policy":  "Missing Content-Security-Policy (CSP) header",
    "X-Content-Type-Options":   "Missing X-Content-Type-Options header",
}

HEADERS = {"User-Agent": "AutoSecAudit/2.0"}
REQUEST_TIMEOUT = (3.0, 8.0)


class XSSScanner(BaseScanner):
    """HTTP-based Cross-Site Scripting (XSS) vulnerability scanner."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.raw_output: str = ""
        self.results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # BaseScanner interface
    # ------------------------------------------------------------------
    def configure(self, target: str) -> None:
        self.target = target
        # Pure-Python scanner – no external CLI binary required
        self._tool_available = True

    def _get_tool_name(self) -> str:
        return "python-requests"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _payload_reflected(payload: str, response_text: str) -> bool:
        """Check if the payload string appears un-encoded in the response body."""
        if not payload or not response_text:
            return False
        if payload in response_text:
            return True
        return False

    @staticmethod
    def _is_html_rendered(resp: Optional[requests.Response]) -> bool:
        """Check if response is rendered as HTML by browsers (text/html or no explicit non-HTML type)."""
        if resp is None:
            return False
        ct = resp.headers.get("Content-Type", "").lower()
        if not ct:
            # No explicit non-HTML type
            return True
        if "text/html" in ct or "application/xhtml+xml" in ct:
            return True
        # Explicit non-HTML type (e.g. application/json, text/plain, image/*)
        return False

    # ------------------------------------------------------------------
    # Core scanning logic
    # ------------------------------------------------------------------
    def _test_reflected_xss(self, base_url: str, endpoints: list = None) -> None:
        """Inject XSS payloads into GET parameters and check for reflection."""
        if endpoints is None:
            endpoints = ENDPOINT_TEMPLATES
        for ep in endpoints:
            path = ep["path"]
            param = ep["param"]
            url = f"{base_url}{path}"

            # Phase 1: marker-based payloads (low false-positive)
            for payload in MARKER_PAYLOADS:
                resp = self._safe_request(
                    "GET",
                    url,
                    params={param: payload},
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                if resp is None:
                    break  # endpoint unreachable – skip remaining payloads
                if self._payload_reflected(payload, resp.text) and self._is_html_rendered(resp):
                    self.results.append({
                        "endpoint": f"{path}?{param}=<payload>",
                        "payload": payload,
                        "status_code": resp.status_code,
                        "evidence": resp.text[:300],
                        "type": "reflected_xss",
                        "confidence": "high",
                    })
                    logger.info(
                        f"[XSS] Reflected payload at {path}?{param} "
                        f"(marker-based, high confidence)"
                    )
                    break  # One high-confidence hit per endpoint is enough

            # Phase 2: standard payloads (broader coverage)
            for payload in XSS_PAYLOADS[:6]:  # limit to first 6 for speed
                resp = self._safe_request(
                    "GET",
                    url,
                    params={param: payload},
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                if resp is None:
                    break
                if self._payload_reflected(payload, resp.text) and self._is_html_rendered(resp):
                    # Avoid duplicate for same endpoint
                    already = any(
                        r["endpoint"] == f"{path}?{param}=<payload>"
                        and r["type"] == "reflected_xss"
                        for r in self.results
                    )
                    if not already:
                        self.results.append({
                            "endpoint": f"{path}?{param}=<payload>",
                            "payload": payload,
                            "status_code": resp.status_code,
                            "evidence": resp.text[:300],
                            "type": "reflected_xss",
                            "confidence": "medium",
                        })
                        logger.info(
                            f"[XSS] Reflected payload at {path}?{param}"
                        )
                        break

    def _test_dom_xss_indicators(self, base_url: str) -> None:
        """Fetch the root page and look for DOM-XSS sinks in JavaScript."""
        dom_sinks = [
            r"document\.write\s*\(",
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"eval\s*\(",
            r"document\.location\s*=",
            r"window\.location\s*=",
            r"location\.href\s*=",
            r"document\.URL",
            r"document\.referrer",
            r"window\.name",
        ]
        pages_to_check = ["/", "/index.html", "/index.htm"]
        for page in pages_to_check:
            resp = self._safe_request(
                "GET",
                f"{base_url}{page}",
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if resp is None or resp.status_code != 200:
                continue
            for sink in dom_sinks:
                if sink in (r"window\.location\s*=", r"location\.href\s*="):
                    # Check if all location assignments are benign static string navigation literals
                    def _all_benign_static_nav(text: str) -> bool:
                        matches = list(re.finditer(r"\b(?:window\.)?location(?:\.href)?\s*=\s*", text, re.IGNORECASE))
                        if not matches:
                            return False
                        for m in matches:
                            rest = text[m.end():].lstrip()
                            if not rest or rest[0] not in ("'", '"'):
                                return False
                            q = rest[0]
                            stop_chars = {';', '"', '\r', '\n', '>', '<'} if q == "'" else {';', "'", '\r', '\n', '>', '<'}
                            end_pos = len(rest)
                            for i, ch in enumerate(rest):
                                if i > 0 and ch in stop_chars:
                                    end_pos = i
                                    break
                            rhs = rest[:end_pos].strip()
                            if len(rhs) < 2 or rhs[0] != q or rhs[-1] != q:
                                return False
                            inner = rhs[1:-1]
                            if "+" in inner or "`" in inner or "${" in inner or q in inner:
                                return False
                        return True

                    if _all_benign_static_nav(resp.text):
                        continue
                if re.search(sink, resp.text):
                    self.results.append({
                        "endpoint": page,
                        "payload": f"DOM sink pattern: {sink}",
                        "status_code": resp.status_code,
                        "evidence": re.search(sink, resp.text).group()[:200],
                        "type": "dom_xss_indicator",
                        "confidence": "low",
                    })
                    logger.info(
                        f"[XSS] DOM sink found on {page}: {sink}"
                    )
                    break  # one sink per page is enough for a finding

    def _test_security_headers(self, base_url: str) -> None:
        """Check for missing XSS-related security headers on the root page."""
        resp = self._safe_request(
            "GET",
            base_url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        if resp is None:
            return
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, message in SECURITY_HEADERS.items():
            if header.lower() not in resp_headers_lower:
                self.results.append({
                    "endpoint": "/",
                    "payload": "N/A",
                    "status_code": resp.status_code,
                    "evidence": f"Header '{header}' not present in response.",
                    "type": "missing_header",
                    "confidence": "high",
                    "header_name": header,
                })
                logger.info(f"[XSS] {message}")
            else:
                # Check for weak X-XSS-Protection (e.g. "0")
                if header == "X-XSS-Protection":
                    val = resp_headers_lower[header.lower()]
                    if val.strip().startswith("0"):
                        self.results.append({
                            "endpoint": "/",
                            "payload": "N/A",
                            "status_code": resp.status_code,
                            "evidence": f"X-XSS-Protection is set to '{val}' (disabled).",
                            "type": "weak_header",
                            "confidence": "high",
                            "header_name": header,
                        })
                        logger.info(
                            f"[XSS] X-XSS-Protection disabled (value: {val})"
                        )

    def _test_hash_fragment_endpoints(self, base_url: str) -> None:
        """Test Angular/SPA hash-fragment based endpoints for reflection.

        Hash fragments are not sent to the server, so this really tests
        whether the server echoes the *path* portion after rewriting.
        """
        fragment_paths = [
            "/#/search?q=",
            "/#/login",
        ]
        for frag_path in fragment_paths:
            for payload in [f'<script>alert("{XSS_MARKER}")</script>', '<img src=x onerror=alert(1)>']:
                # Server only sees path before "#", but some mis-configured
                # servers treat the full URL as path. We send the payload as
                # a normal query param as a fallback test.
                url = f"{base_url}{frag_path}{urllib.parse.quote(payload)}"
                resp = self._safe_request(
                    "GET",
                    url,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                if resp is None:
                    break
                if self._payload_reflected(payload, resp.text):
                    self.results.append({
                        "endpoint": frag_path,
                        "payload": payload,
                        "status_code": resp.status_code,
                        "evidence": resp.text[:300],
                        "type": "reflected_xss",
                        "confidence": "medium",
                    })
                    break

    def _test_form_xss(self, form_endpoints: List[Dict[str, Any]]) -> None:
        """Probe discovered HTML forms (POST and form-sourced GET) via submit_form_probe."""
        preferred = {
            "comment", "message", "text", "name", "q", "search",
            "query", "title", "content", "body", "bio", "feedback",
        }
        selected = self._select_form_targets(form_endpoints, preferred_names=preferred)
        reported_pairs = {
            (str(r.get("endpoint", "")).split("?")[0], r.get("param"))
            for r in self.results
            if r.get("type") == "reflected_xss"
        }

        for ep in selected:
            path = str(ep.get("path") or "")
            param = str(ep.get("param") or "")
            method = str(ep.get("method") or "POST").upper()
            if not path or not param or (path, param) in reported_pairs:
                continue

            for payload in MARKER_PAYLOADS[:2]:
                resp = self.submit_form_probe(ep, param, payload)
                if resp is None:
                    break
                if self._payload_reflected(payload, resp.text) and self._is_html_rendered(resp):
                    self.results.append({
                        "endpoint": path,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "status_code": resp.status_code,
                        "evidence": resp.text[:300],
                        "type": "reflected_xss",
                        "confidence": "high",
                    })
                    reported_pairs.add((path, param))
                    logger.info(
                        f"[XSS] Reflected form payload at {method} {path} ({param})"
                    )
                    break

    # ------------------------------------------------------------------
    # run() – main entry point
    # ------------------------------------------------------------------
    def run(self) -> None:
        base_url, host, port = self._parse_target(self.target)
        logger.info(f"[XSSScanner] Starting scan on {base_url}")
        self.results = []

        # Use discovered endpoints from crawler if available
        if self.discovered_endpoints:
            endpoints_to_test = self.discovered_endpoints
            logger.info(f"[XSSScanner] Using {len(endpoints_to_test)} discovered endpoints from crawler")
        else:
            endpoints_to_test = ENDPOINT_TEMPLATES
            logger.info(f"[XSSScanner] No discovered endpoints, using {len(endpoints_to_test)} default templates")

        get_endpoints = [
            ep for ep in endpoints_to_test
            if not self._is_form_endpoint(ep) and str(ep.get("method") or "GET").upper() == "GET"
        ]
        form_endpoints = [ep for ep in endpoints_to_test if self._is_form_endpoint(ep)]

        # 1. Reflected XSS via GET parameters
        if get_endpoints:
            self._test_reflected_xss(base_url, get_endpoints)

        # 2. Form-based XSS via submit_form_probe
        if form_endpoints:
            self._test_form_xss(form_endpoints)

        # 3. Hash-fragment / SPA endpoints
        self._test_hash_fragment_endpoints(base_url)

        # 4. DOM-XSS sink indicators in page source
        self._test_dom_xss_indicators(base_url)

        # 5. Security header audit
        self._test_security_headers(base_url)

        self.raw_output = (
            f"Tested {len(get_endpoints)} GET endpoints and {len(form_endpoints)} form endpoints with "
            f"{len(XSS_PAYLOADS)} payloads. "
            f"Found {len(self.results)} potential issue(s)."
        )
        logger.info(f"[XSSScanner] Finished – {self.raw_output}")

    # ------------------------------------------------------------------
    # parse_output()
    # ------------------------------------------------------------------
    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings: List[Dict[str, Any]] = []

        for idx, result in enumerate(self.results, start=1):
            rtype = result["type"]
            finding_id = f"XSS-{idx:03d}"

            # ---- severity ----
            severity_map = {
                "reflected_xss":      "High",
                "dom_xss_indicator":  "Medium",
                "missing_header":     "Medium",
                "weak_header":        "Medium",
            }
            severity = severity_map.get(rtype, "Medium")
            if result.get("confidence") == "high" and rtype == "reflected_xss":
                severity = "High"

            # ---- title ----
            title_map = {
                "reflected_xss":     f"Reflected XSS ({result['endpoint']})",
                "dom_xss_indicator": f"Potential DOM-Based XSS ({result['endpoint']})",
                "missing_header":    f"Missing Security Header: {result.get('header_name', 'Unknown')}",
                "weak_header":       f"Weak Security Header: {result.get('header_name', 'Unknown')}",
            }
            title = title_map.get(rtype, f"XSS Issue ({result['endpoint']})")

            # ---- description ----
            description = (
                f"XSS issue detected at endpoint {result['endpoint']}.\n"
                f"Payload / Detail: {result['payload']}\n"
                f"HTTP status: {result['status_code']}\n"
                f"Type: {rtype}\n"
                f"Confidence: {result.get('confidence', 'N/A')}"
            )

            # ---- confidence for Finding model ----
            confidence_map = {
                "reflected_xss":     result.get("confidence", "medium"),
                "dom_xss_indicator": "low",       # pattern matching only, no execution proof
                "missing_header":    "high",       # deterministic: header is either present or not
                "weak_header":       "high",
            }
            finding_confidence = confidence_map.get(rtype, "medium")

            finding_vuln_type = "misconfig" if rtype in ("missing_header", "weak_header") else "xss"
            ep_str = result.get("endpoint", "/")
            ep = ep_str.split("?")[0] if "?" in ep_str else ep_str
            param = result.get("param")
            if not param and "?" in ep_str and "=" in ep_str:
                param = ep_str.split("?")[1].split("=")[0]
            if rtype in ("missing_header", "weak_header") and result.get("header_name"):
                param = result["header_name"]
            elif rtype == "dom_xss_indicator":
                param = "dom_xss"

            finding = {
                "id": finding_id,
                "title": title,
                "severity": format_severity(severity),
                "host": host,
                "port": port,
                "description": description,
                "raw_output": result.get("evidence", "")[:500],
                "owasp_tag": "A03:2021 Injection",
                "tool_name": "xss_scanner",
                "confidence": finding_confidence,
                "vuln_type": finding_vuln_type,
                "endpoint": ep,
                "param": param,
                "method": result.get("method", "GET"),
                "evidence": result.get("evidence"),
            }
            if rtype in ("missing_header", "weak_header") and getattr(self, "dev_environment", None):
                finding = tag_dev_artifact_finding(finding, self.dev_environment)

            findings.append(finding)

        return {"tool_name": "xss_scanner", "findings": findings}

    # ------------------------------------------------------------------
    # _get_mock_output()
    # ------------------------------------------------------------------
    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        findings = [
                {
                    "id": "XSS-001",
                    "title": "Reflected XSS (/search?q=<payload>)",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "XSS issue detected at endpoint /search?q=<payload>.\n"
                        "Payload / Detail: <script>alert(\"aUtOsEc42xSs\")</script>\n"
                        "HTTP status: 200\n"
                        "Type: reflected_xss\n"
                        "Confidence: high"
                    ),
                    "raw_output": '<h2>Search results for: <script>alert("aUtOsEc42xSs")</script></h2>',
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "xss_scanner",
                    "vuln_type": "xss",
                    "endpoint": "/search",
                    "param": "q",
                    "method": "GET",
                    "evidence": '<h2>Search results for: <script>alert("aUtOsEc42xSs")</script></h2>',
                },
                {
                    "id": "XSS-002",
                    "title": "Potential DOM-Based XSS (/)",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "XSS issue detected at endpoint /.\n"
                        "Payload / Detail: DOM sink pattern: document\\.write\\s*\\(\n"
                        "HTTP status: 200\n"
                        "Type: dom_xss_indicator\n"
                        "Confidence: low"
                    ),
                    "raw_output": 'document.write(location.hash.substring(1))',
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "xss_scanner",
                    "vuln_type": "xss",
                    "endpoint": "/",
                    "param": "dom_xss",
                    "method": "GET",
                    "evidence": 'document.write(location.hash.substring(1))',
                },
                {
                    "id": "XSS-003",
                    "title": "Missing Security Header: Content-Security-Policy",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "XSS issue detected at endpoint /.\n"
                        "Payload / Detail: N/A\n"
                        "HTTP status: 200\n"
                        "Type: missing_header\n"
                        "Confidence: high"
                    ),
                    "raw_output": "Header 'Content-Security-Policy' not present in response.",
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "xss_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "Content-Security-Policy",
                    "method": "GET",
                    "evidence": "Header 'Content-Security-Policy' not present in response.",
                },
                {
                    "id": "XSS-004",
                    "title": "Missing Security Header: X-XSS-Protection",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "XSS issue detected at endpoint /.\n"
                        "Payload / Detail: N/A\n"
                        "HTTP status: 200\n"
                        "Type: missing_header\n"
                        "Confidence: high"
                    ),
                    "raw_output": "Header 'X-XSS-Protection' not present in response.",
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "xss_scanner",
                    "vuln_type": "misconfig",
                    "endpoint": "/",
                    "param": "X-XSS-Protection",
                    "method": "GET",
                    "evidence": "Header 'X-XSS-Protection' not present in response.",
                },
            ]

        if getattr(self, "dev_environment", None):
            for f in findings:
                if "Header" in f.get("title", ""):
                    tag_dev_artifact_finding(f, self.dev_environment)

        return {
            "tool_name": "xss_scanner",
            "findings": findings,
        }
