import requests
import re
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity

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
    def _parse_url(target: str):
        """Return (base_url, host, port) from a target string."""
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or parsed.netloc
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return base_url, host, port

    @staticmethod
    def _payload_reflected(payload: str, response_text: str) -> bool:
        """Check if the payload string appears un-encoded in the response body."""
        # Direct reflection
        if payload in response_text:
            return True
        # Also check for the unique marker (if present in payload)
        if XSS_MARKER in payload and XSS_MARKER in response_text:
            return True
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
                try:
                    resp = requests.get(
                        url,
                        params={param: payload},
                        headers=HEADERS,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                        verify=False,
                    )
                    if self._payload_reflected(payload, resp.text):
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
                except requests.RequestException as exc:
                    logger.debug(f"Request to {url} failed: {exc}")
                    break  # endpoint unreachable – skip remaining payloads

            # Phase 2: standard payloads (broader coverage)
            for payload in XSS_PAYLOADS[:6]:  # limit to first 6 for speed
                try:
                    resp = requests.get(
                        url,
                        params={param: payload},
                        headers=HEADERS,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                        verify=False,
                    )
                    if self._payload_reflected(payload, resp.text):
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
                except requests.RequestException:
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
            try:
                resp = requests.get(
                    f"{base_url}{page}",
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                )
                if resp.status_code != 200:
                    continue
                for sink in dom_sinks:
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
            except requests.RequestException:
                pass

    def _test_security_headers(self, base_url: str) -> None:
        """Check for missing XSS-related security headers on the root page."""
        try:
            resp = requests.get(
                base_url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
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
        except requests.RequestException as exc:
            logger.debug(f"Header check on {base_url} failed: {exc}")

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
                try:
                    # Server only sees path before "#", but some mis-configured
                    # servers treat the full URL as path. We send the payload as
                    # a normal query param as a fallback test.
                    url = f"{base_url}{frag_path}{urllib.parse.quote(payload)}"
                    resp = requests.get(
                        url,
                        headers=HEADERS,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                        verify=False,
                    )
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
                except requests.RequestException:
                    break

    # ------------------------------------------------------------------
    # run() – main entry point
    # ------------------------------------------------------------------
    def run(self) -> None:
        base_url, host, port = self._parse_url(self.target)
        logger.info(f"[XSSScanner] Starting scan on {base_url}")
        self.results = []

        # Use discovered endpoints from crawler if available
        if self.discovered_endpoints:
            endpoints_to_test = self.discovered_endpoints
            logger.info(f"[XSSScanner] Using {len(endpoints_to_test)} discovered endpoints from crawler")
        else:
            endpoints_to_test = ENDPOINT_TEMPLATES
            logger.info(f"[XSSScanner] No discovered endpoints, using {len(endpoints_to_test)} default templates")

        # 1. Reflected XSS via GET parameters
        self._test_reflected_xss(base_url, endpoints_to_test)

        # 2. Hash-fragment / SPA endpoints
        self._test_hash_fragment_endpoints(base_url)

        # 3. DOM-XSS sink indicators in page source
        self._test_dom_xss_indicators(base_url)

        # 4. Security header audit
        self._test_security_headers(base_url)

        self.raw_output = (
            f"Tested {len(endpoints_to_test)} endpoints with "
            f"{len(XSS_PAYLOADS)} payloads. "
            f"Found {len(self.results)} potential issue(s)."
        )
        logger.info(f"[XSSScanner] Finished – {self.raw_output}")

    # ------------------------------------------------------------------
    # parse_output()
    # ------------------------------------------------------------------
    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_url(self.target)
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

            findings.append({
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
            })

        return {"tool_name": "xss_scanner", "findings": findings}

    # ------------------------------------------------------------------
    # _get_mock_output()
    # ------------------------------------------------------------------
    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_url(self.target)
        return {
            "tool_name": "xss_scanner",
            "findings": [
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
                },
            ],
        }
