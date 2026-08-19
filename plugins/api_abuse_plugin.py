import requests
import re
import logging
import urllib.parse
import json
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for detecting sensitive data in HTTP responses
# ---------------------------------------------------------------------------
SENSITIVE_PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
    "credit_card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
        r"6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "api_key": re.compile(
        r"(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
        re.IGNORECASE,
    ),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "password_field": re.compile(
        r"\"(?:password|passwd|pass|secret)\"\s*:\s*\"[^\"]+\"", re.IGNORECASE
    ),
}

# Common API discovery paths
API_DISCOVERY_PATHS: List[str] = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/rest/",
    "/graphql",
    "/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/api/Products",
    "/api/Users",
    "/api/Orders",
    "/api/Feedbacks",
]

# Admin / privileged endpoints to test for broken function-level authorization
ADMIN_ENDPOINTS: List[str] = [
    "/api/admin",
    "/api/v1/admin",
    "/api/admin/users",
    "/api/Users/admin",
    "/api/admin/config",
    "/rest/admin",
    "/api/admin/orders",
    "/api/admin/dashboard",
]

# Fields whose presence in a response indicates excessive data exposure
SENSITIVE_RESPONSE_FIELDS: List[str] = [
    "password",
    "passwd",
    "secret",
    "creditCard",
    "credit_card",
    "ssn",
    "token",
    "apiKey",
    "api_key",
    "privateKey",
    "private_key",
]

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "AutoSecAudit/2.0",
    "Accept": "application/json",
}

REQUEST_TIMEOUT = (3.0, 8.0)  # seconds


class APIAbuseScanner(BaseScanner):
    """Scanner for API abuse and data exposure vulnerabilities.

    Checks include:
    - API endpoint discovery
    - Excessive data exposure (OWASP API3)
    - Mass assignment (OWASP API6)
    - Missing pagination
    - GraphQL introspection
    - Broken function-level authorization (OWASP API5)
    - Sensitive data leakage via regex
    """

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.raw_output: str = ""
        self.results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Required overrides
    # ------------------------------------------------------------------

    def configure(self, target: str) -> None:
        self.target = target
        self._tool_available = True  # pure-Python scanner, always available

    def run(self) -> None:
        """Execute all API-abuse checks against the configured target."""
        self.results = []
        base_url = self._normalize_url(self.target)
        host, port = self._extract_host_port(self.target)

        logger.info(f"APIAbuseScanner starting against {base_url}")

        # Phase 1 – discover reachable API endpoints
        discovered = self._discover_endpoints(base_url, host, port)

        # Phase 2 – excessive data exposure checks
        self._check_data_exposure(base_url, host, port)

        # Phase 3 – mass assignment tests
        self._check_mass_assignment(base_url, host, port, discovered)

        # Phase 4 – missing pagination
        self._check_missing_pagination(base_url, host, port, discovered)

        # Phase 5 – GraphQL introspection
        self._check_graphql_introspection(base_url, host, port)

        # Phase 6 – API versioning issues
        self._check_api_versioning(base_url, host, port)

        # Phase 7 – broken function-level authorization
        self._check_broken_auth(base_url, host, port)

        # Phase 8 – sensitive data regex scan across all discovered content
        # (already integrated into the individual checks above)

        self.raw_output = json.dumps(self.results, indent=2)
        logger.info(
            f"APIAbuseScanner finished – {len(self.results)} finding(s) recorded"
        )

    def parse_output(self) -> Dict[str, Any]:
        return {"tool_name": "api_abuse_scanner", "findings": self.results}

    def _get_tool_name(self) -> str:
        return "python-requests"

    def _get_mock_output(self) -> Dict[str, Any]:
        host, port = self._extract_host_port(self.target)
        return {
            "tool_name": "api_abuse_scanner",
            "findings": [
                {
                    "id": "API-001",
                    "title": "Excessive Data Exposure on /api/Users",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "The /api/Users endpoint returns sensitive fields "
                        "(password, email) that should not be exposed to "
                        "unprivileged callers."
                    ),
                    "raw_output": '{"status":200,"leaked_fields":["password","email"]}',
                    "owasp_tag": "A01:2021 Broken Access Control",
                    "tool_name": "api_abuse_scanner",
                },
                {
                    "id": "API-002",
                    "title": "Mass Assignment – role escalation accepted",
                    "severity": "Critical",
                    "host": host,
                    "port": port,
                    "description": (
                        "POST /api/Users with extra field {\"role\": \"admin\"} "
                        "was accepted without stripping the privileged attribute, "
                        "allowing potential privilege escalation."
                    ),
                    "raw_output": '{"status":201,"body_contains_role":true}',
                    "owasp_tag": "A04:2021 Insecure Design",
                    "tool_name": "api_abuse_scanner",
                },
                {
                    "id": "API-003",
                    "title": "GraphQL Introspection Enabled",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "The /graphql endpoint responds to introspection queries, "
                        "revealing the full schema including mutations and "
                        "internal types."
                    ),
                    "raw_output": '{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
                    "owasp_tag": "A01:2021 Broken Access Control",
                    "tool_name": "api_abuse_scanner",
                },
                {
                    "id": "API-004",
                    "title": "Broken Function-Level Authorization on /api/admin",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "The /api/admin endpoint returns a 200 OK response "
                        "without requiring authentication, potentially exposing "
                        "administrative functions."
                    ),
                    "raw_output": '{"status":200,"endpoint":"/api/admin"}',
                    "owasp_tag": "A01:2021 Broken Access Control",
                    "tool_name": "api_abuse_scanner",
                },
                {
                    "id": "API-005",
                    "title": "Sensitive Data Leakage – credit card pattern detected",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "A response from /api/Orders contained data matching "
                        "credit-card number patterns, indicating PCI-DSS "
                        "non-compliance."
                    ),
                    "raw_output": '{"pattern":"credit_card","endpoint":"/api/Orders"}',
                    "owasp_tag": "A04:2021 Insecure Design",
                    "tool_name": "api_abuse_scanner",
                },
            ],
        }

    # ------------------------------------------------------------------
    # Internal helpers – HTTP
    # ------------------------------------------------------------------

    def _safe_get(
        self, url: str, **kwargs
    ) -> Optional[requests.Response]:
        """GET with blanket exception handling."""
        try:
            return requests.get(
                url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT, **kwargs
            )
        except requests.RequestException as exc:
            logger.debug(f"GET {url} failed: {exc}")
            return None

    def _safe_post(
        self, url: str, data: Any = None, json_body: Any = None, **kwargs
    ) -> Optional[requests.Response]:
        """POST with blanket exception handling."""
        try:
            return requests.post(
                url,
                headers=DEFAULT_HEADERS,
                timeout=REQUEST_TIMEOUT,
                data=data,
                json=json_body,
                **kwargs,
            )
        except requests.RequestException as exc:
            logger.debug(f"POST {url} failed: {exc}")
            return None

    def _safe_put(
        self, url: str, json_body: Any = None, **kwargs
    ) -> Optional[requests.Response]:
        """PUT with blanket exception handling."""
        try:
            return requests.put(
                url,
                headers=DEFAULT_HEADERS,
                timeout=REQUEST_TIMEOUT,
                json=json_body,
                **kwargs,
            )
        except requests.RequestException as exc:
            logger.debug(f"PUT {url} failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Internal helpers – URL / target parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(target: str) -> str:
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target.rstrip("/")

    @staticmethod
    def _extract_host_port(target: str) -> tuple:
        """Return (host, port) from the target string."""
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or "unknown"
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return host, port

    # ------------------------------------------------------------------
    # Phase helpers – finding ID counter
    # ------------------------------------------------------------------

    def _next_id(self) -> str:
        return f"API-{len(self.results) + 1:03d}"

    def _add_finding(
        self,
        title: str,
        severity: str,
        host: str,
        port: int,
        description: str,
        raw_output: str,
        owasp_tag: str,
        cve_id: Optional[str] = None,
    ) -> None:
        finding: Dict[str, Any] = {
            "id": self._next_id(),
            "title": title,
            "severity": format_severity(severity),
            "host": host,
            "port": port,
            "description": description,
            "raw_output": raw_output[:1000],
            "owasp_tag": owasp_tag,
            "tool_name": "api_abuse_scanner",
        }
        if cve_id:
            finding["cve_id"] = cve_id
        self.results.append(finding)

    # ------------------------------------------------------------------
    # Phase 1 – endpoint discovery
    # ------------------------------------------------------------------

    def _discover_endpoints(
        self, base_url: str, host: str, port: int
    ) -> List[str]:
        """Probe common API paths and return those that respond."""
        discovered: List[str] = []
        for path in API_DISCOVERY_PATHS:
            url = base_url + path
            resp = self._safe_get(url)
            if resp is not None and resp.status_code < 500:
                discovered.append(path)
                logger.info(f"Discovered API endpoint: {path} ({resp.status_code})")

                # Check Swagger / OpenAPI docs exposure
                if path in ("/swagger.json", "/api-docs", "/openapi.json"):
                    if resp.status_code == 200:
                        self._add_finding(
                            title=f"API Documentation Publicly Accessible ({path})",
                            severity="Medium",
                            host=host,
                            port=port,
                            description=(
                                f"The API documentation endpoint {path} is publicly "
                                "accessible without authentication. An attacker can "
                                "use this to enumerate all available endpoints."
                            ),
                            raw_output=resp.text[:500],
                            owasp_tag="A01:2021 Broken Access Control",
                        )

                # Scan every successful response body for sensitive data
                if resp.status_code == 200 and resp.text:
                    self._scan_for_sensitive_data(resp.text, path, host, port)

        return discovered

    # ------------------------------------------------------------------
    # Phase 2 – excessive data exposure
    # ------------------------------------------------------------------

    def _check_data_exposure(
        self, base_url: str, host: str, port: int
    ) -> None:
        """Check if API responses leak sensitive fields."""
        endpoints_to_check = ["/api/Users", "/api/Products", "/api/Orders"]

        for path in endpoints_to_check:
            url = base_url + path
            resp = self._safe_get(url)
            if resp is None or resp.status_code != 200:
                continue

            body = resp.text.lower()
            leaked_fields = [
                field for field in SENSITIVE_RESPONSE_FIELDS if field.lower() in body
            ]
            if leaked_fields:
                self._add_finding(
                    title=f"Excessive Data Exposure on {path}",
                    severity="High",
                    host=host,
                    port=port,
                    description=(
                        f"The endpoint {path} returns response data containing "
                        f"sensitive fields: {', '.join(leaked_fields)}. These "
                        "fields should be stripped server-side before returning "
                        "data to unprivileged callers."
                    ),
                    raw_output=json.dumps(
                        {"status": resp.status_code, "leaked_fields": leaked_fields}
                    ),
                    owasp_tag="A01:2021 Broken Access Control",
                )

    # ------------------------------------------------------------------
    # Phase 3 – mass assignment
    # ------------------------------------------------------------------

    def _check_mass_assignment(
        self,
        base_url: str,
        host: str,
        port: int,
        discovered: List[str],
    ) -> None:
        """Attempt to send extra privileged fields via POST/PUT."""
        mass_assignment_payloads = [
            {"role": "admin", "isAdmin": True},
            {"role": "admin", "permissions": ["*"]},
            {"isAdmin": True, "privilege": "superuser"},
        ]

        # Target endpoints that typically accept writes
        write_endpoints = ["/api/Users", "/api/Feedbacks", "/api/Orders"]
        for path in write_endpoints:
            url = base_url + path
            for payload in mass_assignment_payloads:
                # Try POST
                resp = self._safe_post(url, json_body=payload)
                if resp is not None and resp.status_code in (200, 201, 202):
                    resp_body = resp.text.lower()
                    # Check if the privileged fields appear in the response
                    injected = [
                        k for k in payload if k.lower() in resp_body
                    ]
                    if injected:
                        self._add_finding(
                            title=f"Mass Assignment – privilege field accepted on {path}",
                            severity="Critical",
                            host=host,
                            port=port,
                            description=(
                                f"POST {path} accepted request body containing "
                                f"privileged fields ({', '.join(injected)}) and "
                                "reflected them in the response. This may allow "
                                "an attacker to escalate privileges."
                            ),
                            raw_output=json.dumps(
                                {
                                    "status": resp.status_code,
                                    "injected_fields": injected,
                                    "payload": payload,
                                }
                            ),
                            owasp_tag="A04:2021 Insecure Design",
                        )
                        break  # one finding per endpoint is enough

                # Try PUT
                resp = self._safe_put(url, json_body=payload)
                if resp is not None and resp.status_code in (200, 201, 202):
                    resp_body = resp.text.lower()
                    injected = [
                        k for k in payload if k.lower() in resp_body
                    ]
                    if injected:
                        self._add_finding(
                            title=f"Mass Assignment via PUT on {path}",
                            severity="Critical",
                            host=host,
                            port=port,
                            description=(
                                f"PUT {path} accepted privileged fields "
                                f"({', '.join(injected)}). The server should "
                                "whitelist acceptable fields and reject extras."
                            ),
                            raw_output=json.dumps(
                                {
                                    "status": resp.status_code,
                                    "injected_fields": injected,
                                    "payload": payload,
                                }
                            ),
                            owasp_tag="A04:2021 Insecure Design",
                        )
                        break

    # ------------------------------------------------------------------
    # Phase 4 – missing pagination
    # ------------------------------------------------------------------

    def _check_missing_pagination(
        self,
        base_url: str,
        host: str,
        port: int,
        discovered: List[str],
    ) -> None:
        """Flag responses that return very large JSON arrays without pagination."""
        LARGE_THRESHOLD = 100  # items

        list_endpoints = [
            p
            for p in discovered
            if p
            not in (
                "/graphql",
                "/swagger.json",
                "/api-docs",
                "/openapi.json",
            )
        ]
        # Also test canonical paths
        for path in list_endpoints or ["/api/Products", "/api/Users", "/api/Orders"]:
            url = base_url + path
            resp = self._safe_get(url)
            if resp is None or resp.status_code != 200:
                continue

            try:
                data = resp.json()
            except (ValueError, TypeError):
                continue

            # Unwrap common envelope patterns
            items = data
            if isinstance(data, dict):
                for key in ("data", "results", "items", "records"):
                    if key in data and isinstance(data[key], list):
                        items = data[key]
                        break

            if isinstance(items, list) and len(items) >= LARGE_THRESHOLD:
                self._add_finding(
                    title=f"Missing Pagination on {path}",
                    severity="Medium",
                    host=host,
                    port=port,
                    description=(
                        f"The endpoint {path} returned {len(items)} items in "
                        "a single response without pagination controls. This "
                        "may lead to denial-of-service or excessive data "
                        "transfer."
                    ),
                    raw_output=json.dumps(
                        {"status": resp.status_code, "item_count": len(items)}
                    ),
                    owasp_tag="A04:2021 Insecure Design",
                )

    # ------------------------------------------------------------------
    # Phase 5 – GraphQL introspection
    # ------------------------------------------------------------------

    def _check_graphql_introspection(
        self, base_url: str, host: str, port: int
    ) -> None:
        """Test whether the GraphQL endpoint allows introspection queries."""
        graphql_paths = ["/graphql", "/api/graphql", "/graphql/v1"]
        introspection_query = {"query": "{__schema{types{name}}}"}

        for path in graphql_paths:
            url = base_url + path
            resp = self._safe_post(url, json_body=introspection_query)
            if resp is None:
                continue

            if resp.status_code == 200:
                try:
                    body = resp.json()
                except (ValueError, TypeError):
                    continue

                if "data" in body and "__schema" in (body.get("data") or {}):
                    type_names = [
                        t.get("name")
                        for t in body["data"]["__schema"].get("types", [])
                    ]
                    self._add_finding(
                        title=f"GraphQL Introspection Enabled ({path})",
                        severity="Medium",
                        host=host,
                        port=port,
                        description=(
                            f"The GraphQL endpoint at {path} responds to "
                            "introspection queries, revealing the full schema "
                            f"({len(type_names)} types exposed). Disable "
                            "introspection in production."
                        ),
                        raw_output=json.dumps(
                            {"types_sample": type_names[:15]}
                        ),
                        owasp_tag="A01:2021 Broken Access Control",
                    )

    # ------------------------------------------------------------------
    # Phase 6 – API versioning issues
    # ------------------------------------------------------------------

    def _check_api_versioning(
        self, base_url: str, host: str, port: int
    ) -> None:
        """Detect when old API versions remain accessible alongside new ones."""
        version_pairs = [
            ("/api/v1/", "/api/v2/"),
            ("/api/v1/Users", "/api/v2/Users"),
        ]

        for old_path, new_path in version_pairs:
            old_resp = self._safe_get(base_url + old_path)
            new_resp = self._safe_get(base_url + new_path)

            if (
                old_resp is not None
                and old_resp.status_code == 200
                and new_resp is not None
                and new_resp.status_code == 200
            ):
                self._add_finding(
                    title=f"Deprecated API Version Still Accessible ({old_path})",
                    severity="Low",
                    host=host,
                    port=port,
                    description=(
                        f"Both {old_path} and {new_path} return HTTP 200, "
                        "indicating the older API version has not been retired. "
                        "Old versions may lack newer security controls."
                    ),
                    raw_output=json.dumps(
                        {
                            "old_status": old_resp.status_code,
                            "new_status": new_resp.status_code,
                        }
                    ),
                    owasp_tag="A04:2021 Insecure Design",
                )

    # ------------------------------------------------------------------
    # Phase 7 – broken function-level authorization
    # ------------------------------------------------------------------

    def _check_broken_auth(
        self, base_url: str, host: str, port: int
    ) -> None:
        """Try accessing admin endpoints without authentication."""
        for path in ADMIN_ENDPOINTS:
            url = base_url + path
            resp = self._safe_get(url)
            if resp is None:
                continue

            if resp.status_code == 200:
                self._add_finding(
                    title=f"Broken Function-Level Authorization ({path})",
                    severity="High",
                    host=host,
                    port=port,
                    description=(
                        f"The administrative endpoint {path} returned HTTP 200 "
                        "without requiring authentication. An attacker could "
                        "access privileged functions directly."
                    ),
                    raw_output=resp.text[:500],
                    owasp_tag="A01:2021 Broken Access Control",
                )
            elif resp.status_code in (301, 302, 307, 308):
                # Redirect may indicate a login page — low concern
                pass
            elif resp.status_code == 403:
                # Properly denied — no finding
                pass

    # ------------------------------------------------------------------
    # Phase 8 – sensitive data regex scan
    # ------------------------------------------------------------------

    def _scan_for_sensitive_data(
        self,
        body: str,
        endpoint: str,
        host: str,
        port: int,
    ) -> None:
        """Apply regex patterns to response body for sensitive data leakage."""
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(body)
            if matches:
                # De-duplicate and cap sample size
                unique_matches = list(set(matches))[:5]
                self._add_finding(
                    title=(
                        f"Sensitive Data Leakage – {pattern_name} pattern "
                        f"detected on {endpoint}"
                    ),
                    severity="High",
                    host=host,
                    port=port,
                    description=(
                        f"The response from {endpoint} contains data matching "
                        f"the '{pattern_name}' pattern ({len(matches)} "
                        f"occurrence(s)). Sample: {unique_matches}. "
                        "Ensure sensitive data is masked or excluded."
                    ),
                    raw_output=json.dumps(
                        {
                            "pattern": pattern_name,
                            "endpoint": endpoint,
                            "match_count": len(matches),
                            "sample": unique_matches,
                        }
                    ),
                    owasp_tag="A04:2021 Insecure Design",
                )
