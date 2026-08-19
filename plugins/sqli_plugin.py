import requests
import re
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL error signatures that indicate a backend database leak
# ---------------------------------------------------------------------------
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"microsoft sql native client error",
    r"odbc sql server driver",
    r"\[sqlite_error\]",
    r"sqlite3\.operationalerror",
    r"sqlite\.error",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"pgsql",
    r"sql command not properly ended",
    r"unterminated string",
    r"syntax error at or near",
    r"unexpected end of sql command",
    r"invalid column name",
    r"unknown column",
    r"operand should contain \d+ column",
    r"division by zero",
    r"com\.mysql\.jdbc",
    r"jdbc\.sqlserverexception",
    r"sqlexception",
    r"org\.postgresql",
    r"hibernate",
]

# ---------------------------------------------------------------------------
# Injection payloads grouped by technique
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = [
    # Error-based / tautology
    "' OR 1=1--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "\" OR 1=1--",
    "1' AND '1'='1",
    # UNION-based probing
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Time-based blind (the response may be slow)
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(3)--",
    # Other common
    "1 AND 1=1--",
    "admin'--",
    "1' ORDER BY 1--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
]

# ---------------------------------------------------------------------------
# Endpoints to probe (path + param name pairs)
# ---------------------------------------------------------------------------
ENDPOINT_TEMPLATES: List[Dict[str, Any]] = [
    {"path": "/search",        "param": "q",        "method": "GET"},
    {"path": "/products",      "param": "search",   "method": "GET"},
    {"path": "/api/Products",  "param": "q",        "method": "GET"},
    {"path": "/rest/products/search", "param": "q",  "method": "GET"},
    {"path": "/items",         "param": "query",    "method": "GET"},
    {"path": "/users",         "param": "id",       "method": "GET"},
    {"path": "/api/users",     "param": "id",       "method": "GET"},
    {"path": "/",              "param": "id",       "method": "GET"},
    {"path": "/",              "param": "page",     "method": "GET"},
    {"path": "/",              "param": "cat",      "method": "GET"},
]

LOGIN_ENDPOINTS = ["/login", "/api/login", "/rest/user/login", "/auth/login"]

HEADERS = {"User-Agent": "AutoSecAudit/2.0"}
REQUEST_TIMEOUT = (3.0, 8.0)


class SQLiScanner(BaseScanner):
    """HTTP-based SQL Injection vulnerability scanner."""

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
    def _check_sql_errors(text: str) -> Optional[str]:
        """Return the first matching SQL error signature found in *text*."""
        lower = text.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if re.search(sig, lower):
                return sig
        return None

    # ------------------------------------------------------------------
    # Core scanning logic
    # ------------------------------------------------------------------
    def _test_get_endpoint(self, base_url: str, endpoint: Dict[str, Any]) -> None:
        """Inject payloads into a single GET endpoint with baseline verification."""
        path = endpoint["path"]
        param = endpoint["param"]
        url = f"{base_url}{path}"

        # Fetch baseline (safe) response first
        baseline = self._get_baseline(url, param, headers=HEADERS, timeout=REQUEST_TIMEOUT)

        for payload in SQLI_PAYLOADS:
            try:
                resp = requests.get(
                    url,
                    params={param: payload},
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                )
                match = self._check_sql_errors(resp.text)
                if match:
                    # Verify against baseline to reduce false positives
                    if baseline:
                        is_verified, confidence = self._verify_against_baseline(baseline, resp)
                    else:
                        # No baseline available — trust the SQL error signature
                        is_verified, confidence = True, "medium"

                    if is_verified:
                        self.results.append({
                            "endpoint": f"{path}?{param}=<payload>",
                            "payload": payload,
                            "matched_signature": match,
                            "status_code": resp.status_code,
                            "evidence": resp.text[:300],
                            "type": "error_based",
                            "verified": True,
                            "confidence": confidence,
                        })
                        logger.info(
                            f"[SQLi] Verified injection at {path}?{param} "
                            f"with payload: {payload!r} (confidence: {confidence})"
                        )
                        return
                    else:
                        logger.debug(
                            f"[SQLi] SQL error found but baseline unchanged at {path}?{param} — skipping"
                        )
            except requests.RequestException as exc:
                logger.debug(f"Request to {url} failed: {exc}")

    def _test_login_endpoints(self, base_url: str) -> None:
        """POST common login forms with SQL injection payloads."""
        for login_path in LOGIN_ENDPOINTS:
            url = f"{base_url}{login_path}"
            for payload in ["' OR 1=1--", "admin'--", "' OR '1'='1'--"]:
                bodies = [
                    {"username": payload, "password": "password"},
                    {"email": payload, "password": "password"},
                    {"user": payload, "pass": "password"},
                ]
                for body in bodies:
                    try:
                        resp = requests.post(
                            url,
                            json=body,
                            headers={**HEADERS, "Content-Type": "application/json"},
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=True,
                            verify=False,
                        )
                        match = self._check_sql_errors(resp.text)
                        if match:
                            self.results.append({
                                "endpoint": login_path,
                                "payload": payload,
                                "matched_signature": match,
                                "status_code": resp.status_code,
                                "evidence": resp.text[:300],
                                "type": "login_bypass",
                            })
                            logger.info(
                                f"[SQLi] Possible login bypass at {login_path} "
                                f"with payload: {payload!r}"
                            )
                            return  # one hit per login endpoint
                        # Heuristic: if we got HTTP 200 with a short JSON body
                        # that contains "token" or "auth", might be a bypass
                        if resp.status_code == 200 and (
                            "token" in resp.text.lower()
                            or "authentication" in resp.text.lower()
                        ):
                            self.results.append({
                                "endpoint": login_path,
                                "payload": payload,
                                "matched_signature": "authentication_bypass_heuristic",
                                "status_code": resp.status_code,
                                "evidence": resp.text[:300],
                                "type": "login_bypass",
                            })
                            return
                    except requests.RequestException as exc:
                        logger.debug(f"Login test to {url} failed: {exc}")

    def _test_url_path_injection(self, base_url: str) -> None:
        """Try path-based injection on REST-style numeric IDs."""
        paths = ["/api/Products/", "/users/", "/api/users/", "/items/"]
        for path in paths:
            for payload in ["1 OR 1=1", "1' OR '1'='1", "1 AND 1=CONVERT(int,@@version)--"]:
                url = f"{base_url}{path}{urllib.parse.quote(payload)}"
                try:
                    resp = requests.get(
                        url,
                        headers=HEADERS,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                        verify=False,
                    )
                    match = self._check_sql_errors(resp.text)
                    if match:
                        self.results.append({
                            "endpoint": f"{path}<id>",
                            "payload": payload,
                            "matched_signature": match,
                            "status_code": resp.status_code,
                            "evidence": resp.text[:300],
                            "type": "path_injection",
                        })
                        return
                except requests.RequestException:
                    pass

    # ------------------------------------------------------------------
    # run() – main entry point
    # ------------------------------------------------------------------
    def run(self) -> None:
        base_url, host, port = self._parse_url(self.target)
        logger.info(f"[SQLiScanner] Starting scan on {base_url}")
        self.results = []

        # Use discovered endpoints from crawler if available, else fall back to hardcoded
        if self.discovered_endpoints:
            endpoints_to_test = self.discovered_endpoints
            logger.info(f"[SQLiScanner] Using {len(endpoints_to_test)} discovered endpoints from crawler")
        else:
            endpoints_to_test = ENDPOINT_TEMPLATES
            logger.info(f"[SQLiScanner] No discovered endpoints, using {len(endpoints_to_test)} default templates")

        # 1. GET parameter injection on discovered/default endpoints
        for ep in endpoints_to_test:
            self._test_get_endpoint(base_url, ep)

        # 2. Login form injection
        self._test_login_endpoints(base_url)

        # 3. REST path-based injection
        self._test_url_path_injection(base_url)

        self.raw_output = f"Tested {len(endpoints_to_test)} GET endpoints, " \
                          f"{len(LOGIN_ENDPOINTS)} login endpoints. " \
                          f"Found {len(self.results)} potential issue(s)."
        logger.info(f"[SQLiScanner] Finished – {self.raw_output}")

    # ------------------------------------------------------------------
    # parse_output()
    # ------------------------------------------------------------------
    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_url(self.target)
        findings: List[Dict[str, Any]] = []

        for idx, result in enumerate(self.results, start=1):
            severity = "Critical" if result["type"] == "login_bypass" else "High"
            finding_id = f"SQLI-{idx:03d}"

            # Confidence: prefer baseline-verified confidence, else use heuristic
            if result.get("verified") and result.get("confidence"):
                confidence = result["confidence"]
            elif result.get("matched_signature") == "authentication_bypass_heuristic":
                confidence = "low"
            elif result["type"] in ("error_based", "path_injection"):
                confidence = "high"
            else:
                confidence = "medium"

            description = (
                f"SQL Injection detected at endpoint {result['endpoint']}.\n"
                f"Payload: {result['payload']}\n"
                f"Matched signature: {result['matched_signature']}\n"
                f"HTTP status: {result['status_code']}\n"
                f"Type: {result['type']}"
            )

            title_map = {
                "error_based": f"SQL Injection – Error-Based ({result['endpoint']})",
                "login_bypass": f"SQL Injection – Login Bypass ({result['endpoint']})",
                "path_injection": f"SQL Injection – Path Injection ({result['endpoint']})",
            }
            title = title_map.get(
                result["type"],
                f"SQL Injection ({result['endpoint']})",
            )

            findings.append({
                "id": finding_id,
                "title": title,
                "severity": format_severity(severity),
                "host": host,
                "port": port,
                "description": description,
                "raw_output": result.get("evidence", "")[:500],
                "owasp_tag": "A03:2021 Injection",
                "tool_name": "sqli_scanner",
                "confidence": confidence,
            })

        return {"tool_name": "sqli_scanner", "findings": findings}

    # ------------------------------------------------------------------
    # _get_mock_output()
    # ------------------------------------------------------------------
    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_url(self.target)
        return {
            "tool_name": "sqli_scanner",
            "findings": [
                {
                    "id": "SQLI-001",
                    "title": "SQL Injection – Error-Based (/search?q=<payload>)",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "SQL Injection detected at /search?q=<payload>.\n"
                        "Payload: ' OR 1=1--\n"
                        "Matched signature: you have an error in your sql syntax\n"
                        "HTTP status: 500\n"
                        "Type: error_based"
                    ),
                    "raw_output": "Error: You have an error in your SQL syntax near '' OR 1=1--'",
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "sqli_scanner",
                    "confidence": "high",
                },
                {
                    "id": "SQLI-002",
                    "title": "SQL Injection – Login Bypass (/rest/user/login)",
                    "severity": "Critical",
                    "host": host,
                    "port": port,
                    "description": (
                        "SQL Injection detected at /rest/user/login.\n"
                        "Payload: ' OR 1=1--\n"
                        "Matched signature: authentication_bypass_heuristic\n"
                        "HTTP status: 200\n"
                        "Type: login_bypass"
                    ),
                    "raw_output": '{"authentication":{"token":"mock-jwt-token","umail":"admin@example.com"}}',
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "sqli_scanner",
                    "confidence": "low",
                },
                {
                    "id": "SQLI-003",
                    "title": "SQL Injection – Error-Based (/api/Products?q=<payload>)",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "SQL Injection detected at /api/Products?q=<payload>.\n"
                        "Payload: ' UNION SELECT NULL,NULL,NULL--\n"
                        "Matched signature: sqlite_error\n"
                        "HTTP status: 500\n"
                        "Type: error_based"
                    ),
                    "raw_output": "SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns",
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "sqli_scanner",
                    "confidence": "high",
                },
                {
                    "id": "SQLI-004",
                    "title": "SQL Injection – Path Injection (/api/Products/<id>)",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "SQL Injection detected at /api/Products/<id>.\n"
                        "Payload: 1 OR 1=1\n"
                        "Matched signature: syntax error at or near\n"
                        "HTTP status: 500\n"
                        "Type: path_injection"
                    ),
                    "raw_output": "ERROR: syntax error at or near 'OR' at character 35",
                    "owasp_tag": "A03:2021 Injection",
                    "tool_name": "sqli_scanner",
                    "confidence": "high",
                },
            ],
        }
