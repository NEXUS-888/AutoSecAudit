import requests
import re
import json
import logging
import time
import urllib.parse
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner
from core.utils import format_severity

logger = logging.getLogger(__name__)


class AuthScanner(BaseScanner):
    """Authentication & Access Control vulnerability scanner.

    Tests for:
    - Default/weak credentials on common login endpoints
    - Insecure Direct Object References (IDOR)
    - Weak password acceptance at registration endpoints
    - Exposed admin panels
    - User enumeration via password reset
    - Missing rate limiting on login endpoints
    """

    HEADERS = {
        "User-Agent": "AutoSecAudit/2.0",
        "Accept": "application/json, text/html, */*",
        "Content-Type": "application/json",
    }

    REQUEST_TIMEOUT = (3.0, 8.0)

    LOGIN_PATHS = ["/login", "/admin", "/api/auth", "/rest/user/login"]

    DEFAULT_CREDENTIALS = [
        {"email": "admin", "password": "admin"},
        {"email": "admin", "password": "password"},
        {"email": "test", "password": "test"},
        {"email": "admin@juice-sh.op", "password": "admin123"},
    ]

    IDOR_PATHS = ["/api/Users/1", "/api/Users/2", "/api/BasketItems/1"]

    ADMIN_PATHS = ["/administration", "/admin", "/#/administration"]

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.raw_output: str = ""
        self.results: List[Dict[str, Any]] = []

    def configure(self, target: str) -> None:
        self.target = target
        self._tool_available = True

    def run(self) -> None:
        """Execute all authentication and access control checks."""
        self.results = []
        base_url = self._normalize_url(self.target)

        logger.info(f"AuthScanner starting against {base_url}")

        self._test_default_credentials(base_url)
        self._test_idor(base_url)
        self._test_weak_password_registration(base_url)
        self._test_exposed_admin_panels(base_url)
        self._test_user_enumeration(base_url)
        self._test_rate_limiting(base_url)

        logger.info(
            f"AuthScanner completed: {len(self.results)} findings"
        )

    # ------------------------------------------------------------------
    # Individual test methods
    # ------------------------------------------------------------------

    def _test_default_credentials(self, base_url: str) -> None:
        """Try default credential pairs against every login path."""
        host, port = self._extract_host_port(base_url)

        for path in self.LOGIN_PATHS:
            url = f"{base_url}{path}"
            for creds in self.DEFAULT_CREDENTIALS:
                try:
                    resp = self._safe_request(
                        "POST",
                        url,
                        json_data=creds,
                        headers=self.HEADERS,
                        timeout=self.REQUEST_TIMEOUT,
                        allow_redirects=False,
                    )
                    if resp is None:
                        continue

                    # Reject SPA catch-all false positives
                    if self.is_soft_404(resp):
                        continue

                    # Heuristic: successful login often returns 200/302 with
                    # a token, session cookie, or a welcome indicator.
                    is_success = False
                    body = resp.text.lower()
                    content_type = resp.headers.get("Content-Type", "").lower()

                    if resp.status_code == 200:
                        # If server returns HTML on POST without setting a session cookie, it's not a successful API login
                        if ("html" in content_type or "<!doctype" in body[:150] or "<html" in body[:150]) and not resp.cookies:
                            pass
                        elif any(
                            kw in body
                            for kw in ["token", "authentication", "success", "welcome", "dashboard"]
                        ):
                            is_success = True
                    elif resp.status_code in (301, 302) and "login" not in (
                        resp.headers.get("Location", "").lower()
                    ):
                        is_success = True

                    if is_success:
                        self.results.append(
                            {
                                "id": f"AUTH-DEFCRED-{len(self.results)+1:03d}",
                                "title": f"Default credentials accepted on {path}",
                                "severity": format_severity("CRITICAL"),
                                "host": host,
                                "port": port,
                                "description": (
                                    f"The endpoint {url} accepted default credentials "
                                    f"({creds['email']}:{creds['password']}). "
                                    f"HTTP {resp.status_code} returned."
                                ),
                                "raw_output": resp.text[:500],
                                "owasp_tag": "A07:2021 Identification and Authentication Failures",
                                "tool_name": "auth_scanner",
                            }
                        )
                except requests.RequestException as exc:
                    logger.debug(f"Request to {url} failed: {exc}")

    def _test_idor(self, base_url: str) -> None:
        """Access sequential resource IDs without authentication."""
        host, port = self._extract_host_port(base_url)

        for path in self.IDOR_PATHS:
            url = f"{base_url}{path}"
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
                    # 1. Reject SPA soft-404 responses
                    if self.is_soft_404(resp):
                        continue

                    # 2. Reject HTML responses — API resource records return JSON/XML
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "html" in content_type or "<!doctype" in resp.text[:150].lower() or "<html" in resp.text[:150].lower():
                        continue

                    # 3. Require valid JSON with real user/object fields as dictionary keys
                    try:
                        data = resp.json()
                    except (ValueError, json.JSONDecodeError):
                        continue

                    user_keys = {
                        "email", "username", "first_name", "last_name",
                        "user_id", "password_hash", "role", "balance", "address"
                    }
                    has_user_data = False

                    if isinstance(data, dict):
                        if any(k in data for k in user_keys) or any(k in data.get("data", {}) for k in user_keys):
                            has_user_data = True
                    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                        if any(k in data[0] for k in user_keys):
                            has_user_data = True

                    if has_user_data:
                        self.results.append(
                            {
                                "id": f"AUTH-IDOR-{len(self.results)+1:03d}",
                                "title": f"IDOR — Unauthenticated access to {path}",
                                "severity": format_severity("HIGH"),
                                "host": host,
                                "port": port,
                                "description": (
                                    f"Resource at {url} is accessible without "
                                    f"authentication and exposes potentially "
                                    f"sensitive object data (HTTP {resp.status_code})."
                                ),
                                "raw_output": resp.text[:500],
                                "owasp_tag": "A01:2021 Broken Access Control",
                                "tool_name": "auth_scanner",
                            }
                        )
            except requests.RequestException as exc:
                logger.debug(f"IDOR check for {url} failed: {exc}")

    def _test_weak_password_registration(self, base_url: str) -> None:
        """Attempt to register accounts with weak passwords."""
        host, port = self._extract_host_port(base_url)
        register_url = f"{base_url}/api/Users/"

        weak_payloads = [
            {
                "email": "weaktest1@autosec.test",
                "password": "123",
                "passwordRepeat": "123",
            },
            {
                "email": "weaktest2@autosec.test",
                "password": "a",
                "passwordRepeat": "a",
            },
            {
                "email": "weaktest3@autosec.test",
                "password": "password",
                "passwordRepeat": "password",
            },
        ]

        for payload in weak_payloads:
            try:
                resp = self._safe_request(
                    "POST",
                    register_url,
                    json_data=payload,
                    headers=self.HEADERS,
                    timeout=self.REQUEST_TIMEOUT,
                )
                if resp is None:
                    continue

                if resp.status_code in (200, 201):
                    self.results.append(
                        {
                            "id": f"AUTH-WEAKPW-{len(self.results)+1:03d}",
                            "title": "Weak password accepted during registration",
                            "severity": format_severity("MEDIUM"),
                            "host": host,
                            "port": port,
                            "description": (
                                f"Registration endpoint {register_url} accepted "
                                f"a weak password ('{payload['password']}'). "
                                f"HTTP {resp.status_code}."
                            ),
                            "raw_output": resp.text[:500],
                            "owasp_tag": "A07:2021 Identification and Authentication Failures",
                            "tool_name": "auth_scanner",
                        }
                    )
            except requests.RequestException as exc:
                logger.debug(f"Weak-password check failed: {exc}")

    def _test_exposed_admin_panels(self, base_url: str) -> None:
        """Probe for admin panels that are publicly reachable."""
        host, port = self._extract_host_port(base_url)

        for path in self.ADMIN_PATHS:
            url = f"{base_url}{path}"
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
                    if self.is_soft_404(resp):
                        continue
                    body = resp.text.lower()
                    if any(
                        kw in body
                        for kw in [
                            "admin", "dashboard", "panel", "management",
                            "configuration", "settings",
                        ]
                    ):
                        self.results.append(
                            {
                                "id": f"AUTH-ADMIN-{len(self.results)+1:03d}",
                                "title": f"Exposed admin panel at {path}",
                                "severity": format_severity("HIGH"),
                                "host": host,
                                "port": port,
                                "endpoint": path,
                                "method": "GET",
                                "description": (
                                    f"Admin panel at {url} is accessible and "
                                    f"returned HTTP {resp.status_code} with "
                                    f"admin-related content."
                                ),
                                "raw_output": resp.text[:500],
                                "owasp_tag": "A01:2021 Broken Access Control",
                                "tool_name": "auth_scanner",
                            }
                        )
            except requests.RequestException as exc:
                logger.debug(f"Admin panel check for {url} failed: {exc}")

    def _test_user_enumeration(self, base_url: str) -> None:
        """Check if the password-reset endpoint leaks user existence."""
        host, port = self._extract_host_port(base_url)
        reset_url = f"{base_url}/rest/user/reset-password"

        test_emails = [
            "admin@juice-sh.op",        # likely exists
            "nonexistent_user_xyz_42@fake.invalid",  # should not exist
        ]
        responses: Dict[str, Optional[requests.Response]] = {}
        for email in test_emails:
            try:
                resp = self._safe_request(
                    "POST",
                    reset_url,
                    json_data={"email": email},
                    headers=self.HEADERS,
                    timeout=self.REQUEST_TIMEOUT,
                )
                responses[email] = resp
            except requests.RequestException as exc:
                logger.debug(f"Reset-password check for {email} failed: {exc}")
                responses[email] = None

        # Compare: differing status codes or markedly different body lengths
        # indicate user enumeration.
        valid_responses = {k: v for k, v in responses.items() if v is not None}
        if len(valid_responses) >= 2:
            codes = [v.status_code for v in valid_responses.values()]
            lengths = [len(v.text) for v in valid_responses.values()]

            codes_differ = len(set(codes)) > 1
            lengths_differ = max(lengths) - min(lengths) > 50 if lengths else False

            if codes_differ or lengths_differ:
                self.results.append(
                    {
                        "id": f"AUTH-ENUM-{len(self.results)+1:03d}",
                        "title": "User enumeration via password reset",
                        "severity": format_severity("MEDIUM"),
                        "host": host,
                        "port": port,
                        "description": (
                            f"Password-reset endpoint {reset_url} returns "
                            f"different responses for existing vs non-existing "
                            f"users (status codes: {codes}, body-length diff: "
                            f"{max(lengths) - min(lengths)} bytes), enabling "
                            f"user enumeration."
                        ),
                        "raw_output": str(
                            {e: r.status_code for e, r in valid_responses.items()}
                        )[:500],
                        "owasp_tag": "A07:2021 Identification and Authentication Failures",
                        "tool_name": "auth_scanner",
                    }
                )

    def _test_rate_limiting(self, base_url: str) -> None:
        """Fire rapid login requests to detect missing rate limiting."""
        host, port = self._extract_host_port(base_url)
        login_url = f"{base_url}/rest/user/login"
        payload = {"email": "rate_limit_test@autosec.test", "password": "wrong"}

        # Step 1: Pre-probe once to verify this is a valid/active auth endpoint
        try:
            pre_check = self._safe_request(
                "POST",
                login_url,
                json_data=payload,
                headers=self.HEADERS,
                timeout=self.REQUEST_TIMEOUT,
            )
            if pre_check is None:
                return
            # If endpoint doesn't exist (404/405), returns HTML/SPA or soft-404, do not test rate limiting
            if pre_check.status_code in (404, 405):
                logger.debug(f"[AuthScanner] Login endpoint {login_url} not found (HTTP {pre_check.status_code}). Skipping rate limit test.")
                return

            pre_content_type = pre_check.headers.get("Content-Type", "").lower()
            if "html" in pre_content_type or "<!doctype" in pre_check.text[:150].lower() or "<html" in pre_check.text[:150].lower():
                logger.debug(f"[AuthScanner] Login endpoint {login_url} returned HTML/SPA. Skipping rate limit test.")
                return

            if self.is_soft_404(pre_check):
                logger.debug(f"[AuthScanner] Login endpoint {login_url} is an SPA soft-404. Skipping rate limit test.")
                return
        except requests.RequestException as exc:
            logger.debug(f"[AuthScanner] Pre-check to {login_url} failed: {exc}")
            return

        success_count = 0
        total_attempts = 10

        start = time.time()
        for _ in range(total_attempts):
            try:
                resp = self._safe_request(
                    "POST",
                    login_url,
                    json_data=payload,
                    headers=self.HEADERS,
                    timeout=self.REQUEST_TIMEOUT,
                )
                # If the server keeps responding (not 429), it lacks limiting
                if resp is not None and resp.status_code != 429:
                    success_count += 1
            except requests.RequestException as exc:
                logger.debug(f"[AuthScanner] Rate-limit probe failed on attempt {success_count+1} to {login_url}: {exc}")
                break
        elapsed = time.time() - start

        if success_count == total_attempts:
            self.results.append(
                {
                    "id": f"AUTH-RATE-{len(self.results)+1:03d}",
                    "title": "Missing rate limiting on login endpoint",
                    "severity": format_severity("MEDIUM"),
                    "host": host,
                    "port": port,
                    "description": (
                        f"Sent {total_attempts} rapid login requests to "
                        f"{login_url} in {elapsed:.2f}s — none were "
                        f"rate-limited (no HTTP 429). This permits brute-force "
                        f"attacks."
                    ),
                    "raw_output": (
                        f"{total_attempts}/{total_attempts} requests accepted "
                        f"in {elapsed:.2f}s"
                    ),
                    "owasp_tag": "A07:2021 Identification and Authentication Failures",
                    "tool_name": "auth_scanner",
                }
            )

    # ------------------------------------------------------------------
    # Output / helpers
    # ------------------------------------------------------------------

    def parse_output(self) -> Dict[str, Any]:
        for f in self.results:
            if "vuln_type" not in f:
                f["vuln_type"] = "idor" if "IDOR" in f.get("title", "") else "auth"
            if not f.get("endpoint") and " at " in f.get("title", ""):
                f["endpoint"] = f["title"].split(" at ")[-1].strip()
            if not f.get("method"):
                f["method"] = "GET"
        return {"tool_name": "auth_scanner", "findings": self.results}

    def _get_tool_name(self) -> str:
        return "python-requests"

    def _get_mock_output(self) -> Dict[str, Any]:
        host, port = self._extract_host_port(
            self._normalize_url(self.target)
        )
        return {
            "tool_name": "auth_scanner",
            "findings": [
                {
                    "id": "AUTH-DEFCRED-001",
                    "title": "Default credentials accepted on /rest/user/login",
                    "severity": "Critical",
                    "host": host,
                    "port": port,
                    "description": (
                        "The login endpoint accepted admin@juice-sh.op:admin123. "
                        "HTTP 200 returned with authentication token."
                    ),
                    "raw_output": '{"authentication":{"token":"eyJhbGciOi...","bid":1,"umail":"admin@juice-sh.op"}}',
                    "owasp_tag": "A07:2021 Identification and Authentication Failures",
                    "tool_name": "auth_scanner",
                    "vuln_type": "auth",
                    "endpoint": "/rest/user/login",
                    "param": "email",
                    "method": "POST",
                    "evidence": '{"authentication":{"token":"eyJhbGciOi...","bid":1,"umail":"admin@juice-sh.op"}}',
                },
                {
                    "id": "AUTH-IDOR-002",
                    "title": "IDOR — Unauthenticated access to /api/Users/1",
                    "severity": "High",
                    "host": host,
                    "port": port,
                    "description": (
                        "Resource /api/Users/1 returned user PII (email, "
                        "username, role) without requiring authentication."
                    ),
                    "raw_output": '{"status":"success","data":{"id":1,"username":"admin","email":"admin@juice-sh.op","role":"admin"}}',
                    "owasp_tag": "A01:2021 Broken Access Control",
                    "tool_name": "auth_scanner",
                    "vuln_type": "idor",
                    "endpoint": "/api/Users/1",
                    "param": "id",
                    "method": "GET",
                    "evidence": '{"status":"success","data":{"id":1,"username":"admin","email":"admin@juice-sh.op","role":"admin"}}',
                },
                {
                    "id": "AUTH-WEAKPW-003",
                    "title": "Weak password accepted during registration",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "Registration endpoint /api/Users/ accepted a 3-char "
                        "password '123'. No password-complexity enforcement."
                    ),
                    "raw_output": '{"status":"success","data":{"id":22,"email":"weaktest1@autosec.test"}}',
                    "owasp_tag": "A07:2021 Identification and Authentication Failures",
                    "tool_name": "auth_scanner",
                    "vuln_type": "auth",
                    "endpoint": "/api/Users/",
                    "param": "password",
                    "method": "POST",
                    "evidence": '{"status":"success","data":{"id":22,"email":"weaktest1@autosec.test"}}',
                },
                {
                    "id": "AUTH-ENUM-004",
                    "title": "User enumeration via password reset",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "Password-reset endpoint returns HTTP 200 for existing "
                        "users and HTTP 401 for unknown users, allowing "
                        "attackers to enumerate valid accounts."
                    ),
                    "raw_output": "{'admin@juice-sh.op': 200, 'nonexistent@fake.invalid': 401}",
                    "owasp_tag": "A07:2021 Identification and Authentication Failures",
                    "tool_name": "auth_scanner",
                    "vuln_type": "auth",
                    "endpoint": "/rest/user/reset-password",
                    "param": "email",
                    "method": "POST",
                    "evidence": "{'admin@juice-sh.op': 200, 'nonexistent@fake.invalid': 401}",
                },
                {
                    "id": "AUTH-RATE-005",
                    "title": "Missing rate limiting on login endpoint",
                    "severity": "Medium",
                    "host": host,
                    "port": port,
                    "description": (
                        "10 rapid login requests to /rest/user/login completed "
                        "in 1.23s without receiving a single HTTP 429 response, "
                        "indicating no rate limiting is enforced."
                    ),
                    "raw_output": "10/10 requests accepted in 1.23s",
                    "owasp_tag": "A07:2021 Identification and Authentication Failures",
                    "tool_name": "auth_scanner",
                    "vuln_type": "auth",
                    "endpoint": "/rest/user/login",
                    "method": "POST",
                    "evidence": "10/10 requests accepted in 1.23s",
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
