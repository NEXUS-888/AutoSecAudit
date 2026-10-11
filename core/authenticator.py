"""
Automated Form and API Authentication Module for AutoSecAudit.

Detects login endpoints, extracts anti-CSRF tokens, submits credentials
via form or JSON POST, captures session cookies and JWT Bearer tokens,
and verifies authenticated session persistence.
"""

import re
import json
import logging
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field
from html.parser import HTMLParser

import requests

logger = logging.getLogger(__name__)

# Common login path candidates to probe if login_url is not specified
COMMON_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/user/login",
    "/users/login",
    "/users/sign_in",
    "/account/login",
    "/auth/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/session",
    "/rest/user/login",
]

# Field name heuristics for username/email
USERNAME_FIELD_CANDIDATES = [
    "username", "user", "email", "login", "identifier",
    "user_id", "userid", "user_name", "account", "login_id",
    "email_address", "auth_user"
]

# Field name heuristics for password
PASSWORD_FIELD_CANDIDATES = [
    "password", "pass", "pwd", "user_password", "passwd",
    "secret", "auth_pass"
]

# Anti-CSRF token name candidates
CSRF_TOKEN_CANDIDATES = [
    "csrf_token", "csrf-token", "csrftoken", "_csrf", "_csrf_token",
    "_token", "authenticity_token", "csrfmiddlewaretoken",
    "xsrf_token", "xsrf-token", "antiforgery_token", "__requestverificationtoken"
]


@dataclass
class AuthResult:
    """Result of an automated login attempt."""
    success: bool = False
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    token: Optional[str] = None
    message: str = ""
    status_code: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "cookies": self.cookies,
            "headers": self.headers,
            "login_url": self.login_url,
            "token": self.token[:10] + "..." if self.token and len(self.token) > 10 else self.token,
            "message": self.message,
            "status_code": self.status_code,
        }


class _LoginFormParser(HTMLParser):
    """Parses HTML to extract login forms, input field names, and hidden CSRF tokens."""

    def __init__(self):
        super().__init__()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "POST").upper(),
                "inputs": {},          # name -> type
                "hidden_fields": {},   # name -> value
                "has_password": False,
            }

        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name") or attr_dict.get("id")
            input_type = attr_dict.get("type", "text").lower()
            val = attr_dict.get("value", "")

            if name:
                self._current_form["inputs"][name] = input_type
                if input_type == "password":
                    self._current_form["has_password"] = True
                if input_type == "hidden":
                    self._current_form["hidden_fields"][name] = val

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            if self._current_form["has_password"]:
                self.forms.append(self._current_form)
            self._current_form = None


class AutoAuthenticator:
    """
    Automated Form and API Authenticator for AutoSecAudit.
    
    Probes for login endpoints, parses forms, extracts CSRF tokens,
    submits credentials, captures session cookies and bearer tokens,
    and equips the scanner with authenticated authority.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        login_url: Optional[str] = None,
        timeout: Tuple[float, float] = (3.0, 8.0),
        session: Optional[requests.Session] = None
    ):
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.explicit_login_url = login_url
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "AutoSecAudit/2.0 Authenticator",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
        })
        self.session.verify = False

    def authenticate(self) -> AuthResult:
        """
        Execute automated login flow.
        
        Returns:
            AuthResult containing success flag, captured cookies, and auth headers.
        """
        if not self.username or not self.password:
            return AuthResult(success=False, message="Missing username or password.")

        login_endpoints = self._resolve_login_endpoints()
        if not login_endpoints:
            return AuthResult(success=False, message=f"No login endpoint could be discovered on {self.base_url}.")

        logger.info(f"[AutoAuth] Attempting automated login on {len(login_endpoints)} target candidate(s)...")
        last_failure_message = "No valid credentials or session established."

        for endpoint_url in login_endpoints:
            logger.info(f"[AutoAuth] Probing login candidate: {endpoint_url}")
            result = self._try_login_at_endpoint(endpoint_url)
            if result.success:
                logger.info(
                    f"[AutoAuth] Successfully authenticated at {endpoint_url}! "
                    f"Captured {len(result.cookies)} cookie(s), token={'yes' if result.token else 'no'}"
                )
                return result
            if result.message and "404" not in result.message:
                last_failure_message = result.message

        return AuthResult(
            success=False,
            message=f"Authentication failed on {self.base_url}: {last_failure_message}"
        )

    def _resolve_login_endpoints(self) -> List[str]:
        """Resolve ordered list of candidate URLs to test."""
        if self.explicit_login_url:
            full_url = urllib.parse.urljoin(f"{self.base_url}/", self.explicit_login_url.lstrip("/"))
            return [full_url]

        candidates = []
        for path in COMMON_LOGIN_PATHS:
            candidates.append(urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/")))
        return candidates

    def _try_login_at_endpoint(self, url: str) -> AuthResult:
        """Attempt login at a specific endpoint using both Form and JSON approaches."""
        try:
            get_resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            logger.debug(f"[AutoAuth] GET probe to {url} failed: {e}")
            return AuthResult(success=False, login_url=url, message=f"GET probe failed: {e}")

        # If endpoint returns 404, skip
        if get_resp.status_code == 404:
            return AuthResult(success=False, login_url=url, message="Endpoint returned 404")

        content_type = get_resp.headers.get("Content-Type", "").lower()
        is_html = "html" in content_type or "<!doctype" in get_resp.text[:150].lower() or "<html" in get_resp.text[:150].lower()

        # Strategy A: If it's an HTML page, parse form inputs & hidden CSRF tokens
        if is_html:
            form_result = self._attempt_html_form_login(url, get_resp)
            if form_result.success:
                return form_result

        # Strategy B: Attempt JSON API authentication (common for SPAs and REST APIs)
        json_result = self._attempt_json_api_login(url)
        if json_result.success:
            return json_result

        # Strategy C: Blind Form POST as fallback
        fallback_result = self._attempt_blind_form_login(url)
        if fallback_result.success:
            return fallback_result

        return AuthResult(
            success=False,
            login_url=url,
            message="Credentials rejected or no valid session captured.",
            status_code=get_resp.status_code
        )

    def _attempt_html_form_login(self, page_url: str, get_resp: requests.Response) -> AuthResult:
        """Parse HTML login form, populate user/pass and CSRF token, and submit."""
        parser = _LoginFormParser()
        try:
            parser.feed(get_resp.text)
        except Exception as e:
            logger.debug(f"[AutoAuth] HTML form parse error on {page_url}: {e}")
            return AuthResult(success=False, login_url=page_url, message="Form parse error")

        if not parser.forms:
            logger.debug(f"[AutoAuth] No password form found on {page_url}")
            return AuthResult(success=False, login_url=page_url, message="No password form found")

        form = parser.forms[0]
        action = form.get("action") or ""
        post_url = urllib.parse.urljoin(page_url, action)

        # Detect username/email field name
        user_field = None
        pass_field = None

        for field_name, input_type in form["inputs"].items():
            fn_lower = field_name.lower()
            if input_type == "password" or any(p in fn_lower for p in PASSWORD_FIELD_CANDIDATES):
                pass_field = field_name
            elif any(u == fn_lower for u in USERNAME_FIELD_CANDIDATES) or any(u in fn_lower for u in ["user", "email", "login"]):
                user_field = field_name

        if not pass_field:
            return AuthResult(success=False, login_url=page_url, message="Password input field could not be identified")

        if not user_field:
            # Pick first text input that isn't password or csrf
            for field_name, input_type in form["inputs"].items():
                if field_name != pass_field and input_type in ("text", "email"):
                    user_field = field_name
                    break

        if not user_field:
            user_field = "username"

        # Build payload with hidden fields (CSRF tokens)
        payload = dict(form.get("hidden_fields", {}))
        payload[user_field] = self.username
        payload[pass_field] = self.password

        # Add common CSRF token if not present in hidden fields but found in cookies
        for cookie_name, cookie_val in self.session.cookies.items():
            if any(c in cookie_name.lower() for c in ["csrf", "xsrf"]):
                if not any(c in payload for c in CSRF_TOKEN_CANDIDATES):
                    payload["csrf_token"] = cookie_val

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": page_url,
            "Origin": self.base_url,
        }

        try:
            resp = self.session.post(
                post_url,
                data=payload,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            return self._evaluate_auth_response(post_url, resp)
        except requests.RequestException as exc:
            return AuthResult(success=False, login_url=post_url, message=f"POST error: {exc}")

    def _attempt_json_api_login(self, url: str) -> AuthResult:
        """Attempt JSON-based API login payload."""
        payload_variations = [
            {"username": self.username, "password": self.password},
            {"email": self.username, "password": self.password},
            {"identifier": self.username, "password": self.password},
        ]

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": self.base_url,
            "Referer": url,
        }

        for payload in payload_variations:
            try:
                resp = self.session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                auth_res = self._evaluate_auth_response(url, resp)
                if auth_res.success:
                    return auth_res
            except requests.RequestException as exc:
                logger.debug(f"[AutoAuth] JSON login probe failed for {url}: {exc}")
                continue

        return AuthResult(success=False, login_url=url, message="JSON login attempts failed")

    def _attempt_blind_form_login(self, url: str) -> AuthResult:
        """Fallback form POST attempt with common field permutations."""
        field_pairs = [
            ("username", "password"),
            ("email", "password"),
            ("user", "pass"),
            ("login", "password"),
        ]

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.base_url,
            "Referer": url,
        }

        for u_name, p_name in field_pairs:
            payload = {u_name: self.username, p_name: self.password}
            try:
                resp = self.session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                auth_res = self._evaluate_auth_response(url, resp)
                if auth_res.success:
                    return auth_res
            except requests.RequestException as exc:
                logger.debug(f"[AutoAuth] Blind form probe failed for {url}: {exc}")
                continue

        return AuthResult(success=False, login_url=url, message="Blind form login failed")

    def _evaluate_auth_response(self, login_url: str, resp: requests.Response) -> AuthResult:
        """Inspect response to determine if login succeeded and extract tokens/cookies."""
        # Check 1: Did we receive new session cookies?
        captured_cookies = dict(self.session.cookies)
        
        # Check 2: Did we receive a JSON response containing an auth token?
        token = None
        auth_headers = {}

        try:
            data = resp.json()
            if isinstance(data, dict):
                # Search for token keys
                for key in ["token", "access_token", "jwt", "accessToken", "id_token", "authToken"]:
                    if key in data and isinstance(data[key], str) and len(data[key]) > 10:
                        token = data[key]
                        break
                    if "data" in data and isinstance(data["data"], dict) and key in data["data"]:
                        token = data["data"][key]
                        break
        except (ValueError, json.JSONDecodeError):
            pass

        if token:
            auth_headers["Authorization"] = f"Bearer {token}"

        # Indicators of successful authentication:
        # A. HTTP 200 with captured session cookie or token
        # B. HTTP 302/301 redirect to dashboard/home with cookies
        # C. JSON response with success: true
        has_cookies = len(captured_cookies) > 0
        has_token = token is not None
        status_ok = resp.status_code in (200, 201, 302, 303, 307)

        # Check for explicit failure strings in response body
        body_lower = resp.text.lower()
        has_explicit_failure = any(f in body_lower for f in [
            "invalid credential", "invalid username", "invalid password",
            "login failed", "unauthorized", "incorrect password",
            "user not found", "access denied", "wrong password"
        ]) and resp.status_code in (400, 401, 403)

        if has_explicit_failure:
            return AuthResult(
                success=False,
                login_url=login_url,
                message="Server rejected credentials with invalid authentication error.",
                status_code=resp.status_code
            )

        if (has_cookies or has_token) and status_ok:
            return AuthResult(
                success=True,
                cookies=captured_cookies,
                headers=auth_headers,
                login_url=login_url,
                token=token,
                message="Login successful. Session credentials captured.",
                status_code=resp.status_code
            )

        # If redirected away from login path with status 200 after redirect
        if resp.status_code == 200 and resp.url and "/login" not in resp.url.lower():
            return AuthResult(
                success=True,
                cookies=captured_cookies,
                headers=auth_headers,
                login_url=login_url,
                token=token,
                message="Login successful via navigation redirect.",
                status_code=resp.status_code
            )

        return AuthResult(
            success=False,
            login_url=login_url,
            message=f"Response status {resp.status_code} did not establish an authenticated session.",
            status_code=resp.status_code
        )
