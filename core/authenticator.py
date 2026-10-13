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
CSRF_TOKEN_NAMES = CSRF_TOKEN_CANDIDATES

MAX_CREDENTIAL_SUBMISSIONS = 6
DEFAULT_DENY_PATTERN = r"logout|log-out|signout|sign-out|logoff|delete|remove|destroy"

FAILURE_INDICATORS = [
    "invalid credential", "invalid username", "invalid password",
    "invalid email or password", "invalid email", "incorrect password",
    "wrong password", "bad credentials", "authentication failed",
    "user not found", "access denied", "login failed", "unauthorized",
    "not authorized", "login error", "details don't match",
    "don't match our records", "do not match", "credentials do not match"
]


def _extract_token_from_json(data: Any) -> Optional[str]:
    """Search for auth token recursively in nested JSON structures."""
    token_keys = {"token", "access_token", "jwt", "accesstoken", "id_token", "authtoken"}
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in token_keys and isinstance(v, str) and len(v) > 10:
                return v
        for container in ["authentication", "data", "auth", "session", "result", "user"]:
            if container in data and isinstance(data[container], dict):
                t = _extract_token_from_json(data[container])
                if t:
                    return t
        for v in data.values():
            if isinstance(v, (dict, list)):
                t = _extract_token_from_json(v)
                if t:
                    return t
    elif isinstance(data, list):
        for item in data:
            t = _extract_token_from_json(item)
            if t:
                return t
    return None


def _has_failure_indicator(resp: requests.Response) -> bool:
    """Check for explicit failure strings in response body regardless of status code."""
    body_lower = resp.text.lower() if resp and resp.text else ""
    return any(f in body_lower for f in FAILURE_INDICATORS)


def _is_clear_credential_rejection(resp: requests.Response) -> bool:
    """Determine if response indicates invalid credentials specifically."""
    if resp.status_code in (401, 403):
        return True
    return _has_failure_indicator(resp)


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
        session: Optional[requests.Session] = None,
        verify_url: Optional[str] = None,
    ):
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.explicit_login_url = login_url
        self.verify_url = verify_url or f"{self.base_url}/"
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "AutoSecAudit/2.0 Authenticator",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
        })
        self.session.verify = False
        self.credential_submissions_count = 0

    def authenticate(self) -> AuthResult:
        """
        Execute automated login flow.
        
        Returns:
            AuthResult containing success flag, captured cookies, and auth headers.
        """
        if not self.username or not self.password:
            return AuthResult(success=False, message="Missing username or password.")

        self.credential_submissions_count = 0

        # Snapshot anonymous baseline of verify_url prior to authentication
        anon_status, anon_url, anon_text = self._get_anonymous_verify_baseline()

        login_endpoints = self._resolve_login_endpoints()
        if not login_endpoints:
            return AuthResult(success=False, message=f"No login endpoint could be discovered on {self.base_url}.")

        logger.info(f"[AutoAuth] Attempting automated login on {len(login_endpoints)} target candidate(s)...")
        last_failure_message = "No valid credentials or session established."

        for endpoint_url in login_endpoints:
            if self.credential_submissions_count >= MAX_CREDENTIAL_SUBMISSIONS:
                logger.info(f"[AutoAuth] Reached maximum credential submissions limit ({MAX_CREDENTIAL_SUBMISSIONS}).")
                break

            logger.info(f"[AutoAuth] Probing login candidate: {endpoint_url}")
            result, rejected = self._try_login_at_endpoint(endpoint_url, anon_status, anon_url, anon_text)
            if result.success:
                logger.info(
                    f"[AutoAuth] Successfully authenticated at {endpoint_url}! "
                    f"Captured {len(result.cookies)} cookie(s), token={'yes' if result.token else 'no'}"
                )
                return result

            if result.message and "404" not in result.message:
                last_failure_message = result.message

            # Stop at the first endpoint that clearly rejects the credentials
            if rejected:
                logger.info(f"[AutoAuth] Endpoint {endpoint_url} clearly rejected credentials. Stopping further spraying.")
                return result

        return AuthResult(
            success=False,
            message=f"Authentication failed on {self.base_url}: {last_failure_message}"
        )

    def _get_anonymous_verify_baseline(self) -> Tuple[int, str, str]:
        """Fetch baseline state of verify_url prior to authentication."""
        try:
            resp = self.session.get(self.verify_url, timeout=self.timeout, allow_redirects=True)
            return resp.status_code, getattr(resp, "url", "") or "", resp.text or ""
        except Exception:
            return 0, "", ""

    def _resolve_login_endpoints(self) -> List[str]:
        """Resolve ordered list of candidate URLs to test."""
        deny_re = re.compile(DEFAULT_DENY_PATTERN, re.IGNORECASE)
        if self.explicit_login_url:
            full_url = urllib.parse.urljoin(f"{self.base_url}/", self.explicit_login_url.lstrip("/"))
            return [full_url]

        candidates = []
        for path in COMMON_LOGIN_PATHS:
            if deny_re.search(path):
                continue
            candidates.append(urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/")))
        return candidates

    def _try_login_at_endpoint(
        self,
        url: str,
        anon_status: int = 0,
        anon_url: str = "",
        anon_text: str = ""
    ) -> Tuple[AuthResult, bool]:
        """Attempt login at a specific endpoint using Form and JSON approaches."""
        try:
            get_resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            logger.debug(f"[AutoAuth] GET probe to {url} failed: {e}")
            return AuthResult(success=False, login_url=url, message=f"GET probe failed: {e}"), False

        if get_resp.status_code == 404:
            return AuthResult(success=False, login_url=url, message="Endpoint returned 404"), False

        content_type = get_resp.headers.get("Content-Type", "").lower()
        is_html = "html" in content_type or "<!doctype" in get_resp.text[:150].lower() or "<html" in get_resp.text[:150].lower() or "<form" in get_resp.text.lower()
        is_json_resp = "application/json" in content_type or (get_resp.text.strip().startswith("{") and get_resp.text.strip().endswith("}"))

        # Check 1: HTML page with password form
        if is_html:
            parser = _LoginFormParser()
            try:
                parser.feed(get_resp.text)
            except Exception as e:
                logger.debug(f"[AutoAuth] HTML form parse error on {url}: {e}")

            if parser.forms:
                return self._attempt_html_form_login(url, get_resp, parser.forms[0], anon_status, anon_url, anon_text)

        # Check 2: JSON API endpoint
        # During auto-discovery, only probe if an empty JSON POST returns 400, 401, or 422.
        # Explicit login_url is exempted.
        is_json_login = False
        if self.explicit_login_url:
            is_json_login = True
        else:
            try:
                empty_post_resp = self.session.post(
                    url,
                    json={},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=self.timeout,
                    allow_redirects=True
                )
                if empty_post_resp.status_code in (400, 401, 422):
                    is_json_login = True
            except requests.RequestException:
                pass

        if is_json_login:
            return self._attempt_json_api_login(url, anon_status, anon_url, anon_text)

        # Endpoint does not look like a login endpoint (no password form and not JSON auth)
        return AuthResult(
            success=False,
            login_url=url,
            message="Endpoint has no login form or JSON API authentication structure.",
            status_code=get_resp.status_code
        ), False

    def _attempt_html_form_login(
        self,
        page_url: str,
        get_resp: requests.Response,
        form: Dict[str, Any],
        anon_status: int = 0,
        anon_url: str = "",
        anon_text: str = ""
    ) -> Tuple[AuthResult, bool]:
        """Parse HTML login form, populate user/pass and CSRF token, and submit."""
        if self.credential_submissions_count >= MAX_CREDENTIAL_SUBMISSIONS:
            return AuthResult(success=False, login_url=page_url, message="Max credential submissions limit reached."), False

        action = form.get("action") or ""
        post_url = urllib.parse.urljoin(page_url, action)

        user_field = None
        pass_field = None

        for field_name, input_type in form["inputs"].items():
            fn_lower = field_name.lower()
            if input_type == "password" or any(p in fn_lower for p in PASSWORD_FIELD_CANDIDATES):
                pass_field = field_name
            elif any(u == fn_lower for u in USERNAME_FIELD_CANDIDATES) or any(u in fn_lower for u in ["user", "email", "login"]):
                user_field = field_name

        if not pass_field:
            return AuthResult(success=False, login_url=page_url, message="Password input field could not be identified"), False

        if not user_field:
            for field_name, input_type in form["inputs"].items():
                if field_name != pass_field and input_type in ("text", "email"):
                    user_field = field_name
                    break

        if not user_field:
            user_field = "username"

        payload = dict(form.get("hidden_fields", {}))
        payload[user_field] = self.username
        payload[pass_field] = self.password

        for cookie_name, cookie_val in self.session.cookies.items():
            if any(c in cookie_name.lower() for c in ["csrf", "xsrf"]):
                if not any(c in payload for c in CSRF_TOKEN_CANDIDATES):
                    payload["csrf_token"] = cookie_val

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": page_url,
            "Origin": self.base_url,
        }

        # Snapshot cookie jar before the POST
        cookies_before = dict(self.session.cookies)
        self.credential_submissions_count += 1

        try:
            resp = self.session.post(
                post_url,
                data=payload,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            return self._evaluate_auth_response(post_url, resp, cookies_before, anon_status, anon_url, anon_text)
        except requests.RequestException as exc:
            return AuthResult(success=False, login_url=post_url, message=f"POST error: {exc}"), False

    def _attempt_json_api_login(
        self,
        url: str,
        anon_status: int = 0,
        anon_url: str = "",
        anon_text: str = ""
    ) -> Tuple[AuthResult, bool]:
        if "@" in self.username:
            payload_variations = [
                {"email": self.username, "password": self.password},
                {"username": self.username, "password": self.password},
                {"identifier": self.username, "password": self.password},
            ]
        else:
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

        last_res = AuthResult(success=False, login_url=url, message="JSON login attempts failed")
        was_rejected = False

        for payload in payload_variations:
            if self.credential_submissions_count >= MAX_CREDENTIAL_SUBMISSIONS:
                break

            cookies_before = dict(self.session.cookies)
            self.credential_submissions_count += 1

            try:
                resp = self.session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                auth_res, rejected = self._evaluate_auth_response(url, resp, cookies_before, anon_status, anon_url, anon_text)
                if auth_res.success:
                    return auth_res, False
                if rejected:
                    was_rejected = True
                    last_res = auth_res
                    break
                last_res = auth_res
            except requests.RequestException as exc:
                logger.debug(f"[AutoAuth] JSON login probe failed for {url}: {exc}")
                continue

        return last_res, was_rejected

    def _evaluate_auth_response(
        self,
        login_url: str,
        resp: requests.Response,
        cookies_before: Dict[str, str],
        anon_status: int = 0,
        anon_url: str = "",
        anon_text: str = ""
    ) -> Tuple[AuthResult, bool]:
        """Inspect response to determine if login succeeded and extract tokens/cookies."""
        # Check 1 & 2: Check for explicit rejection or 401/403 status
        if _is_clear_credential_rejection(resp):
            return AuthResult(
                success=False,
                login_url=login_url,
                message=f"Server rejected credentials (status {resp.status_code}).",
                status_code=resp.status_code
            ), True

        # Check 3: Did we receive new or changed session cookies from the login response?
        cookies_after = dict(self.session.cookies)
        resp_cookies = dict(getattr(resp, "cookies", {}) or {})
        new_or_changed_cookies = dict(resp_cookies)
        for k, v in cookies_after.items():
            if k not in cookies_before or cookies_before[k] != v:
                new_or_changed_cookies[k] = v

        # Check 4: Did we receive a JSON response containing an auth token?
        token = None
        auth_headers = {}
        try:
            data = resp.json()
            token = _extract_token_from_json(data)
        except (ValueError, json.JSONDecodeError, AttributeError):
            pass

        if token:
            auth_headers["Authorization"] = f"Bearer {token}"

        has_new_cookies = len(new_or_changed_cookies) > 0
        has_token = token is not None
        status_ok = resp.status_code in (200, 201, 302, 303, 307)
        is_redirect_away = resp.status_code in (301, 302, 303, 307) and getattr(resp, "url", "") and "/login" not in resp.url.lower()

        if not (has_new_cookies or has_token or is_redirect_away) or not status_ok:
            return AuthResult(
                success=False,
                login_url=login_url,
                message=f"Response status {resp.status_code} did not establish an authenticated session.",
                status_code=resp.status_code
            ), False

        # Check 5: Post-login verification step
        verified = self._verify_authenticated_session(
            token, auth_headers, new_or_changed_cookies, is_redirect_away,
            anon_status, anon_url, anon_text
        )

        if not verified:
            return AuthResult(
                success=False,
                login_url=login_url,
                message="Post-login session verification failed.",
                status_code=resp.status_code
            ), False

        captured_cookies = dict(self.session.cookies) if (has_new_cookies or is_redirect_away) else new_or_changed_cookies
        return AuthResult(
            success=True,
            cookies=captured_cookies,
            headers=auth_headers,
            login_url=login_url,
            token=token,
            message="Login successful. Session credentials captured and verified.",
            status_code=resp.status_code
        ), False

    def _verify_authenticated_session(
        self,
        token: Optional[str],
        auth_headers: Dict[str, str],
        new_cookies: Dict[str, str],
        is_redirect_away: bool,
        anon_status: int,
        anon_url: str,
        anon_text: str
    ) -> bool:
        """Verify authenticated session against anonymous baseline."""
        try:
            verify_resp = self.session.get(
                self.verify_url,
                headers=dict(auth_headers),
                timeout=self.timeout,
                allow_redirects=True
            )
        except Exception as e:
            logger.debug(f"[AutoAuth] Verify request failed: {e}")
            return False

        # A. If anonymous was 401/403 and authenticated is 200:
        if anon_status in (401, 403) and verify_resp.status_code == 200:
            return True

        # B. If anonymous redirected to login and authenticated stays on root or non-login:
        if "/login" in anon_url.lower() and "/login" not in getattr(verify_resp, "url", "").lower() and verify_resp.status_code == 200:
            return True

        # C. Check for logout links or username appearing in authenticated text:
        verify_text = verify_resp.text or ""
        verify_lower = verify_text.lower()
        logout_keywords = ["logout", "log-out", "signout", "sign-out", "logoff", "sign off"]
        has_new_logout = any(kw in verify_lower for kw in logout_keywords) and not any(kw in anon_text.lower() for kw in logout_keywords)
        has_new_username = self.username.lower() in verify_lower and self.username.lower() not in anon_text.lower()

        if has_new_logout or has_new_username:
            return True

        # D. Login POST redirected away from login (e.g. 302 to /dashboard) and verify is not on login:
        if is_redirect_away and "/login" not in getattr(verify_resp, "url", "").lower():
            return True

        # E. Token alone: requires status change (A/B), logout/username (C), or redirect (D)
        if token and not new_cookies:
            if anon_status in (401, 403) and verify_resp.status_code == 200:
                return True
            return False

        # F. Cookies or session: require material body difference from anonymous baseline
        if new_cookies or is_redirect_away:
            anon_clean = anon_text.strip()
            verify_clean = verify_text.strip()
            if anon_clean and verify_clean:
                if anon_clean != verify_clean and abs(len(verify_clean) - len(anon_clean)) >= 20:
                    return True

        return False
