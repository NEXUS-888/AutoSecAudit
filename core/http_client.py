"""
Shared, Scope-Aware HTTP Client for AutoSecAudit (ScanHttpClient).

Provides:
- A shared requests.Session carrying authentication headers and cookies.
- Constant User-Agent header (AutoSecAudit/2.0).
- Thread-safe global politeness rate limiting shared across plugins.
- Default connection and read timeouts.
- Hop-by-hop manual redirect resolution with strict scope verification (same origin + is_target_allowed).
- Automatic exponential backoff on HTTP 429/503 honoring Retry-After headers.
- Never returns 429/503 responses to plugin detection logic.
"""

import time
import email.utils
import logging
import threading
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List, Union
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.politeness import PolitenessEngine
from core.utils import is_target_allowed

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "AutoSecAudit/2.0"
DEFAULT_TIMEOUT = (3.0, 8.0)  # (connect_timeout, read_timeout)
MAX_RETRIES_429 = 2
MAX_REDIRECTS = 10


def parse_retry_after(header_val: Optional[str]) -> Optional[float]:
    """Parse HTTP Retry-After header into delay in seconds."""
    if not header_val:
        return None
    val = header_val.strip()
    try:
        return float(val)
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(val)
        delta = dt.timestamp() - time.time()
        return max(0.0, delta)
    except Exception:
        pass
    return None


class ScanHttpClient:
    """
    Centralized HTTP client owned by the Engine and injected into all scanning plugins.
    """

    def __init__(
        self,
        target: Optional[str] = None,
        session: Optional[requests.Session] = None,
        politeness: Optional[PolitenessEngine] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        default_timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
        max_retries_on_429: Optional[int] = None,
        mock_mode: bool = False,
        request_interval_ms: Optional[int] = None,
        pacing_ms: Optional[int] = None,
        **kwargs: Any,
    ):
        self.target: str = target or ""
        self.default_timeout: Tuple[float, float] = default_timeout
        self.mock_mode: bool = mock_mode
        self._lock = threading.Lock()
        self._throttled_count: int = 0

        self.politeness = politeness or PolitenessEngine()
        pacing_val = pacing_ms if pacing_ms is not None else request_interval_ms
        if pacing_val is not None:
            self.politeness.request_interval_ms = pacing_val

        if max_retries_on_429 is not None:
            self.max_retries_on_429 = max_retries_on_429
        else:
            self.max_retries_on_429 = getattr(self.politeness, "max_retries_on_429", MAX_RETRIES_429)

        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        self.session.verify = False

        if auth_headers:
            self.session.headers.update(auth_headers)
        if auth_cookies:
            self.session.cookies.update(auth_cookies)

    @property
    def throttled_count(self) -> int:
        """Thread-safe getter for throttled requests count."""
        with self._lock:
            return self._throttled_count

    @throttled_count.setter
    def throttled_count(self, val: int) -> None:
        """Thread-safe setter for throttled requests count."""
        with self._lock:
            self._throttled_count = val

    def increment_throttled_count(self) -> int:
        """Atomically increment and return throttled requests count."""
        with self._lock:
            self._throttled_count += 1
            return self._throttled_count

    @property
    def request_interval_ms(self) -> int:
        return self.politeness.request_interval_ms

    @request_interval_ms.setter
    def request_interval_ms(self, val: int) -> None:
        self.politeness.request_interval_ms = val

    @property
    def pacing_ms(self) -> int:
        return self.politeness.pacing_ms

    @pacing_ms.setter
    def pacing_ms(self, val: int) -> None:
        self.politeness.pacing_ms = val

    def set_target(self, target: str) -> None:
        """Update target URL scope."""
        self.target = target or ""

    def set_auth(
        self,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        """Update authentication credentials across session."""
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

    def is_in_scope(self, url: str) -> bool:
        """
        Verify that a URL is in-scope:
        1. Target policy allows the host (is_target_allowed: private/loopback).
        2. If target is configured, exact origin matches (scheme + hostname + port).
        Catches parse/port errors safely and returns False.
        """
        if not url:
            return False

        try:
            allowed, _ = is_target_allowed(url)
            if not allowed:
                return False

            if self.target:
                target_parsed = urllib.parse.urlparse(self.target)
                url_parsed = urllib.parse.urlparse(url)

                target_scheme = target_parsed.scheme.lower() or "http"
                url_scheme = url_parsed.scheme.lower() or "http"

                target_host = (target_parsed.hostname or "").lower()
                url_host = (url_parsed.hostname or "").lower()

                target_port = target_parsed.port or (443 if target_scheme == "https" else 80)
                url_port = url_parsed.port or (443 if url_scheme == "https" else 80)

                if (
                    url_scheme != target_scheme
                    or url_host != target_host
                    or url_port != target_port
                ):
                    return False

            return True
        except (ValueError, Exception) as exc:
            logger.debug(f"[ScanHttpClient] is_in_scope check failed for {url}: {exc}")
            return False

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[Union[float, Tuple[float, float]]] = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        """
        Execute an HTTP request with politeness pacing, manual scope-checked redirects,
        and automatic 429/503 exponential backoff. Never raises exceptions to plugins.
        """
        try:
            if json_data is None and "json" in kwargs:
                json_data = kwargs.pop("json")
            # 0. Initial scope check
            initial_check_url = url
            if self.target and not urllib.parse.urlparse(url).scheme:
                initial_check_url = urllib.parse.urljoin(self.target, url)
            if not self.is_in_scope(initial_check_url):
                logger.warning(f"[ScanHttpClient] Initial URL out of scope: {url}")
                return None

            req_timeout = timeout if timeout is not None else self.default_timeout
            attempt_429 = 0

            while True:
                # 1. Pacing delay
                self.politeness.pace_request()

                # 2. Execute request with manual hop-by-hop redirects
                try:
                    resp = self._execute_with_redirects(
                        method=method,
                        url=url,
                        params=params,
                        json_data=json_data,
                        data=data,
                        headers=headers,
                        timeout=req_timeout,
                        allow_redirects=allow_redirects,
                        **kwargs,
                    )
                except requests.RequestException as exc:
                    logger.debug(f"[ScanHttpClient] Request failed for {url}: {exc}")
                    return None
                except Exception as exc:
                    logger.debug(f"[ScanHttpClient] Unexpected error executing request for {url}: {exc}")
                    return None

                if resp is None:
                    return None

                # 3. Handle rate-limiting (429 or 503)
                if resp.status_code in (429, 503):
                    if attempt_429 < self.max_retries_on_429:
                        attempt_429 += 1
                        raw_retry_after = resp.headers.get("Retry-After")
                        parsed_delay = parse_retry_after(raw_retry_after)

                        if parsed_delay is not None and parsed_delay > 0:
                            backoff = min(parsed_delay, 10.0)
                        else:
                            backoff = min(1.0 * (2 ** (attempt_429 - 1)), 8.0)

                        logger.warning(
                            f"[ScanHttpClient] Target returned HTTP {resp.status_code} on {url}. "
                            f"Backing off for {backoff:.2f}s (retry {attempt_429}/{self.max_retries_on_429})..."
                        )
                        time.sleep(backoff)
                        continue
                    else:
                        self.increment_throttled_count()
                        logger.warning(
                            f"[ScanHttpClient] Target persistent {resp.status_code} after {self.max_retries_on_429} retries on {url}. "
                            f"Suppressing response from detection logic."
                        )
                        return None

                # Normal response received
                return resp
        except Exception as exc:
            logger.debug(f"[ScanHttpClient] Request unhandled exception for {url}: {exc}")
            return None

    def safe_request(self, *args, **kwargs) -> Optional[requests.Response]:
        """Alias for request()."""
        return self.request(*args, **kwargs)

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("OPTIONS", url, **kwargs)

    def _execute_with_redirects(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Any = DEFAULT_TIMEOUT,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        """
        Execute request, following redirects manually one hop at a time while checking scope.
        """
        current_method = method.upper()
        current_url = url
        current_params = params
        current_json = json_data
        current_data = data
        history: List[requests.Response] = []

        req_headers = dict(headers or {})
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = DEFAULT_USER_AGENT

        for hop in range(MAX_REDIRECTS):
            req = requests.Request(
                method=current_method,
                url=current_url,
                params=current_params,
                json=current_json,
                data=current_data,
                headers=req_headers,
            )
            prepared = self.session.prepare_request(req)
            # Ensure constant User-Agent
            prepared.headers["User-Agent"] = DEFAULT_USER_AGENT

            send_kwargs = {
                "timeout": timeout,
                "allow_redirects": False,
                "verify": False,
            }
            # Pass any extra kwargs recognized by send
            for k in ("proxies", "stream", "cert"):
                if k in kwargs:
                    send_kwargs[k] = kwargs[k]

            resp = self.session.send(prepared, **send_kwargs)

            # Check if redirection is required
            if allow_redirects and resp.is_redirect and "Location" in resp.headers:
                location = resp.headers["Location"]
                try:
                    resolved_url = urllib.parse.urljoin(current_url, location)
                except Exception as exc:
                    logger.warning(
                        f"[ScanHttpClient] Failed to resolve redirect Location '{location}': {exc}"
                    )
                    resp.history = history
                    return resp

                # Scope Check: Must be in-scope on every hop
                if not self.is_in_scope(resolved_url):
                    logger.warning(
                        f"[ScanHttpClient] Redirect to out-of-scope host blocked: {resolved_url} (from {current_url})"
                    )
                    resp.history = history
                    return resp

                # Record history and prepare next hop
                history.append(resp)
                current_url = resolved_url

                # Adjust method for 301/302/303 as per standard HTTP behavior
                if resp.status_code in (301, 302, 303):
                    current_method = "GET"
                    current_params = None
                    current_json = None
                    current_data = None
                # 307 and 308 preserve the original method and payload

                continue

            # Non-redirect response or redirects disabled
            resp.history = history
            return resp

        # Exceeded maximum redirects
        logger.warning(f"[ScanHttpClient] Exceeded maximum redirect limit ({MAX_REDIRECTS}) for {url}")
        resp.history = history
        return resp
