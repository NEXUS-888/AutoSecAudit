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
import socket
import threading
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List, Union
import requests
import requests.adapters
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from core.politeness import PolitenessEngine
from core.utils import is_target_allowed
from core.timing import global_timing_controller

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "AutoSecAudit/2.0"
DEFAULT_TIMEOUT = (3.0, 8.0)  # (connect_timeout, read_timeout)
MAX_RETRIES_429 = 2
MAX_REDIRECTS = 10
STREAM_CHUNK_SIZE = 65536

_watchdog_tls = threading.local()


class _RequestWatchdog:
    """
    Per-request wall-clock watchdog that aborts active sockets if req_deadline expires
    during either the header phase (session.send) or the body phase (_consume_bounded_body).
    """

    def __init__(self, deadline: float):
        self.deadline: float = deadline
        self.triggered: bool = False
        self.counted_timeout: bool = False
        self._closed: bool = False
        self._lock = threading.Lock()
        self._conns: List[Any] = []
        self._socks: List[Any] = []
        self._timer: Optional[threading.Timer] = None

    def __enter__(self) -> "_RequestWatchdog":
        _watchdog_tls.watchdog = self
        delay = max(0.001, self.deadline - time.monotonic())
        self._timer = threading.Timer(delay, self._on_timeout)
        self._timer.daemon = True
        self._timer.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        with self._lock:
            self._closed = True
            if self._timer is not None:
                self._timer.cancel()
        if getattr(_watchdog_tls, "watchdog", None) is self:
            _watchdog_tls.watchdog = None

    def mark_timed_out(self, client: "ScanHttpClient") -> None:
        with self._lock:
            if self.counted_timeout:
                return
            self.counted_timeout = True
        client.increment_requests_timed_out()

    def register_conn(self, conn: Any) -> None:
        if conn is None:
            return
        sock = getattr(conn, "sock", None)
        with self._lock:
            if conn not in self._conns:
                self._conns.append(conn)
            if sock is not None and sock not in self._socks:
                self._socks.append(sock)
            should_abort = self.triggered or (not self._closed and time.monotonic() >= self.deadline)
            if should_abort:
                self.triggered = True
        if should_abort and sock is not None:
            self._abort_socket(sock)

    def register_socket(self, sock: Any) -> None:
        if sock is None:
            return
        with self._lock:
            if sock not in self._socks:
                self._socks.append(sock)
            should_abort = self.triggered or (not self._closed and time.monotonic() >= self.deadline)
            if should_abort:
                self.triggered = True
        if should_abort:
            self._abort_socket(sock)

    @staticmethod
    def _abort_socket(sock: Any) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def _on_timeout(self) -> None:
        socks: List[Any] = []
        with self._lock:
            if self._closed:
                return
            self.triggered = True
            socks.extend(self._socks)
            for conn in self._conns:
                s = getattr(conn, "sock", None)
                if s is not None and s not in socks:
                    socks.append(s)
        for s in socks:
            self._abort_socket(s)


class _WatchdogHTTPAdapter(requests.adapters.HTTPAdapter):
    """HTTPAdapter that registers underlying urllib3 connections/sockets with _RequestWatchdog."""

    @staticmethod
    def _wrap_pool(pool: Any) -> None:
        if pool is None or getattr(pool, "_autosec_watchdog_wrapped", False):
            return
        orig_get_conn = getattr(pool, "_get_conn", None)
        if not callable(orig_get_conn):
            return

        def wrapped_get_conn(*args: Any, **kwargs: Any) -> Any:
            conn = orig_get_conn(*args, **kwargs)
            wd: Optional[_RequestWatchdog] = getattr(_watchdog_tls, "watchdog", None)
            if wd is not None:
                wd.register_conn(conn)
            if conn is not None and not getattr(conn, "_autosec_watchdog_wrapped", False):
                orig_new_conn = getattr(conn, "_new_conn", None)
                if callable(orig_new_conn):
                    def wrapped_new_conn(*n_args: Any, **n_kwargs: Any) -> Any:
                        sock = orig_new_conn(*n_args, **n_kwargs)
                        cur_wd: Optional[_RequestWatchdog] = getattr(_watchdog_tls, "watchdog", None)
                        if cur_wd is not None:
                            cur_wd.register_socket(sock)
                        return sock

                    conn._new_conn = wrapped_new_conn
                conn._autosec_watchdog_wrapped = True
            return conn

        pool._get_conn = wrapped_get_conn
        pool._autosec_watchdog_wrapped = True

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Union[bool, str] = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        try:
            if hasattr(self, "get_connection_with_tls_context"):
                pool = self.get_connection_with_tls_context(request, verify, proxies=proxies, cert=cert)
            else:
                pool = self.get_connection(request.url, proxies)
            self._wrap_pool(pool)
        except Exception:
            pass
        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


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
        timing_controller: Optional[Any] = None,
        **kwargs: Any,
    ):
        self.target: str = target or ""
        self.default_timeout: Tuple[float, float] = default_timeout
        self.mock_mode: bool = mock_mode
        self._lock = threading.Lock()
        self._throttled_count: int = 0
        self._responses_truncated: int = 0
        self._requests_timed_out: int = 0
        self._max_response_bytes: Optional[int] = kwargs.pop("max_response_bytes", None)
        self._max_request_seconds: Optional[float] = kwargs.pop("max_request_seconds", None)
        self.timing_controller = timing_controller or global_timing_controller

        self.politeness = politeness or PolitenessEngine()
        pacing_val = pacing_ms if pacing_ms is not None else request_interval_ms
        if pacing_val is not None:
            self.politeness.request_interval_ms = pacing_val

        if max_retries_on_429 is not None:
            self.max_retries_on_429 = max_retries_on_429
        else:
            self.max_retries_on_429 = getattr(self.politeness, "max_retries_on_429", MAX_RETRIES_429)

        self.session = session or requests.Session()
        self._mount_watchdog_adapters(self.session)
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        self.session.verify = False

        if auth_headers:
            self.session.headers.update(auth_headers)
        if auth_cookies:
            self.session.cookies.update(auth_cookies)

        self.deadline: Optional[float] = None

    @staticmethod
    def _mount_watchdog_adapters(sess: Any) -> None:
        if not isinstance(sess, requests.Session):
            return
        for prefix in ("http://", "https://"):
            existing = sess.adapters.get(prefix)
            if not isinstance(existing, _WatchdogHTTPAdapter):
                sess.mount(prefix, _WatchdogHTTPAdapter())

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
    def responses_truncated(self) -> int:
        """Thread-safe getter for responses truncated count."""
        with self._lock:
            return self._responses_truncated

    @responses_truncated.setter
    def responses_truncated(self, val: int) -> None:
        """Thread-safe setter for responses truncated count."""
        with self._lock:
            self._responses_truncated = val

    def increment_responses_truncated(self) -> int:
        """Atomically increment and return responses truncated count."""
        with self._lock:
            self._responses_truncated += 1
            return self._responses_truncated

    @property
    def requests_timed_out(self) -> int:
        """Thread-safe getter for requests timed out count."""
        with self._lock:
            return self._requests_timed_out

    @requests_timed_out.setter
    def requests_timed_out(self, val: int) -> None:
        """Thread-safe setter for requests timed out count."""
        with self._lock:
            self._requests_timed_out = val

    def increment_requests_timed_out(self) -> int:
        """Atomically increment and return requests timed out count."""
        with self._lock:
            self._requests_timed_out += 1
            return self._requests_timed_out

    @property
    def max_response_bytes(self) -> int:
        if self._max_response_bytes is not None:
            return int(self._max_response_bytes)
        return int(getattr(config, "MAX_RESPONSE_BYTES", 5 * 1024 * 1024))

    @max_response_bytes.setter
    def max_response_bytes(self, val: Optional[int]) -> None:
        self._max_response_bytes = val

    @property
    def max_request_seconds(self) -> float:
        if self._max_request_seconds is not None:
            return float(self._max_request_seconds)
        return float(getattr(config, "MAX_REQUEST_SECONDS", 30))

    @max_request_seconds.setter
    def max_request_seconds(self, val: Optional[float]) -> None:
        self._max_request_seconds = val

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
            # 0. Initial scope and deadline check
            if self.deadline is not None and time.monotonic() > self.deadline:
                logger.warning(f"[ScanHttpClient] Request skipped: scan deadline exceeded for {url}")
                return None

            initial_check_url = url
            if self.target and not urllib.parse.urlparse(url).scheme:
                initial_check_url = urllib.parse.urljoin(self.target, url)
            if not self.is_in_scope(initial_check_url):
                logger.warning(f"[ScanHttpClient] Initial URL out of scope: {url}")
                return None

            req_timeout = timeout if timeout is not None else self.default_timeout
            if self.deadline is not None:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    return None
                if isinstance(req_timeout, (int, float)):
                    req_timeout = min(req_timeout, max(0.1, remaining))

            attempt_429 = 0

            while True:
                if self.deadline is not None and time.monotonic() > self.deadline:
                    return None
                # Wait if another thread is currently running serialized timing verification
                self.timing_controller.wait_if_timing_active()

                # 1. Pacing delay
                self.politeness.pace_request()

                # 2. Execute request with manual hop-by-hop redirects within in-flight tracking
                try:
                    with self.timing_controller.track_in_flight():
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

    @staticmethod
    def _extract_raw_socket(raw: Any) -> Any:
        if raw is None:
            return None
        try:
            fp = getattr(raw, "_fp", None)
            if fp is not None:
                inner_fp = getattr(fp, "fp", None)
                if inner_fp is not None:
                    raw_io = getattr(inner_fp, "raw", None)
                    if raw_io is not None and hasattr(raw_io, "_sock"):
                        return raw_io._sock
                    if hasattr(inner_fp, "_sock"):
                        return inner_fp._sock
                if hasattr(fp, "_sock"):
                    return fp._sock
            conn = getattr(raw, "_connection", None)
            if conn is not None and getattr(conn, "sock", None) is not None:
                return conn.sock
        except Exception:
            pass
        return None

    def _consume_bounded_body(
        self,
        resp: requests.Response,
        max_bytes: int,
        req_deadline: float,
        read_timeout_val: float,
        watchdog: Optional[_RequestWatchdog] = None,
    ) -> requests.Response:
        """
        Read response body in chunks up to max_bytes and up to req_deadline wall time.
        Sets resp.truncated = True if cut short by either limit (False otherwise),
        updates client counters (responses_truncated / requests_timed_out),
        and ensures resp.content, resp.text, and resp.json() work on the resulting body.
        """
        if resp is None:
            return resp

        existing_content = getattr(resp, "_content", False)
        if isinstance(existing_content, (bytes, bytearray)):
            if len(existing_content) > max_bytes:
                resp._content = bytes(existing_content[:max_bytes])
                resp.truncated = True
                self.increment_responses_truncated()
            else:
                resp.truncated = False
            return resp

        raw = getattr(resp, "raw", None)
        sock = self._extract_raw_socket(raw)
        if watchdog is not None and sock is not None:
            watchdog.register_socket(sock)

        buf = bytearray()
        truncated = False
        hit_size_limit = False
        hit_time_limit = False

        if isinstance(raw, urllib3.response.HTTPResponse) and hasattr(raw, "read1"):
            while True:
                if hasattr(raw, "isclosed") and raw.isclosed():
                    if watchdog is not None and watchdog.triggered:
                        truncated = True
                        hit_time_limit = True
                    break

                now = time.monotonic()
                remaining_time = req_deadline - now
                if remaining_time <= 0 or (watchdog is not None and watchdog.triggered):
                    truncated = True
                    hit_time_limit = True
                    break

                if sock is not None:
                    try:
                        sock.settimeout(min(read_timeout_val, max(0.02, remaining_time)))
                    except Exception:
                        pass

                read_amt = min(STREAM_CHUNK_SIZE, max(1, (max_bytes - len(buf)) + 1))
                try:
                    chunk = raw.read1(read_amt, decode_content=True)
                except (
                    requests.exceptions.Timeout,
                    urllib3.exceptions.TimeoutError,
                    TimeoutError,
                    socket.timeout,
                ):
                    truncated = True
                    hit_time_limit = True
                    break
                except Exception as exc:
                    cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
                    if (
                        (watchdog is not None and watchdog.triggered)
                        or isinstance(cause, (TimeoutError, socket.timeout, urllib3.exceptions.TimeoutError))
                        or time.monotonic() >= req_deadline
                    ):
                        truncated = True
                        hit_time_limit = True
                    else:
                        truncated = True
                    break

                if not chunk:
                    if watchdog is not None and watchdog.triggered:
                        truncated = True
                        hit_time_limit = True
                    break

                if len(buf) + len(chunk) > max_bytes:
                    needed = max_bytes - len(buf)
                    if needed > 0:
                        buf.extend(chunk[:needed])
                    truncated = True
                    hit_size_limit = True
                    break

                buf.extend(chunk)
                if hasattr(raw, "isclosed") and raw.isclosed():
                    break
        elif hasattr(resp, "iter_content"):
            try:
                for chunk in resp.iter_content(chunk_size=STREAM_CHUNK_SIZE):
                    if not chunk:
                        if watchdog is not None and watchdog.triggered:
                            truncated = True
                            hit_time_limit = True
                            break
                        continue
                    if len(buf) + len(chunk) > max_bytes:
                        needed = max_bytes - len(buf)
                        if needed > 0:
                            buf.extend(chunk[:needed])
                        truncated = True
                        hit_size_limit = True
                        break
                    buf.extend(chunk)
                    if (watchdog is not None and watchdog.triggered) or time.monotonic() >= req_deadline:
                        truncated = True
                        hit_time_limit = True
                        break
            except (
                requests.exceptions.Timeout,
                urllib3.exceptions.TimeoutError,
                TimeoutError,
                socket.timeout,
            ):
                truncated = True
                hit_time_limit = True
            except Exception as exc:
                truncated = True
                cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
                if (
                    (watchdog is not None and watchdog.triggered)
                    or isinstance(cause, (TimeoutError, socket.timeout, urllib3.exceptions.TimeoutError))
                    or time.monotonic() >= req_deadline
                ):
                    hit_time_limit = True

        try:
            resp.close()
        except Exception:
            pass

        resp._content = bytes(buf)
        resp._content_consumed = True
        resp.truncated = truncated

        if hit_size_limit:
            self.increment_responses_truncated()
        if hit_time_limit:
            if watchdog is not None:
                watchdog.mark_timed_out(self)
            else:
                self.increment_requests_timed_out()

        return resp

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
        self._mount_watchdog_adapters(self.session)

        current_method = method.upper()
        current_url = url
        current_params = params
        current_json = json_data
        current_data = data
        history: List[requests.Response] = []

        req_headers = dict(headers or {})
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = DEFAULT_USER_AGENT

        max_bytes = self.max_response_bytes
        max_seconds = self.max_request_seconds
        req_deadline = time.monotonic() + max_seconds
        resp: Optional[requests.Response] = None

        if isinstance(timeout, tuple) and len(timeout) == 2:
            base_conn_t, base_read_t = float(timeout[0]), float(timeout[1])
        else:
            t_val = float(timeout) if isinstance(timeout, (int, float)) else 8.0
            base_conn_t, base_read_t = t_val, t_val

        with _RequestWatchdog(req_deadline) as watchdog:
            for hop in range(MAX_REDIRECTS):
                now = time.monotonic()
                if self.deadline is not None and now > self.deadline:
                    return None
                if watchdog.triggered or now >= req_deadline:
                    watchdog.mark_timed_out(self)
                    return None

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

                remaining_req = max(0.05, req_deadline - now)
                if self.deadline is not None:
                    remaining_req = min(remaining_req, max(0.05, self.deadline - now))
                if isinstance(timeout, tuple) and len(timeout) == 2:
                    hop_timeout: Any = (min(base_conn_t, remaining_req), min(base_read_t, remaining_req))
                else:
                    hop_timeout = min(base_read_t, remaining_req)

                send_kwargs: Dict[str, Any] = {
                    "timeout": hop_timeout,
                    "allow_redirects": False,
                    "verify": False,
                    "stream": True,
                }
                for k in ("proxies", "cert"):
                    if k in kwargs:
                        send_kwargs[k] = kwargs[k]

                try:
                    resp = self.session.send(prepared, **send_kwargs)
                except (
                    requests.exceptions.Timeout,
                    urllib3.exceptions.TimeoutError,
                    TimeoutError,
                    socket.timeout,
                ):
                    watchdog.mark_timed_out(self)
                    raise
                except Exception as exc:
                    if watchdog.triggered or time.monotonic() >= req_deadline:
                        watchdog.mark_timed_out(self)
                        raise requests.exceptions.ReadTimeout("Request exceeded MAX_REQUEST_SECONDS") from exc
                    raise

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
                        return self._consume_bounded_body(resp, max_bytes, req_deadline, base_read_t, watchdog)

                    # Scope Check: Must be in-scope on every hop
                    if not self.is_in_scope(resolved_url):
                        logger.warning(
                            f"[ScanHttpClient] Redirect to out-of-scope host blocked: {resolved_url} (from {current_url})"
                        )
                        resp.history = history
                        return self._consume_bounded_body(resp, max_bytes, req_deadline, base_read_t, watchdog)

                    # Cleanly close redirect hop body before advancing
                    resp.truncated = False
                    try:
                        resp.close()
                    except Exception:
                        pass

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
                return self._consume_bounded_body(resp, max_bytes, req_deadline, base_read_t, watchdog)

            # Exceeded maximum redirects
            logger.warning(f"[ScanHttpClient] Exceeded maximum redirect limit ({MAX_REDIRECTS}) for {url}")
            if resp is not None:
                resp.history = history
                return self._consume_bounded_body(resp, max_bytes, req_deadline, base_read_t, watchdog)
            return None
