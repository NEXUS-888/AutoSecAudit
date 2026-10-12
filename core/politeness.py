"""
Adaptive Rate Limiter & Politeness Engine for AutoSecAudit.

Prevents target service exhaustion, WAF rate-limiting, and IP bans
through jittered request pacing, automatic exponential backoff on HTTP 429/503,
and request header normalization.
"""

import time
import random
import logging
import threading
from typing import Dict, Any, Optional

import config

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "AutoSecAudit/2.0"
DEFAULT_REQUEST_INTERVAL_MS = int(getattr(config, "SCAN_REQUEST_INTERVAL_MS", 50))


class PolitenessEngine:
    """
    Manages request throttling, jitter delays, and backoff recovery.
    Thread-safe for concurrent scanning plugins.
    """

    def __init__(
        self,
        min_jitter_ms: int = 0,
        max_jitter_ms: int = 25,
        max_retries_on_429: int = 2,
        request_interval_ms: Optional[int] = None,
        pacing_ms: Optional[int] = None,
        **kwargs: Any,
    ):
        self.min_jitter_ms = min_jitter_ms
        self.max_jitter_ms = max_jitter_ms
        self.max_retries_on_429 = max_retries_on_429
        if pacing_ms is not None:
            self.request_interval_ms = pacing_ms
        elif "interval_ms" in kwargs:
            self.request_interval_ms = kwargs["interval_ms"]
        elif request_interval_ms is not None:
            self.request_interval_ms = request_interval_ms
        else:
            self.request_interval_ms = DEFAULT_REQUEST_INTERVAL_MS
        self.consecutive_429s = 0
        self._next_allowed_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def pacing_ms(self) -> int:
        return self.request_interval_ms

    @pacing_ms.setter
    def pacing_ms(self, val: int) -> None:
        self.request_interval_ms = val

    def pace_request(self) -> None:
        """
        Apply thread-safe global rate limiting delay between requests.
        Keeps shared _next_allowed_at under lock, reservations space out callers by interval.
        """
        now = time.monotonic()
        with self._lock:
            if self.request_interval_ms > 0:
                interval = self.request_interval_ms / 1000.0
            else:
                interval = 0.0

            if interval <= 0.0:
                if self.max_jitter_ms > 0:
                    min_j = max(0, self.min_jitter_ms)
                    max_j = max(min_j, self.max_jitter_ms)
                    delay = random.uniform(min_j, max_j) / 1000.0
                else:
                    delay = 0.0
                if delay > 0:
                    time.sleep(delay)
                return

            scheduled_time = max(now, self._next_allowed_at)
            self._next_allowed_at = scheduled_time + interval
            sleep_duration = scheduled_time - now

        if sleep_duration > 0:
            time.sleep(sleep_duration)
            while time.monotonic() < scheduled_time:
                time.sleep(0.0005)

    def handle_response_status(self, status_code: int) -> float:
        """
        Calculates recommended sleep penalty if throttled by target.
        Returns sleep duration in seconds (0.0 if normal).
        """
        with self._lock:
            if status_code in (429, 503):
                self.consecutive_429s += 1
                backoff = min(1.0 * (2 ** (self.consecutive_429s - 1)), 8.0)
            else:
                if self.consecutive_429s > 0:
                    self.consecutive_429s = max(0, self.consecutive_429s - 1)
                return 0.0

        logger.warning(
            f"[Politeness] Target returned HTTP {status_code}. Backing off for {backoff:.1f}s (strike {self.consecutive_429s})"
        )
        time.sleep(backoff)
        return backoff

    @staticmethod
    def get_polite_headers(custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate standardized headers with stable User-Agent (no UA rotation)."""
        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if custom_headers:
            headers.update(custom_headers)
        return headers
