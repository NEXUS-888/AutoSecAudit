"""
Adaptive Rate Limiter & Politeness Engine for AutoSecAudit.

Prevents target service exhaustion, WAF rate-limiting, and IP bans
through jittered request pacing, automatic exponential backoff on HTTP 429/503,
and request header normalization.
"""

import time
import random
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "AutoSecAudit/2.0 (Security Auditor; https://github.com/NEXUS-888/AutoSecAudit)",
]


class PolitenessEngine:
    """
    Manages request throttling, jitter delays, and backoff recovery.
    """

    def __init__(
        self,
        min_jitter_ms: int = 0,
        max_jitter_ms: int = 25,
        max_retries_on_429: int = 2,
    ):
        self.min_jitter_ms = min_jitter_ms
        self.max_jitter_ms = max_jitter_ms
        self.max_retries_on_429 = max_retries_on_429
        self.consecutive_429s = 0

    def pace_request(self) -> None:
        """Apply light randomized jitter delay between active attack probes."""
        if self.max_jitter_ms > 0:
            delay = random.uniform(self.min_jitter_ms, self.max_jitter_ms) / 1000.0
            time.sleep(delay)

    def handle_response_status(self, status_code: int) -> float:
        """
        Calculates recommended sleep penalty if throttled by target.
        Returns sleep duration in seconds (0.0 if normal).
        """
        if status_code in (429, 503):
            self.consecutive_429s += 1
            backoff = min(1.0 * (2 ** (self.consecutive_429s - 1)), 8.0)
            logger.warning(
                f"[Politeness] Target returned HTTP {status_code}. Backing off for {backoff:.1f}s (strike {self.consecutive_429s})"
            )
            time.sleep(backoff)
            return backoff
        else:
            if self.consecutive_429s > 0:
                self.consecutive_429s = max(0, self.consecutive_429s - 1)
            return 0.0

    @staticmethod
    def get_polite_headers(custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate standardized headers with randomized User-Agent."""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if custom_headers:
            headers.update(custom_headers)
        return headers
