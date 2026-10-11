"""
Single Page Application (SPA) and Soft-404 Calibration Detector for AutoSecAudit.

Prevents false positive findings on targets running frontend SPAs (React, Vue, Vite, Next.js)
where unhandled or non-existent URLs return HTTP 200 with index.html.
"""

import uuid
import hashlib
import logging
import re
from typing import Optional
import requests

logger = logging.getLogger(__name__)


class SPADetector:
    """Detects if a target uses an SPA catch-all router and filters soft-404 responses."""

    def __init__(self, base_url: str, session: Optional[requests.Session] = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.is_spa_catchall: bool = False
        self.baseline_status: int = 404
        self.baseline_length: int = 0
        self.baseline_hash: str = ""
        self.baseline_title: str = ""
        self._calibrate()

    def _calibrate(self) -> None:
        """Send a probe to a randomized non-existent path to detect catch-all behavior."""
        dummy_path = f"/autosec-probe-{uuid.uuid4().hex[:12]}"
        probe_url = f"{self.base_url}{dummy_path}"
        try:
            resp = self.session.get(
                probe_url,
                timeout=(2.0, 5.0),
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": "AutoSecAudit/2.0 SPADetector"}
            )
            if resp.status_code == 200:
                self.is_spa_catchall = True
                self.baseline_status = 200
                self.baseline_length = len(resp.text)
                self.baseline_hash = hashlib.md5(resp.text.encode("utf-8")).hexdigest()
                
                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    self.baseline_title = title_match.group(1).strip()
                
                logger.info(
                    f"[SPADetector] Target {self.base_url} is an SPA catch-all router "
                    f"(baseline length: {self.baseline_length} bytes, hash: {self.baseline_hash[:8]})."
                )
        except Exception as exc:
            logger.debug(f"[SPADetector] Calibration probe failed for {probe_url}: {exc}")

    def is_soft_404(self, resp: Optional[requests.Response]) -> bool:
        """
        Check if a given response is a soft-404 (an SPA fallback response).
        
        Returns True if the response matches the baseline index.html.
        """
        if resp is None:
            return False

        if not self.is_spa_catchall:
            return False

        # Non-200 responses are handled normally by status codes
        if resp.status_code != 200:
            return False

        # 1. Exact body hash match with baseline index.html
        resp_hash = hashlib.md5(resp.text.encode("utf-8")).hexdigest()
        if resp_hash == self.baseline_hash:
            return True

        # 2. Check if response is HTML and within length tolerance
        content_type = resp.headers.get("Content-Type", "").lower()
        is_html = "html" in content_type or "<!doctype" in resp.text[:150].lower() or "<html" in resp.text[:150].lower()
        
        if is_html:
            diff = abs(len(resp.text) - self.baseline_length)
            # Within 50 bytes or within 4% of baseline length
            if diff < 50 or (self.baseline_length > 0 and (diff / self.baseline_length) < 0.04):
                return True
            
            # If title matches the baseline SPA title
            if self.baseline_title:
                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if title_match and title_match.group(1).strip() == self.baseline_title:
                    return True

        return False
