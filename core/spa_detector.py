"""
Single Page Application (SPA) and Soft-404 Calibration Detector for AutoSecAudit.

Prevents false positive findings on targets running frontend SPAs (React, Vue, Vite, Next.js)
where unhandled or non-existent URLs return HTTP 200 with index.html.
"""

import difflib
import uuid
import hashlib
import logging
import re
from typing import Optional
import requests

logger = logging.getLogger(__name__)


class SPADetector:
    """Detects if a target uses an SPA catch-all router and filters soft-404 responses."""

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, calibrate: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.is_spa_catchall: bool = False
        self.baseline_status: int = 404
        self.baseline_length: int = 0
        self.baseline_hash: str = ""
        self.baseline_title: str = ""
        self.baseline_text: str = ""
        if calibrate:
            self._calibrate()

    def _calibrate(self) -> None:
        """Send 2-3 probes (including one with file extension) following redirects to detect catch-all behavior."""
        probes = [
            f"{self.base_url}/autosec-probe-{uuid.uuid4().hex[:12]}",
            f"{self.base_url}/autosec-probe-{uuid.uuid4().hex[:12]}/",
            f"{self.base_url}/autosec-probe-{uuid.uuid4().hex[:12]}.html",
        ]
        success_resps = []
        for probe_url in probes:
            try:
                resp = self.session.get(
                    probe_url,
                    timeout=(2.0, 5.0),
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "AutoSecAudit/2.0 SPADetector"}
                )
                if resp.status_code == 200:
                    success_resps.append(resp)
            except Exception as exc:
                logger.debug(f"[SPADetector] Calibration probe failed for {probe_url}: {exc}")

        # If at least 2 probes returned HTTP 200, target is an SPA catch-all
        if len(success_resps) >= 2:
            self.is_spa_catchall = True
            baseline_resp = success_resps[0]
            self.baseline_status = 200
            self.baseline_length = len(baseline_resp.text)
            self.baseline_text = baseline_resp.text
            self.baseline_hash = hashlib.md5(baseline_resp.text.encode("utf-8")).hexdigest()

            title_match = re.search(r"<title[^>]*>(.*?)</title>", baseline_resp.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                self.baseline_title = title_match.group(1).strip()

            logger.info(
                f"[SPADetector] Target {self.base_url} is an SPA catch-all router "
                f"(baseline length: {self.baseline_length} bytes, hash: {self.baseline_hash[:8]})."
            )

    def is_soft_404(self, resp: Optional[requests.Response]) -> bool:
        """
        Check if a given response is a soft-404 (an SPA fallback response).
        
        Returns True if the response matches the baseline index.html within tolerance.
        A site with a shared title differing by more than 30% in content is NOT a soft-404.
        """
        if resp is None:
            return False

        if not self.is_spa_catchall:
            return False

        # Non-200 responses are handled normally by status codes
        if resp.status_code != 200:
            return False

        diff = abs(len(resp.text) - self.baseline_length)
        diff_ratio = diff / max(self.baseline_length, 1)

        # Pages differing by more than 30% in content are not soft-404s
        if diff_ratio > 0.30:
            return False

        # 1. Exact body hash match with baseline index.html
        resp_hash = hashlib.md5(resp.text.encode("utf-8")).hexdigest()
        if resp_hash == self.baseline_hash:
            return True

        # When the hash doesn't match, compare against baseline_text content similarity
        if not self.baseline_text:
            return False

        # Compare content similarity on capped text (up to 10,000 characters)
        cap = 10000
        similarity = difflib.SequenceMatcher(
            None, self.baseline_text[:cap], resp.text[:cap]
        ).ratio()
        if similarity < 0.70:
            return False

        # 2. Check if response is HTML and within length/similarity tolerance
        content_type = resp.headers.get("Content-Type", "").lower()
        is_html = "html" in content_type or "<!doctype" in resp.text[:150].lower() or "<html" in resp.text[:150].lower()

        if is_html:
            # Within 50 bytes or within 4% of baseline length
            if diff < 50 or diff_ratio < 0.04:
                return True

            # Title equality only counts together with length/similarity tolerance (diff_ratio <= 0.30 and similarity >= 0.70)
            if self.baseline_title:
                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if title_match and title_match.group(1).strip() == self.baseline_title:
                    return True

        return False
