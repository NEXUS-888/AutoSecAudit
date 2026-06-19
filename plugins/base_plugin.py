from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
import logging
import shutil
import requests
import config

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base class for all security scanning plugins."""

    def __init__(self, mock_mode: Optional[bool] = None):
        self.target: str = ""
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self._tool_available: Optional[bool] = None
        self.discovered_endpoints: list = []  # populated by engine from crawler

    def set_discovered_endpoints(self, endpoints: list) -> None:
        """Set discovered endpoints from the web crawler."""
        self.discovered_endpoints = endpoints

    @abstractmethod
    def configure(self, target: str) -> None:
        """Configure the scanner with target URL/IP."""
        self.target = target

    @abstractmethod
    def run(self) -> None:
        """Execute the scanning tool."""
        pass

    @abstractmethod
    def parse_output(self) -> Dict[str, Any]:
        """Parse tool output and return standardized findings."""
        pass

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if the scanning tool is installed and available."""
        if self._tool_available is not None:
            return self._tool_available

        self._tool_available = shutil.which(tool_name) is not None
        if not self._tool_available:
            logger.warning(f"Tool '{tool_name}' not found. Plugin will run in mock mode.")
        return self._tool_available

    def get_standardized_output(self) -> Dict[str, Any]:
        """Execute run() and parse_output() to get standardized findings."""
        tool_name = self._get_tool_name()
        tool_available = self.check_tool_available(tool_name)
        logger.info(f"[DEBUG] {self.__class__.__name__}: mock_mode={self.mock_mode}, tool={tool_name}, available={tool_available}")
        
        if self.mock_mode:
            logger.info(f"Running {self.__class__.__name__} in MOCK mode")
            return self._get_mock_output()

        if not tool_available:
            logger.warning(f"Skipping {self.__class__.__name__}: tool '{tool_name}' not installed and mock mode is OFF")
            return {"tool_name": tool_name, "findings": []}

        self.run()
        return self.parse_output()

    @abstractmethod
    def _get_tool_name(self) -> str:
        """Return the name of the underlying tool."""
        pass

    @abstractmethod
    def _get_mock_output(self) -> Dict[str, Any]:
        """Return mock findings for development/demo."""
        pass

    # ------------------------------------------------------------------
    # Baseline verification helpers
    # ------------------------------------------------------------------
    _baseline_cache: Dict[str, Any] = {}

    def _get_baseline(self, url: str, param: str, method: str = "GET",
                      headers: Optional[Dict] = None, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """
        Fetch a baseline (safe) response for an endpoint.
        Caches results so we only hit each endpoint once.
        """
        cache_key = f"{method}:{url}:{param}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        try:
            safe_value = "test123"
            if method.upper() == "GET":
                resp = requests.get(
                    url, params={param: safe_value},
                    headers=headers or {"User-Agent": "AutoSecAudit/2.0"},
                    timeout=timeout, allow_redirects=True, verify=False,
                )
            else:
                resp = requests.post(
                    url, json={param: safe_value},
                    headers=headers or {"User-Agent": "AutoSecAudit/2.0",
                                        "Content-Type": "application/json"},
                    timeout=timeout, allow_redirects=True, verify=False,
                )

            baseline = {
                "status_code": resp.status_code,
                "length": len(resp.text),
                "content": resp.text[:500],
            }
            self._baseline_cache[cache_key] = baseline
            return baseline
        except requests.RequestException:
            return None

    @staticmethod
    def _verify_against_baseline(
        baseline: Dict[str, Any],
        malicious_response: requests.Response,
    ) -> Tuple[bool, str]:
        """
        Compare a malicious response against the baseline.

        Returns (is_verified, confidence):
        - is_verified: True if behavior actually changed (likely real vulnerability)
        - confidence: 'high' if strong evidence, 'medium' if moderate, 'low' if weak
        """
        mal_status = malicious_response.status_code
        mal_length = len(malicious_response.text)
        base_status = baseline["status_code"]
        base_length = baseline["length"]

        # Status code changed significantly (e.g. 200 → 500)
        status_changed = mal_status != base_status

        # Response length changed by more than 20%
        if base_length > 0:
            length_ratio = abs(mal_length - base_length) / base_length
        else:
            length_ratio = 1.0 if mal_length > 0 else 0.0
        length_changed = length_ratio > 0.20

        # Both changed = high confidence the payload caused a real effect
        if status_changed and length_changed:
            return True, "high"

        # Only status changed (e.g. 200 → 500 = server error from payload)
        if status_changed and mal_status >= 500:
            return True, "high"

        # Only length changed significantly
        if length_changed and length_ratio > 0.50:
            return True, "medium"

        # Minor changes — could be noise
        if status_changed or length_changed:
            return True, "low"

        # No meaningful change — likely false positive
        return False, "low"

