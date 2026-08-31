from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple, List, Callable, Union
import logging
import shutil
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import config
from core.politeness import PolitenessEngine
from core.timing import TimingVerifier
from core.fuzzer import generate_json_fuzz_mutations, extract_json_leaf_paths, mutate_json_at_path

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base class for all security scanning plugins."""

    def __init__(self, mock_mode: Optional[bool] = None):
        self.target: str = ""
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self._tool_available: Optional[bool] = None
        self.discovered_endpoints: list = []  # populated by engine from crawler
        self._baseline_cache: Dict[str, Any] = {}
        self.politeness = PolitenessEngine(min_jitter_ms=0, max_jitter_ms=20)
        self.timing_verifier = TimingVerifier(baseline_samples=2, min_delay_ratio=0.70)

    def set_discovered_endpoints(self, endpoints: list) -> None:
        """Set discovered endpoints from the web crawler."""
        self.discovered_endpoints = endpoints

    @staticmethod
    def _parse_target(target: str):
        """Return (base_url, host, port) from a target string."""
        import urllib.parse
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or parsed.netloc
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return base_url, host, port

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

        if tool_name in ("python-requests", "internal", "python", "requests", "builtin"):
            self._tool_available = True
            return True

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

    def _get_baseline(self, url: str, param: str, method: str = "GET",
                      headers: Optional[Dict] = None, timeout: Any = 10) -> Optional[Dict[str, Any]]:
        """
        Fetch a baseline (safe) response for an endpoint.
        Caches results so we only hit each endpoint once.
        """
        cache_key = f"{method}:{url}:{param}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        try:
            safe_value = "test123"
            if isinstance(timeout, tuple):
                req_timeout = timeout
            else:
                req_timeout = (3.0, float(timeout))
            if method.upper() == "GET":
                resp = requests.get(
                    url, params={param: safe_value},
                    headers=headers or {"User-Agent": "AutoSecAudit/2.0"},
                    timeout=req_timeout, allow_redirects=True, verify=False,
                )
            else:
                resp = requests.post(
                    url, json={param: safe_value},
                    headers=headers or {"User-Agent": "AutoSecAudit/2.0",
                                        "Content-Type": "application/json"},
                    timeout=req_timeout, allow_redirects=True, verify=False,
                )

            baseline = {
                "status_code": resp.status_code,
                "length": len(resp.text),
                "content": resp.text[:500],
            }
            self._baseline_cache[cache_key] = baseline
            return baseline
        except requests.RequestException as exc:
            logger.debug(f"[BaseScanner] Baseline probe for {url} ({param}) failed: {exc}")
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

    def _safe_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Tuple[float, float] = (3.0, 8.0),
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """
        Execute an HTTP request with politeness pacing and rate-limit backoff.
        """
        self.politeness.pace_request()
        req_headers = self.politeness.get_polite_headers(headers)

        try:
            if method.upper() == "GET":
                resp = requests.get(
                    url, params=params, headers=req_headers,
                    timeout=timeout, allow_redirects=allow_redirects, verify=False,
                )
            elif method.upper() == "POST":
                resp = requests.post(
                    url, params=params, json=json_data, data=data, headers=req_headers,
                    timeout=timeout, allow_redirects=allow_redirects, verify=False,
                )
            elif method.upper() == "PUT":
                resp = requests.put(
                    url, params=params, json=json_data, data=data, headers=req_headers,
                    timeout=timeout, allow_redirects=allow_redirects, verify=False,
                )
            elif method.upper() == "DELETE":
                resp = requests.delete(
                    url, params=params, json=json_data, headers=req_headers,
                    timeout=timeout, allow_redirects=allow_redirects, verify=False,
                )
            else:
                resp = requests.request(
                    method, url, params=params, json=json_data, data=data, headers=req_headers,
                    timeout=timeout, allow_redirects=allow_redirects, verify=False,
                )

            self.politeness.handle_response_status(resp.status_code)
            return resp
        except requests.RequestException as exc:
            logger.debug(f"[BaseScanner] Safe request failed for {url}: {exc}")
            return None

    def _verify_timing(
        self,
        probe_fn: Callable[[], Optional[requests.Response]],
        delay_probe_fn: Callable[[], Optional[requests.Response]],
        fast_probe_fn: Optional[Callable[[], Optional[requests.Response]]] = None,
        expected_delay: float = 3.0,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Execute statistical baseline calibration and two-phase delay verification.
        """
        baseline_stats = self.timing_verifier.calibrate_baseline(probe_fn)
        return self.timing_verifier.verify_delay(
            baseline_stats, delay_probe_fn, fast_probe_fn, expected_delay
        )

    def _fuzz_json_body(
        self,
        url: str,
        method: str,
        base_json: Dict[str, Any],
        payload: Any,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[str, Optional[requests.Response]]]:
        """
        Fuzz all leaf keys of a JSON request body and return (mutated_path, response) pairs.
        """
        mutations = generate_json_fuzz_mutations(base_json, payload)
        results: List[Tuple[str, Optional[requests.Response]]] = []

        for path, mutated_body in mutations:
            resp = self._safe_request(method, url, json_data=mutated_body, headers=headers)
            results.append((path, resp))

        return results


