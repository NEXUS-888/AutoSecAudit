from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple, List, Callable, Union
import logging
import shutil
import difflib
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import config
from core.politeness import PolitenessEngine
from core.http_client import ScanHttpClient
from core.timing import TimingVerifier
from core.fuzzer import generate_json_fuzz_mutations, extract_json_leaf_paths, mutate_json_at_path
from core.spa_detector import SPADetector
from core.dev_detector import detect_dev_environment

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
        self._spa_detector: Optional[SPADetector] = None
        self.dev_environment: Optional[str] = None
        self.auth_headers: Dict[str, str] = {}
        self.auth_cookies: Dict[str, str] = {}
        self.http: Optional[ScanHttpClient] = None

    def set_http_client(self, client: Any) -> None:
        """Set shared ScanHttpClient instance."""
        self.http = client
        if client and hasattr(client, "politeness"):
            self.politeness = client.politeness

    def _get_http_client(self) -> ScanHttpClient:
        """Lazily initialize or return the shared ScanHttpClient."""
        if self.http is None:
            self.http = ScanHttpClient(
                target=self.target,
                politeness=self.politeness,
                auth_headers=self.auth_headers,
                auth_cookies=self.auth_cookies,
                mock_mode=self.mock_mode,
            )
        return self.http

    def set_discovered_endpoints(self, endpoints: list) -> None:
        """Set discovered endpoints from the web crawler."""
        self.discovered_endpoints = endpoints

    def set_dev_environment(self, dev_env: Optional[str]) -> None:
        """Set detected development environment (e.g. Vite Dev Server)."""
        self.dev_environment = dev_env

    def set_auth(self, headers: Optional[Dict[str, str]] = None, cookies: Optional[Dict[str, str]] = None) -> None:
        """Set authentication headers and cookies for authenticated scanning."""
        if headers:
            self.auth_headers.update(headers)
        if cookies:
            self.auth_cookies.update(cookies)
        if self.http:
            self.http.set_auth(headers=headers, cookies=cookies)

    def get_authenticated_session(self) -> requests.Session:
        """Return a requests.Session pre-loaded with authentication credentials."""
        client = self._get_http_client()
        return client.session

    def set_spa_detector(self, spa_detector: SPADetector) -> None:
        """Set shared SPADetector calibrated by Engine."""
        self._spa_detector = spa_detector

    def get_spa_detector(self, session: Optional[requests.Session] = None) -> SPADetector:
        """Lazily initialize and return the SPADetector for the target."""
        if self._spa_detector is None:
            base_url, _, _ = self._parse_target(self.target or "http://localhost")
            self._spa_detector = SPADetector(base_url=base_url, session=session)
        return self._spa_detector

    def is_soft_404(self, resp: Optional[requests.Response], session: Optional[requests.Session] = None) -> bool:
        """Check if a response is an SPA soft-404 false positive."""
        if resp is None:
            return False
        detector = self.get_spa_detector(session=session)
        return detector.is_soft_404(resp)

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
            return {
                "tool_name": tool_name,
                "findings": [],
                "status": "skipped",
                "error": f"Tool '{tool_name}' is not installed on the system and mock mode is disabled",
                "raw_output": f"Skipped: tool '{tool_name}' not found on system PATH."
            }

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

    def _get_baseline(
        self,
        url: str,
        param: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        timeout: Any = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch baseline responses (at least 2 samples + 1 control request) for an endpoint.
        Measures natural variance (status stability and length spread).
        Caches results so we only hit each endpoint once.
        Delegates to _safe_request / shared HTTP layer with auth.
        """
        cache_key = f"{method}:{url}:{param}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        safe_value = "safe123"
        control_value = f"ctrl_{int(time.time() * 1000) % 100000}"
        if isinstance(timeout, tuple):
            req_timeout = timeout
        else:
            req_timeout = (3.0, float(timeout))

        # Sample 1 (safe baseline)
        if method.upper() == "GET":
            resp1 = self._safe_request(
                "GET", url, params={param: safe_value},
                headers=headers, timeout=req_timeout, allow_redirects=True,
            )
        else:
            resp1 = self._safe_request(
                "POST", url, json_data={param: safe_value},
                headers=headers, timeout=req_timeout, allow_redirects=True,
            )

        if resp1 is None:
            return None

        # Sample 2 (safe baseline for natural variance)
        if method.upper() == "GET":
            resp2 = self._safe_request(
                "GET", url, params={param: safe_value},
                headers=headers, timeout=req_timeout, allow_redirects=True,
            )
        else:
            resp2 = self._safe_request(
                "POST", url, json_data={param: safe_value},
                headers=headers, timeout=req_timeout, allow_redirects=True,
            )

        # Control request (benign random value)
        if method.upper() == "GET":
            resp_ctrl = self._safe_request(
                "GET", url, params={param: control_value},
                headers=headers, timeout=req_timeout, allow_redirects=True,
            )
        else:
            resp_ctrl = self._safe_request(
                "POST", url, json_data={param: control_value},
                headers=headers, timeout=req_timeout, allow_redirects=True,
            )

        text1 = resp1.text or ""
        text2 = (resp2.text if resp2 is not None else text1) or ""
        ctrl_text = (resp_ctrl.text if resp_ctrl is not None else text1) or ""

        status1 = resp1.status_code
        status2 = resp2.status_code if resp2 is not None else status1
        ctrl_status = resp_ctrl.status_code if resp_ctrl is not None else status1

        len1 = len(text1)
        len2 = len(text2)
        ctrl_len = len(ctrl_text)

        lengths = [len1, len2]
        length_spread = abs(len1 - len2)
        variance_ratio = length_spread / max(1, min(lengths))

        sample_similarity = difflib.SequenceMatcher(None, text1[:2000], text2[:2000]).ratio()

        baseline = {
            "status_code": status1,
            "length": len1,
            "content": text1[:2000],
            "safe_value": safe_value,
            "control_value": control_value,
            "control_status": ctrl_status,
            "control_length": ctrl_len,
            "control_content": ctrl_text[:2000],
            "status_codes": [status1, status2],
            "lengths": lengths,
            "length_spread": length_spread,
            "variance_ratio": variance_ratio,
            "sample_similarity": sample_similarity,
            "samples": [
                {"status_code": status1, "length": len1, "content": text1[:2000]},
                {"status_code": status2, "length": len2, "content": text2[:2000]},
            ],
            "url": url,
            "param": param,
            "method": method,
        }
        self._baseline_cache[cache_key] = baseline
        return baseline

    @staticmethod
    def _verify_against_baseline(
        baseline: Dict[str, Any],
        malicious_response: requests.Response,
        payload: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Compare a malicious response against baseline using statistical variance,
        control difference, reflected input discounting, and sequence similarity.

        Returns (is_verified, confidence):
        - is_verified: True if behavior actually changed (likely real vulnerability)
        - confidence: 'high' if strong evidence, 'medium' if moderate, 'low' if weak
        """
        mal_status = getattr(malicious_response, "status_code", 200)
        mal_text = getattr(malicious_response, "text", "") or ""
        mal_length = len(mal_text)

        base_status = baseline.get("status_code", 200)
        base_length = baseline.get("length", len(baseline.get("content", "")))
        base_content = baseline.get("content", "")

        status_codes = baseline.get("status_codes") or [base_status]
        lengths = baseline.get("lengths") or [base_length]

        # Calculate natural variance in baseline
        if len(lengths) > 1:
            min_len = min(lengths)
            max_len = max(lengths)
            observed_variance = (max_len - min_len) / max(1, min_len)
        else:
            observed_variance = baseline.get("variance_ratio", 0.0)

        # Baseline internal sample similarity
        sample_similarity = baseline.get("sample_similarity")
        if sample_similarity is None and baseline.get("samples") and len(baseline["samples"]) > 1:
            s1 = baseline["samples"][0].get("content") or baseline["samples"][0].get("text") or ""
            s2 = baseline["samples"][1].get("content") or baseline["samples"][1].get("text") or ""
            sample_similarity = difflib.SequenceMatcher(None, s1[:2000], s2[:2000]).ratio()
        if sample_similarity is None:
            sample_similarity = 1.0

        # Control response data
        ctrl_status = baseline.get("control_status")
        ctrl_len = baseline.get("control_length")
        ctrl_content = baseline.get("control_content")

        # Status change check: A status change counts only if not in status_codes and != control_status
        status_changed = (mal_status not in status_codes) and (ctrl_status is None or mal_status != ctrl_status)

        # Reflected input discounting
        discounted_mal_text = mal_text
        discounted_mal_length = mal_length
        safe_val = str(baseline.get("safe_value", "safe123"))

        reflected = False
        if payload and str(payload) in mal_text:
            p_str = str(payload)
            reflected = True
            discounted_mal_text = mal_text.replace(p_str, safe_val)
            discounted_mal_length = len(discounted_mal_text)

        # Check pure reflection against baseline text and control text
        if reflected and not status_changed:
            is_pure_reflection = False
            if base_content:
                ref_sim = difflib.SequenceMatcher(None, base_content[:2000], discounted_mal_text[:2000]).ratio()
                if ref_sim >= 0.95 or discounted_mal_length == base_length:
                    is_pure_reflection = True
            elif discounted_mal_length == base_length:
                is_pure_reflection = True

            if is_pure_reflection:
                return False, "low"

        # Compare against control request:
        # Reject on the control only when the probe is close to the control in content (is_close_to_control)
        if ctrl_status is not None:
            ctrl_sim = difflib.SequenceMatcher(None, ctrl_content[:2000], discounted_mal_text[:2000]).ratio() if ctrl_content else 0.0
            ctrl_len_val = ctrl_len if ctrl_len is not None else (len(ctrl_content) if ctrl_content else 0)
            ctrl_diff = abs(discounted_mal_length - ctrl_len_val)
            ctrl_margin = max(10, int(ctrl_len_val * max(0.10, observed_variance)))
            is_close_to_control = (ctrl_diff <= ctrl_margin) or (ctrl_sim >= 0.85)

            if is_close_to_control and (mal_status == ctrl_status or not status_changed):
                return False, "low"

        # 1. 500+ server error: verified only if genuinely changed from baseline and control
        if mal_status >= 500:
            if mal_status in status_codes or mal_status == ctrl_status:
                return False, "low"
            return True, "high"

        # Natural variance & sequence similarity comparison against baseline
        if base_length > 0:
            raw_length_ratio = abs(discounted_mal_length - base_length) / base_length
        else:
            raw_length_ratio = 1.0 if discounted_mal_length > 0 else 0.0

        significance_threshold = max(0.20, observed_variance)
        length_changed = raw_length_ratio > significance_threshold

        # SequenceMatcher on bounded prefix between discounted probe and baseline
        prefix_base = base_content[:2000]
        prefix_mal = discounted_mal_text[:2000]
        if prefix_base and prefix_mal:
            probe_base_sim = difflib.SequenceMatcher(None, prefix_base, prefix_mal).ratio()
        else:
            probe_base_sim = 1.0 if prefix_base == prefix_mal else 0.0

        # Divergence from baseline: similarity is below baseline samples' own similarity by margin
        sim_margin = max(0.05, 1.0 - sample_similarity)
        similarity_diverged = probe_base_sim < (sample_similarity - sim_margin)

        # If status unchanged and either within natural length variance or not diverged in similarity
        if not status_changed and (raw_length_ratio <= significance_threshold or not similarity_diverged):
            return False, "low"

        # Verdict
        if status_changed and length_changed:
            return True, "high"

        if status_changed:
            return True, "low"

        if length_changed and similarity_diverged:
            if raw_length_ratio > max(0.50, significance_threshold * 1.5):
                return True, "medium"
            return True, "low"

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
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        """
        Execute an HTTP request with politeness pacing, scope-checking, and backoff.
        Delegates to the shared ScanHttpClient while preserving exact signature.
        """
        if json_data is None and "json" in kwargs:
            json_data = kwargs.pop("json")
        client = self._get_http_client()
        return client.request(
            method=method,
            url=url,
            params=params,
            json_data=json_data,
            data=data,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            **kwargs,
        )

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


