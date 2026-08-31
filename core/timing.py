"""
Statistical Timing & Latency Verification Engine for AutoSecAudit.

Eliminates false positives in time-based blind vulnerability detection
(e.g., Blind SQL Injection ' AND SLEEP(3)--, Blind OS Command Injection 'sleep 3')
by calculating baseline response distributions and running two-phase confirmation probes.
"""

import time
import logging
import statistics
from typing import Dict, Any, Callable, Optional, Tuple, List

logger = logging.getLogger(__name__)


class TimingVerifier:
    """
    Statistical timing analysis engine for blind vulnerability verification.
    """

    def __init__(self, baseline_samples: int = 3, min_delay_ratio: float = 0.70):
        """
        :param baseline_samples: Number of safe probes to measure baseline latency.
        :param min_delay_ratio: Fraction of expected delay required to consider a probe successful (e.g. 0.70 for 3s -> >= 2.1s).
        """
        self.baseline_samples = baseline_samples
        self.min_delay_ratio = min_delay_ratio

    def calibrate_baseline(self, probe_fn: Callable[[], Optional[Any]]) -> Dict[str, float]:
        """
        Measure baseline latency by invoking `probe_fn` multiple times.
        Returns dictionary with mean, std_dev, min, and max latency in seconds.
        """
        latencies: List[float] = []
        for _ in range(self.baseline_samples):
            start = time.monotonic()
            resp = probe_fn()
            elapsed = time.monotonic() - start
            if resp is not None:
                latencies.append(elapsed)

        if not latencies:
            return {"mean": 0.1, "std_dev": 0.0, "min": 0.1, "max": 0.1, "samples": 0}

        mean_lat = statistics.mean(latencies)
        std_lat = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
        return {
            "mean": round(mean_lat, 4),
            "std_dev": round(std_lat, 4),
            "min": round(min(latencies), 4),
            "max": round(max(latencies), 4),
            "samples": len(latencies),
        }

    def verify_delay(
        self,
        baseline_stats: Dict[str, float],
        delay_probe_fn: Callable[[], Optional[Any]],
        fast_probe_fn: Optional[Callable[[], Optional[Any]]] = None,
        expected_delay: float = 3.0,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Executes a two-phase statistical timing verification.

        1. Phase 1 (Delay Probe): Executes payload with expected sleep delay (e.g. 3.0s).
        2. Phase 2 (Fast Inverse Probe): Executes zero-delay control payload to confirm latency drops back to baseline.

        Returns:
            (is_verified: bool, confidence: str, details: dict)
            confidence: "high" | "medium" | "low"
        """
        base_mean = baseline_stats.get("mean", 0.1)
        base_std = baseline_stats.get("std_dev", 0.0)

        # Threshold required for positive delay detection
        delay_threshold = base_mean + (expected_delay * self.min_delay_ratio)

        # Phase 1: Measure delay probe
        start_delay = time.monotonic()
        delay_resp = delay_probe_fn()
        elapsed_delay = time.monotonic() - start_delay

        details: Dict[str, Any] = {
            "baseline_mean": base_mean,
            "baseline_std": base_std,
            "expected_delay": expected_delay,
            "threshold": round(delay_threshold, 3),
            "delay_elapsed": round(elapsed_delay, 3),
            "phase1_passed": elapsed_delay >= delay_threshold,
            "phase2_passed": False,
            "fast_elapsed": None,
        }

        if delay_resp is None or not details["phase1_passed"]:
            return False, "low", details

        # Phase 2: Fast inverse verification probe (if provided)
        if fast_probe_fn is not None:
            start_fast = time.monotonic()
            fast_resp = fast_probe_fn()
            elapsed_fast = time.monotonic() - start_fast
            details["fast_elapsed"] = round(elapsed_fast, 3)

            # Fast probe must return close to baseline (e.g. less than half the delay threshold)
            fast_threshold = base_mean + (expected_delay * 0.35)
            if fast_resp is not None and elapsed_fast <= fast_threshold:
                details["phase2_passed"] = True
                return True, "high", details
            else:
                # Delay occurred, but fast probe was also slow (possible network congestion)
                return True, "medium", details

        # Single-phase verified
        return True, "medium", details
