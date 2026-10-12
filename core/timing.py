"""
Statistical Timing & Latency Verification Engine for AutoSecAudit.

Eliminates false positives in time-based blind vulnerability detection
(e.g., Blind SQL Injection ' AND SLEEP(3)--, Blind OS Command Injection 'sleep 3')
by calculating baseline response distributions and running two-phase confirmation probes.
"""

import time
import logging
import statistics
import threading
import contextlib
from typing import Dict, Any, Callable, Optional, Tuple, List

logger = logging.getLogger(__name__)


class TimingTrafficController:
    """Coordinates traffic between parallel plugin tasks and serialized timing verification."""

    def __init__(self):
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self.active_timing_thread: Optional[int] = None
        self._in_flight_threads: Dict[int, int] = {}

    def _other_in_flight_count(self, timing_thread_id: int) -> int:
        return sum(count for tid, count in self._in_flight_threads.items() if tid != timing_thread_id and count > 0)

    def pause_other_traffic(self) -> None:
        """
        Enter timing phase:
        Sets active_timing_thread and waits until all other threads' in-flight requests reach 0.
        """
        current = threading.get_ident()
        with self._condition:
            while self.active_timing_thread is not None and self.active_timing_thread != current:
                self._condition.wait()
            self.active_timing_thread = current
            while self._other_in_flight_count(current) > 0:
                self._condition.wait()

    def resume_other_traffic(self) -> None:
        """Exit timing phase and notify all waiting threads."""
        current = threading.get_ident()
        with self._condition:
            if self.active_timing_thread == current:
                self.active_timing_thread = None
                self._condition.notify_all()

    def wait_if_timing_active(self) -> None:
        """Wait if another thread is in a timing phase."""
        current = threading.get_ident()
        with self._condition:
            while self.active_timing_thread is not None and self.active_timing_thread != current:
                self._condition.wait()

    @contextlib.contextmanager
    def track_in_flight(self):
        """
        Context manager for tracking an in-flight HTTP request.
        Blocks at entry if another thread is currently in a timing phase.
        Increments in-flight count for this thread, yields, then decrements and notifies.
        """
        current = threading.get_ident()
        with self._condition:
            while self.active_timing_thread is not None and self.active_timing_thread != current:
                self._condition.wait()
            self._in_flight_threads[current] = self._in_flight_threads.get(current, 0) + 1
        try:
            yield
        finally:
            with self._condition:
                self._in_flight_threads[current] = max(0, self._in_flight_threads.get(current, 0) - 1)
                self._condition.notify_all()

    @contextlib.contextmanager
    def serialized_timing_phase(self):
        self.pause_other_traffic()
        try:
            yield
        finally:
            self.resume_other_traffic()


global_timing_controller = TimingTrafficController()


class TimingVerifier:
    """
    Statistical timing analysis engine for blind vulnerability verification.
    """

    def __init__(
        self,
        baseline_samples: int = 3,
        min_delay_ratio: float = 0.70,
        k_std_dev: float = 3.0,
        controller: Optional[TimingTrafficController] = None,
    ):
        """
        :param baseline_samples: Number of safe probes to measure baseline latency.
        :param min_delay_ratio: Fraction of expected delay required to consider a probe successful (e.g. 0.70 for 3s -> >= 2.1s).
        :param k_std_dev: Multiplier for baseline standard deviation in threshold calculation.
        :param controller: TimingTrafficController instance to coordinate traffic.
        """
        self.baseline_samples = baseline_samples
        self.min_delay_ratio = min_delay_ratio
        self.k_std_dev = k_std_dev
        self.controller = controller or global_timing_controller

    def calibrate_baseline(self, probe_fn: Callable[[], Optional[Any]]) -> Dict[str, float]:
        """
        Measure baseline latency by invoking `probe_fn` multiple times.
        Returns dictionary with mean, std_dev, min, and max latency in seconds.
        """
        latencies: List[float] = []
        with self.controller.serialized_timing_phase():
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
        Executes statistical timing verification:
        1. Threshold = mean + max(k·std_dev, ratio·expected).
        2. Phase 1: Measure initial delay probe.
        3. Phase 1b: Require the delay to reproduce on a second delay probe.
        4. Phase 2: Measure fast control probe (if provided); if slow, not verified.

        Returns:
            (is_verified: bool, confidence: str, details: dict)
            confidence: "high" | "medium" | "low"
        """
        base_mean = baseline_stats.get("mean", 0.1)
        base_std = baseline_stats.get("std_dev", 0.0)

        # Statistical threshold: mean + max(k * std_dev, ratio * expected_delay)
        delay_margin = max(self.k_std_dev * base_std, self.min_delay_ratio * expected_delay)
        delay_threshold = base_mean + delay_margin

        details: Dict[str, Any] = {
            "baseline_mean": base_mean,
            "baseline_std": base_std,
            "expected_delay": expected_delay,
            "threshold": round(delay_threshold, 3),
            "delay_elapsed": None,
            "delay_elapsed_1": None,
            "delay_elapsed_2": None,
            "phase1_passed": False,
            "phase1_reproduced": False,
            "phase2_passed": False,
            "fast_elapsed": None,
        }

        with self.controller.serialized_timing_phase():
            # Phase 1: Initial delay probe
            start_delay_1 = time.monotonic()
            delay_resp_1 = delay_probe_fn()
            elapsed_delay_1 = time.monotonic() - start_delay_1

            details["delay_elapsed"] = round(elapsed_delay_1, 3)
            details["delay_elapsed_1"] = round(elapsed_delay_1, 3)
            details["phase1_passed"] = elapsed_delay_1 >= delay_threshold

            if delay_resp_1 is None or not details["phase1_passed"]:
                return False, "low", details

            # Phase 1b: Require the delay to reproduce on a second delay probe
            start_delay_2 = time.monotonic()
            delay_resp_2 = delay_probe_fn()
            elapsed_delay_2 = time.monotonic() - start_delay_2

            details["delay_elapsed_2"] = round(elapsed_delay_2, 3)
            if delay_resp_2 is None or elapsed_delay_2 < delay_threshold:
                details["phase1_reproduced"] = False
                return False, "low", details

            details["phase1_reproduced"] = True

            # Phase 2: Fast control verification probe (if provided)
            if fast_probe_fn is not None:
                start_fast = time.monotonic()
                fast_resp = fast_probe_fn()
                elapsed_fast = time.monotonic() - start_fast
                details["fast_elapsed"] = round(elapsed_fast, 3)

                # Fast control probe must return close to baseline
                fast_threshold = base_mean + (expected_delay * 0.35)
                if fast_resp is None or elapsed_fast > fast_threshold:
                    # If control probe is also slow -> not verified (network congestion or server lag)
                    details["phase2_passed"] = False
                    return False, "low", details

                details["phase2_passed"] = True
                return True, "high", details

            # Single-phase reproduced delay verified
            details["phase2_passed"] = True
            return True, "medium", details
