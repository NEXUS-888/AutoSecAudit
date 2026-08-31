"""
Unit tests for Statistical Timing & Latency Verification Engine.
"""

import time
import unittest
from core.timing import TimingVerifier


class TestTimingVerifier(unittest.TestCase):
    """Test suite for TimingVerifier."""

    def setUp(self):
        self.verifier = TimingVerifier(baseline_samples=2, min_delay_ratio=0.70)

    def test_calibrate_baseline(self):
        def fast_probe():
            time.sleep(0.01)
            return "ok"

        stats = self.verifier.calibrate_baseline(fast_probe)
        self.assertEqual(stats["samples"], 2)
        self.assertGreater(stats["mean"], 0.005)
        self.assertLess(stats["mean"], 0.1)

    def test_verify_delay_success_two_phase(self):
        baseline_stats = {"mean": 0.02, "std_dev": 0.005}

        def delay_probe():
            time.sleep(0.15)
            return "delayed_resp"

        def fast_probe():
            time.sleep(0.02)
            return "fast_resp"

        # Expected delay 0.15s
        is_verified, confidence, details = self.verifier.verify_delay(
            baseline_stats,
            delay_probe_fn=delay_probe,
            fast_probe_fn=fast_probe,
            expected_delay=0.15,
        )
        self.assertTrue(is_verified)
        self.assertEqual(confidence, "high")
        self.assertTrue(details["phase1_passed"])
        self.assertTrue(details["phase2_passed"])

    def test_verify_delay_rejection_on_no_delay(self):
        baseline_stats = {"mean": 0.02, "std_dev": 0.005}

        def fake_delay_probe():
            # Fast return (no actual delay)
            time.sleep(0.02)
            return "fast_resp"

        is_verified, confidence, details = self.verifier.verify_delay(
            baseline_stats,
            delay_probe_fn=fake_delay_probe,
            expected_delay=0.20,
        )
        self.assertFalse(is_verified)
        self.assertEqual(confidence, "low")
        self.assertFalse(details["phase1_passed"])


if __name__ == "__main__":
    unittest.main()
