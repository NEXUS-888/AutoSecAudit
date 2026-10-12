"""Tests for Batch 12: False-positive control (AUD-32, AUD-33)."""
import time
import unittest
import threading
from unittest.mock import MagicMock

from plugins.base_plugin import BaseScanner
from core.timing import TimingVerifier, TimingTrafficController


class TestB12FalsePositiveControl(unittest.TestCase):
    # -----------------------------------------------------------------------
    # AUD-32: Baseline comparison & false-positive control
    # -----------------------------------------------------------------------
    def test_aud32_response_varying_naturally_by_30_percent_not_verified(self):
        """AUD-32: Response varying naturally by ~30% (e.g. dynamic token/timestamp) is NOT verified."""
        baseline = {
            "status_code": 200,
            "length": 1000,
            "content": "Page content with dynamic token " + "A" * 960,
            "samples": [
                {"status_code": 200, "length": 1000, "content": "Page content with dynamic token " + "A" * 960},
                {"status_code": 200, "length": 1300, "content": "Page content with dynamic token " + "A" * 1260},
            ],
            "status_codes": [200, 200],
            "lengths": [1000, 1300],
            "variance_ratio": 0.30,
            "sample_similarity": 0.85,
            "safe_value": "safe123",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Page content with dynamic token " + "A" * 1210

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
        self.assertFalse(
            is_verified,
            f"Response varying within natural variance (30%) should not be verified, got {is_verified} ({confidence})",
        )

    def test_aud32_pure_reflection_of_input_not_verified(self):
        """AUD-32: Pure reflection of the input is NOT verified."""
        safe_val = "safe123"
        base_text = f"<html><body>Welcome back, {safe_val}! Your dashboard is ready.</body></html>"
        payload = "<script>alert('AutoSec_XSS_Probe')</script>"
        reflected_text = f"<html><body>Welcome back, {payload}! Your dashboard is ready.</body></html>"

        baseline = {
            "status_code": 200,
            "length": len(base_text),
            "content": base_text,
            "safe_value": safe_val,
            "status_codes": [200, 200],
            "lengths": [len(base_text), len(base_text)],
            "variance_ratio": 0.0,
            "sample_similarity": 1.0,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = reflected_text

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp, payload=payload)
        self.assertFalse(
            is_verified,
            f"Pure reflection of input should not be verified, got {is_verified} ({confidence})",
        )

    def test_aud32_status_200_to_500_change_is_verified(self):
        """AUD-32: 200 -> 500 status change is verified with high confidence."""
        baseline = {
            "status_code": 200,
            "length": 500,
            "content": "normal page content",
            "status_codes": [200, 200],
            "lengths": [500, 500],
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error: SQL syntax error near 'OR 1=1'"

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
        self.assertTrue(is_verified, "200 -> 500 status change must be verified")
        self.assertEqual(confidence, "high", "200 -> 500 status change must have high confidence")

    def test_aud32_unstable_baseline_503_not_verified(self):
        """AUD-32 (Required change 1): Baseline with status_codes=[200, 503] with a 503 probe -> False."""
        baseline = {
            "status_code": 200,
            "length": 500,
            "content": "service response",
            "status_codes": [200, 503],
            "lengths": [500, 500],
            "control_status": 200,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "503 Service Unavailable"

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
        self.assertFalse(
            is_verified,
            f"Probe with status in baseline status_codes must not be verified, got {is_verified} ({confidence})",
        )

    def test_aud32_control_status_500_not_verified(self):
        """AUD-32 (Required change 1): Control status is 500 with a 500 probe -> False."""
        baseline = {
            "status_code": 200,
            "length": 500,
            "content": "normal page",
            "status_codes": [200, 200],
            "lengths": [500, 500],
            "control_status": 500,
            "control_length": 300,
            "control_content": "Internal Server Error for generic inputs",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error for generic inputs"

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
        self.assertFalse(
            is_verified,
            f"Probe matching control status 500 must not be verified, got {is_verified} ({confidence})",
        )

    def test_aud32_probe_close_to_control_not_verified(self):
        """AUD-32 (Required change 2): Baseline length 1000, control length 400 ('Not found'), probe length 401 -> False."""
        ctrl_page = "<html><body>404 Not Found - The requested resource was not found.</body></html>" + "x" * 320
        probe_page = ctrl_page + "!"  # 1 byte difference

        baseline = {
            "status_code": 200,
            "length": 1000,
            "content": "Normal home page content " + "h" * 975,
            "status_codes": [200, 200],
            "lengths": [1000, 1000],
            "control_status": 200,
            "control_length": 400,
            "control_content": ctrl_page,
            "variance_ratio": 0.05,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = probe_page

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
        self.assertFalse(
            is_verified,
            f"Probe response close to control page must not be verified, got {is_verified} ({confidence})",
        )

    def test_aud32_template_match_with_token_variation_not_verified(self):
        """AUD-32 (Required change 3): Baseline samples share template with dynamic token; probe with same template and token within variance -> False."""
        sample1 = "<html><body>Welcome user! Token: abc123def456. Copyright 2026.</body></html>"
        sample2 = "<html><body>Welcome user! Token: xyz789uvw012. Copyright 2026.</body></html>"
        probe_text = "<html><body>Welcome user! Token: pqr345rst678. Copyright 2026.</body></html>"

        baseline = {
            "status_code": 200,
            "length": len(sample1),
            "content": sample1,
            "samples": [
                {"status_code": 200, "length": len(sample1), "content": sample1},
                {"status_code": 200, "length": len(sample2), "content": sample2},
            ],
            "status_codes": [200, 200],
            "lengths": [len(sample1), len(sample2)],
            "variance_ratio": 0.05,
            "sample_similarity": 0.88,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = probe_text

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
        self.assertFalse(
            is_verified,
            f"Probe sharing template within sample_similarity variance must not be verified, got {is_verified} ({confidence})",
        )

    def test_aud32_sql_error_differs_from_control_200_is_verified(self):
        """AUD-32: Baseline 200 with >=1500-char templated page, control_status=200, probe 200 with SQL error -> True."""
        template_page = "<html><head><title>Store Product Details</title></head><body><h1>Product Overview</h1>" + "<p>Description details and specifications...</p>" * 30 + "</body></html>"
        self.assertGreaterEqual(len(template_page), 1500)

        sql_error_page = "<html><body><h3>Database Error</h3><p>You have an error in your SQL syntax near '\''</p></body></html>"

        baseline = {
            "status_code": 200,
            "length": len(template_page),
            "content": template_page,
            "control_status": 200,
            "control_content": template_page,
            "control_length": len(template_page),
            "sample_similarity": 1.0,
            "lengths": [len(template_page), len(template_page)],
            "status_codes": [200, 200],
            "variance_ratio": 0.0,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = sql_error_page

        is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp, payload="'")
        self.assertTrue(
            is_verified,
            f"SQL error page differing from control must be verified as True, got {is_verified} ({confidence})",
        )

    # -----------------------------------------------------------------------
    # AUD-33: Statistical timing verification & serialization
    # -----------------------------------------------------------------------
    def test_aud33_slow_control_probe_returns_false(self):
        """AUD-33: If the control (fast) probe is also slow, verify_delay returns False and phase1_reproduced is True."""
        verifier = TimingVerifier(baseline_samples=2, min_delay_ratio=0.70)
        baseline_stats = {"mean": 0.05, "std_dev": 0.005}

        # Delay probe reproduces delay (0.25s sleep vs 0.19s threshold)
        delay_calls = 0
        def fake_delay_probe():
            nonlocal delay_calls
            delay_calls += 1
            time.sleep(0.25)
            return "delayed"

        # Fast probe is also slow (0.25s sleep)
        def fake_slow_control():
            time.sleep(0.25)
            return "slow_control"

        is_verified, confidence, details = verifier.verify_delay(
            baseline_stats,
            delay_probe_fn=fake_delay_probe,
            fast_probe_fn=fake_slow_control,
            expected_delay=0.20,
        )
        self.assertTrue(details["phase1_reproduced"], "Delay must reproduce before testing control probe")
        self.assertFalse(
            is_verified,
            f"Slow control probe must return False, got {is_verified} ({confidence})",
        )

    def test_aud33_jittery_baseline_raises_threshold(self):
        """AUD-33: Jittery baseline (high std_dev) raises the delay threshold = mean + max(k*std_dev, ratio*expected)."""
        verifier = TimingVerifier(baseline_samples=3, min_delay_ratio=0.70)
        calm_stats = {"mean": 0.10, "std_dev": 0.01}
        jittery_stats = {"mean": 0.10, "std_dev": 0.80}

        def dummy_probe():
            return "dummy"

        _, _, details_calm = verifier.verify_delay(
            calm_stats,
            delay_probe_fn=dummy_probe,
            expected_delay=1.0,
        )
        _, _, details_jittery = verifier.verify_delay(
            jittery_stats,
            delay_probe_fn=dummy_probe,
            expected_delay=1.0,
        )

        self.assertGreater(
            details_jittery["threshold"],
            details_calm["threshold"],
            f"Jittery baseline threshold ({details_jittery['threshold']}) must be higher than calm ({details_calm['threshold']})",
        )
        self.assertGreaterEqual(
            details_jittery["threshold"],
            jittery_stats["mean"] + (3.0 * jittery_stats["std_dev"]) - 0.01,
        )

    def test_aud33_reproduced_delay_with_fast_control_returns_true(self):
        """AUD-33: A delay that reproduces on a second probe with a fast control probe returns True."""
        verifier = TimingVerifier(baseline_samples=2, min_delay_ratio=0.70)
        baseline_stats = {"mean": 0.02, "std_dev": 0.005}

        delay_call_count = 0
        def fake_reproducing_delay_probe():
            nonlocal delay_call_count
            delay_call_count += 1
            time.sleep(0.15)
            return "delay_resp"

        def fake_fast_control():
            time.sleep(0.01)
            return "fast_resp"

        is_verified, confidence, details = verifier.verify_delay(
            baseline_stats,
            delay_probe_fn=fake_reproducing_delay_probe,
            fast_probe_fn=fake_fast_control,
            expected_delay=0.15,
        )
        self.assertTrue(is_verified, f"Reproduced delay with fast control must return True, got {is_verified}")
        self.assertEqual(confidence, "high")
        self.assertGreaterEqual(
            delay_call_count,
            2,
            "Delay probe must be invoked at least twice to verify reproducibility",
        )

    def test_aud33_timing_phase_waits_for_in_flight_and_blocks_new_requests(self):
        """AUD-33 (Required change 5): Timing phase waits for in-flight request, and blocks new requests until phase exits."""
        controller = TimingTrafficController()
        in_flight_done = threading.Event()
        request_started = threading.Event()
        timing_phase_entered = threading.Event()
        timing_phase_completed = threading.Event()
        new_request_started = threading.Event()

        # Thread 1: in-flight request running
        def worker_in_flight():
            with controller.track_in_flight():
                request_started.set()
                time.sleep(0.10)
                in_flight_done.set()

        t1 = threading.Thread(target=worker_in_flight)
        t1.start()
        request_started.wait()

        # Thread 2: timing phase enters
        timing_phase_started_after_in_flight = False
        def worker_timing():
            nonlocal timing_phase_started_after_in_flight
            with controller.serialized_timing_phase():
                timing_phase_started_after_in_flight = in_flight_done.is_set()
                timing_phase_entered.set()
                time.sleep(0.10)
            timing_phase_completed.set()

        t2 = threading.Thread(target=worker_timing)
        t2.start()
        timing_phase_entered.wait()

        # Thread 3: new request attempted while timing phase is active
        new_request_ran_after_timing = False
        def worker_new_request():
            nonlocal new_request_ran_after_timing
            new_request_started.set()
            with controller.track_in_flight():
                new_request_ran_after_timing = timing_phase_completed.is_set()

        t3 = threading.Thread(target=worker_new_request)
        t3.start()
        new_request_started.wait()

        t1.join()
        t2.join()
        t3.join()

        self.assertTrue(
            timing_phase_started_after_in_flight,
            "Timing phase body must only start after in-flight request completes",
        )
        self.assertTrue(
            new_request_ran_after_timing,
            "New request from another thread must block until timing phase exits",
        )


if __name__ == "__main__":
    unittest.main()
