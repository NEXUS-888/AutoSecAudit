"""
Test suite for Silent Failure Hunter fixes:
1. Enricher network & non-JSON handling
2. DeltaAnalyzer malformed input resiliency
3. Engine plugin crash tracking & status reporting
4. Web UI async upload exception handling
"""

import sys
import unittest
from unittest.mock import MagicMock, patch
import requests

sys.path.insert(0, ".")

from intelligence.enricher import Enricher
from intelligence.delta import DeltaAnalyzer
from core.models import Finding, ScanResult, Report
from core.engine import Engine
from ui.app import app


class TestSilentFailures(unittest.TestCase):

    def test_enricher_handles_non_json_http200(self):
        """Verify Enricher handles non-JSON HTTP 200 responses (e.g. HTML WAF response)."""
        enricher = Enricher()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")

        with patch("requests.get", return_value=mock_resp):
            res_nvd = enricher._fetch_from_nvd("CVE-2021-99999")
            self.assertIsNone(res_nvd)

            res_circl = enricher._fetch_from_circl("CVE-2021-99999")
            self.assertIsNone(res_circl)

    def test_enricher_handles_network_exceptions(self):
        """Verify Enricher handles request timeouts and connection errors safely."""
        enricher = Enricher()
        with patch("requests.get", side_effect=requests.ConnectionError("Connection refused")):
            res = enricher._fetch_from_nvd("CVE-2021-99999")
            self.assertIsNone(res)

    def test_delta_analyzer_handles_malformed_inputs(self):
        """Verify DeltaAnalyzer does not crash on malformed dictionaries or None values."""
        analyzer = DeltaAnalyzer()

        # 1. Malformed dictionary list
        malformed_current = [
            {"id": "SEC-01", "title": "SQLi"},
            {"title": "Missing ID"},
            None,
            "Invalid String Entry"
        ]
        malformed_previous = {
            "all_findings": [
                {"id": "SEC-02", "title": "XSS"},
                None,
                {"no_id": True}
            ]
        }

        delta = analyzer.compare_with_dict(malformed_current, malformed_previous)
        self.assertIn("new_issues", delta)
        self.assertIn("fixed_issues", delta)
        self.assertEqual(delta["summary"]["new_count"], 1)
        self.assertEqual(delta["summary"]["fixed_count"], 1)

        # 2. None or invalid Report objects in compare()
        empty_delta = analyzer.compare(None, None)
        self.assertEqual(empty_delta["summary"]["new_count"], 0)
        self.assertEqual(empty_delta["summary"]["fixed_count"], 0)

    def test_engine_records_plugin_failure_status(self):
        """Verify Engine records failed plugin status and error details instead of clean 0 findings."""
        engine = Engine(mock_mode=False)
        mock_plugin = MagicMock()
        mock_plugin.__class__.__name__ = "CrashingPlugin"
        mock_plugin.configure.side_effect = RuntimeError("Simulated plugin crash")

        res = engine._execute_plugin(mock_plugin)
        self.assertEqual(res["status"], "failed")
        self.assertIn("Simulated plugin crash", res["error"])
        self.assertEqual(res["findings"], [])

    def test_scan_async_handles_invalid_input(self):
        """Verify scan_async returns structured JSON errors instead of unhandled 500 HTML."""
        with app.test_client() as client:
            resp = client.post("/scan/async", data={})
            self.assertEqual(resp.status_code, 400)
            data = resp.get_json()
            self.assertIn("error", data)


if __name__ == "__main__":
    print("=" * 60)
    print("RUNNING SILENT FAILURE HUNTER REGRESSION SUITE")
    print("=" * 60)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSilentFailures)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print()
        print("=" * 60)
        print("ALL SILENT FAILURE TESTS PASSED!")
        print("=" * 60)
        sys.exit(0)
    else:
        sys.exit(1)
