"""
Tests for Batch 26: Benchmark harness (AUD-69 and AUD-70).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestBenchmarkMetrics(unittest.TestCase):
    """Unit tests for benchmark/metrics.py covering synthetic findings, cookies, placeholders, and edge cases."""

    def setUp(self):
        from benchmark.metrics import compute_metrics, GroundTruth, endpoint_matches
        self.compute_metrics = compute_metrics
        self.GroundTruth = GroundTruth
        self.endpoint_matches = endpoint_matches

    def test_synthetic_true_positive(self):
        """A finding matching a real truth item is counted as a true positive."""
        truth = self.GroundTruth(
            target="test_app",
            items=[
                {"id": "REAL-1", "vuln_type": "sqli", "endpoint": "/search", "classification": "real"}
            ],
            informational=[]
        )
        findings = [
            {"vuln_type": "sqli", "endpoint": "/search?q=1", "title": "SQLi"}
        ]
        res = self.compute_metrics(findings, truth)
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["false_negatives"], 0)
        self.assertAlmostEqual(res["precision"], 1.0)
        self.assertAlmostEqual(res["recall"], 1.0)
        self.assertAlmostEqual(res["f1"], 1.0)

    def test_synthetic_decoy_hit_counted_as_false_positive(self):
        """A finding matching a decoy truth item is counted as a false positive."""
        truth = self.GroundTruth(
            target="test_app",
            items=[
                {"id": "REAL-1", "vuln_type": "sqli", "endpoint": "/search", "classification": "real"},
                {"id": "DECOY-1", "vuln_type": "csrf", "endpoint": "/login", "classification": "decoy"}
            ],
            informational=[]
        )
        findings = [
            {"vuln_type": "csrf", "endpoint": "/login", "title": "CSRF on safe form"}
        ]
        res = self.compute_metrics(findings, truth)
        self.assertEqual(res["true_positives"], 0)
        self.assertEqual(res["false_positives"], 1)
        self.assertEqual(res["false_negatives"], 1)
        self.assertAlmostEqual(res["precision"], 0.0)
        self.assertAlmostEqual(res["recall"], 0.0)
        self.assertAlmostEqual(res["f1"], 0.0)

    def test_synthetic_unmatched_non_informational_counted_as_false_positive(self):
        """An unmatched finding not in the informational list is counted as a false positive."""
        truth = self.GroundTruth(
            target="test_app",
            items=[
                {"id": "REAL-1", "vuln_type": "sqli", "endpoint": "/search", "classification": "real"}
            ],
            informational=["misconfig"]
        )
        findings = [
            {"vuln_type": "xss", "endpoint": "/unknown/page", "title": "False XSS"}
        ]
        res = self.compute_metrics(findings, truth)
        self.assertEqual(res["true_positives"], 0)
        self.assertEqual(res["false_positives"], 1)
        self.assertEqual(res["false_negatives"], 1)
        self.assertAlmostEqual(res["precision"], 0.0)

    def test_synthetic_informational_finding_ignored(self):
        """An unmatched finding matching the informational list is ignored (not a false positive)."""
        truth = self.GroundTruth(
            target="test_app",
            items=[
                {"id": "REAL-1", "vuln_type": "sqli", "endpoint": "/search", "classification": "real"}
            ],
            informational=["misconfig", "port_scan"]
        )
        findings = [
            {"vuln_type": "sqli", "endpoint": "/search", "title": "SQLi"},
            {"vuln_type": "misconfig", "endpoint": "/", "title": "Missing CSP"},
            {"vuln_type": "port_scan", "endpoint": "/80", "title": "Port open"}
        ]
        res = self.compute_metrics(findings, truth)
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["false_negatives"], 0)
        self.assertAlmostEqual(res["precision"], 1.0)
        self.assertAlmostEqual(res["recall"], 1.0)
        self.assertAlmostEqual(res["f1"], 1.0)

    def test_endpoint_normalization(self):
        """Endpoints with numeric segments (/api/users/1) match placeholders (/api/users/{id})."""
        truth = self.GroundTruth(
            target="test_app",
            items=[
                {"id": "REAL-IDOR", "vuln_type": "idor", "endpoint": "/api/users/{id}", "classification": "real"}
            ],
            informational=[]
        )
        findings = [
            {"vuln_type": "idor", "endpoint": "/api/users/1", "title": "IDOR"}
        ]
        res = self.compute_metrics(findings, truth)
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["false_negatives"], 0)

    def test_cookie_matched_by_endpoint_and_unrelated_endpoint_is_false_positive(self):
        """Cookies are matched by endpoint; a cookie finding on an unrelated endpoint (/other) is an FP."""
        truth = self.GroundTruth(
            target="test_app",
            items=[
                {"id": "COOKIE-LOGIN", "vuln_type": "insecure_cookie", "endpoint": "/login", "classification": "real"}
            ],
            informational=[]
        )
        # 1. Matching endpoint -> TP
        res_ok = self.compute_metrics(
            [{"vuln_type": "insecure_cookie", "endpoint": "/login", "title": "Cookie"}],
            truth
        )
        self.assertEqual(res_ok["true_positives"], 1)
        self.assertEqual(res_ok["false_positives"], 0)

        # 2. Unrelated endpoint (/other) -> FP
        res_fp = self.compute_metrics(
            [{"vuln_type": "insecure_cookie", "endpoint": "/other", "title": "Cookie on /other"}],
            truth
        )
        self.assertEqual(res_fp["true_positives"], 0)
        self.assertEqual(res_fp["false_positives"], 1)
        self.assertEqual(res_fp["false_negatives"], 1)

    def test_placeholder_matching_with_non_numeric_identifiers(self):
        """Non-numeric route segments like /users/v1/alice match {username} or {id} placeholders."""
        self.assertTrue(self.endpoint_matches("/users/v1/alice", "/users/v1/{id}"))
        self.assertTrue(self.endpoint_matches("/users/v1/alice/email", "/users/v1/{id}/email"))
        self.assertFalse(self.endpoint_matches("/users/v1/alice/email", "/users/v1/{id}"))
        self.assertFalse(self.endpoint_matches("/users/v1", "/users/v1/{id}"))

        truth = self.GroundTruth(
            target="vampi_app",
            items=[
                {"id": "VAMPI-BOLA", "vuln_type": "idor", "endpoint": "/users/v1/{username}", "classification": "real"}
            ],
            informational=[]
        )
        findings = [
            {"vuln_type": "idor", "endpoint": "/users/v1/alice", "title": "BOLA on user alice"}
        ]
        res = self.compute_metrics(findings, truth)
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_positives"], 0)

    def test_edge_cases_empty_findings_and_truth(self):
        """No division by zero on empty findings or empty truth edge cases."""
        # 1. Empty truth and empty findings
        empty_truth = self.GroundTruth(target="empty", items=[], informational=[])
        res = self.compute_metrics([], empty_truth)
        self.assertEqual(res["true_positives"], 0)
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["false_negatives"], 0)
        self.assertAlmostEqual(res["precision"], 1.0)
        self.assertAlmostEqual(res["recall"], 1.0)
        self.assertAlmostEqual(res["f1"], 1.0)

        # 2. Real truth items but empty findings
        has_truth = self.GroundTruth(
            target="real",
            items=[{"id": "R1", "vuln_type": "sqli", "endpoint": "/a", "classification": "real"}],
            informational=[]
        )
        res2 = self.compute_metrics([], has_truth)
        self.assertEqual(res2["true_positives"], 0)
        self.assertEqual(res2["false_positives"], 0)
        self.assertEqual(res2["false_negatives"], 1)
        self.assertAlmostEqual(res2["precision"], 0.0)
        self.assertAlmostEqual(res2["recall"], 0.0)
        self.assertAlmostEqual(res2["f1"], 0.0)

        # 3. Empty truth but findings reported
        res3 = self.compute_metrics([{"vuln_type": "sqli", "endpoint": "/a"}], empty_truth)
        self.assertEqual(res3["true_positives"], 0)
        self.assertEqual(res3["false_positives"], 1)
        self.assertEqual(res3["false_negatives"], 0)
        self.assertAlmostEqual(res3["precision"], 0.0)
        self.assertAlmostEqual(res3["recall"], 1.0)
        self.assertAlmostEqual(res3["f1"], 0.0)


class TestGroundTruthSchema(unittest.TestCase):
    """Schema validation for all ground-truth files (AUD-70 acceptance)."""

    def test_all_ground_truth_files_conform_to_schema(self):
        truth_dir = Path(__file__).parent / "benchmark" / "ground_truth"
        self.assertTrue(truth_dir.is_dir(), f"Ground truth dir {truth_dir} must exist")

        json_files = list(truth_dir.glob("*.json"))
        expected_files = {"testbed1.json", "testbed2.json", "pygoat.json", "vampi.json", "vulpy.json"}
        found_names = {f.name for f in json_files}
        self.assertTrue(expected_files.issubset(found_names),
                        f"Missing ground truth files. Expected: {expected_files}, found: {found_names}")

        allowed_classifications = {"real", "decoy"}
        required_item_keys = {"id", "vuln_type", "endpoint", "classification"}
        external_app_files = {"pygoat.json", "vampi.json", "vulpy.json"}

        for fpath in json_files:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("target", data, f"{fpath.name} missing 'target'")
            self.assertIn("items", data, f"{fpath.name} missing 'items'")
            items = data["items"]
            self.assertIsInstance(items, list, f"{fpath.name} 'items' must be a list")

            seen_ids = set()
            for idx, item in enumerate(items):
                item_prefix = f"{fpath.name} item #{idx} ({item.get('id', 'unknown')})"
                # Required keys
                for key in required_item_keys:
                    self.assertIn(key, item, f"{item_prefix} missing required key '{key}'")

                # Allowed classification values
                self.assertIn(item["classification"], allowed_classifications,
                              f"{item_prefix} invalid classification '{item['classification']}'")

                # No duplicate ids
                item_id = item["id"]
                self.assertNotIn(item_id, seen_ids, f"{fpath.name} duplicate id '{item_id}'")
                seen_ids.add(item_id)

                # Endpoints start with /
                endpoint = item["endpoint"]
                self.assertTrue(endpoint.startswith("/"),
                                f"{item_prefix} endpoint '{endpoint}' does not start with '/'")

                # Source citation required on external apps
                if fpath.name in external_app_files:
                    self.assertIn("source", item, f"{item_prefix} external app item must have 'source'")
                    self.assertTrue(bool(item.get("source")), f"{item_prefix} 'source' must not be empty")

                # Optional detectable boolean
                if "detectable" in item:
                    self.assertIsInstance(item["detectable"], bool,
                                          f"{item_prefix} 'detectable' must be boolean")


class TestBenchmarkRunnerCLI(unittest.TestCase):
    """Tests for runner CLI argument handling, loopback validation, and reachability."""

    def test_is_loopback_target_helper(self):
        """Unit test for is_loopback_target helper accepting 127.0.0.2/localhost and rejecting RFC 1918."""
        from benchmark.run_benchmark import is_loopback_target
        ok, _ = is_loopback_target("http://127.0.0.1:8080")
        self.assertTrue(ok)
        ok, _ = is_loopback_target("http://127.0.0.2:8080")
        self.assertTrue(ok)
        ok, _ = is_loopback_target("http://localhost:5000")
        self.assertTrue(ok)

        # Rejects private network IPs
        ok, msg = is_loopback_target("http://192.168.1.10:8000")
        self.assertFalse(ok)
        self.assertIn("loopback", msg.lower())

        ok, msg = is_loopback_target("http://10.0.0.5:8000")
        self.assertFalse(ok)
        self.assertIn("loopback", msg.lower())

    def test_runner_rejects_non_loopback_target_with_nonzero_exit(self):
        """CLI subprocess test asserting non-zero exit and 'loopback' in stderr for non-loopback hosts."""
        for target in ("http://192.168.1.10", "http://10.0.0.5", "http://example.com"):
            proc = subprocess.run(
                [sys.executable, "-m", "benchmark.run_benchmark", "--url", target, "--truth", "testbed1"],
                capture_output=True,
                text=True
            )
            self.assertNotEqual(proc.returncode, 0, f"Expected non-zero exit for {target}")
            output = proc.stdout + proc.stderr
            self.assertIn("loopback", output.lower(),
                          f"Expected loopback rejection message for {target}, got: {output}")

    def test_runner_reports_clear_error_when_url_unreachable(self):
        # Port 59199 is closed loopback
        proc = subprocess.run(
            [sys.executable, "-m", "benchmark.run_benchmark", "--url", "http://127.0.0.1:59199", "--truth", "testbed1"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(proc.returncode, 0)
        output = proc.stdout + proc.stderr
        self.assertNotIn("Traceback (most recent call last)", output,
                         f"Runner should report a clear error instead of a traceback: {output}")
        self.assertTrue("unreachable" in output.lower() or "offline" in output.lower() or "connection" in output.lower(),
                        f"Expected unreachable message, got: {output}")

    def test_runner_url_mode_against_local_testbed1(self):
        """Run --url against started testbed1 and assert same metrics as built-in mode."""
        from testsupport import LocalFixtureServer
        from testbed.app import app as testbed1_app
        from benchmark.run_benchmark import run_builtin_testbed

        # 1. Run built-in testbed1 benchmark
        builtin_res = run_builtin_testbed("testbed1")["metrics"]

        # 2. Run --url mode via subprocess against a local testbed1 fixture
        with LocalFixtureServer(testbed1_app) as srv:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_json = os.path.join(tmpdir, "url_mode_results.json")
                proc = subprocess.run(
                    [sys.executable, "-m", "benchmark.run_benchmark",
                     "--url", srv.base_url,
                     "--truth", "testbed1",
                     "--output", tmp_json],
                    capture_output=True,
                    text=True
                )
                self.assertEqual(proc.returncode, 0, f"URL mode run failed: {proc.stdout}\n{proc.stderr}")
                self.assertTrue(os.path.isfile(tmp_json))

                with open(tmp_json, "r", encoding="utf-8") as f:
                    saved_data = json.load(f)

                self.assertIn("testbed1", saved_data)
                url_metrics = saved_data["testbed1"]["metrics"]

                # Assert metrics equal built-in mode
                for key in ("true_positives", "false_positives", "false_negatives",
                            "matched_items", "precision", "recall", "f1"):
                    self.assertEqual(
                        url_metrics[key],
                        builtin_res[key],
                        f"Mismatch in {key}: url_mode={url_metrics[key]} vs builtin={builtin_res[key]}"
                    )


class TestBenchmarkBuiltinTestbeds(unittest.TestCase):
    """End-to-end benchmark test against testbed1 and testbed2 (AUD-69 acceptance)."""

    def test_benchmark_builtin_testbed1_and_testbed2(self):
        """Starts testbed1 and testbed2, runs benchmark, asserts 0 FP, recall >= 0.85 on each, and metrics JSON."""
        from benchmark.run_benchmark import run_all_benchmarks

        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = os.path.join(tmpdir, "benchmark_results.json")
            results = run_all_benchmarks(output_file=json_out, targets=["testbed1", "testbed2"])

            self.assertIn("testbed1", results)
            self.assertIn("testbed2", results)

            for target_name in ("testbed1", "testbed2"):
                target_res = results[target_name]
                metrics = target_res["metrics"]
                self.assertEqual(metrics["false_positives"], 0,
                                 f"{target_name} had false positives: {metrics.get('false_positive_findings')}")
                self.assertGreaterEqual(metrics["recall"], 0.85,
                                        f"{target_name} recall was below 0.85: {metrics['recall']}")
                self.assertIn("duration_seconds", target_res)
                self.assertIn("precision", metrics)
                self.assertIn("recall", metrics)
                self.assertIn("f1", metrics)

            # Assert results JSON file exists and contains the required keys
            self.assertTrue(os.path.isfile(json_out))
            with open(json_out, "r", encoding="utf-8") as f:
                saved = json.load(f)
            for target_name in ("testbed1", "testbed2"):
                self.assertIn(target_name, saved)
                self.assertIn("duration_seconds", saved[target_name])
                self.assertIn("precision", saved[target_name]["metrics"])
                self.assertIn("recall", saved[target_name]["metrics"])
                self.assertIn("f1", saved[target_name]["metrics"])


class TestBenchmarkEngineFiltering(unittest.TestCase):
    """Unit tests for BenchmarkEngine plugin filtering (AUD-69)."""

    def test_benchmark_engine_excludes_nmap_and_nikto(self):
        """BenchmarkEngine excludes binary tools (Nmap, Nikto) and drops count vs Engine."""
        from core.engine import Engine
        from benchmark.run_benchmark import BenchmarkEngine

        base_engine = Engine()
        base_count = base_engine.load_plugins()

        bench_engine = BenchmarkEngine()
        bench_count = bench_engine.load_plugins()

        # Asserts the count dropped versus Engine
        self.assertLess(bench_count, base_count)
        # Asserts no remaining plugin has tool name nmap or nikto
        for p in bench_engine.plugins:
            tool_name = p._get_tool_name().lower() if hasattr(p, "_get_tool_name") else ""
            stem = Path(tool_name).stem.lower() if tool_name else ""
            self.assertNotIn("nmap", {tool_name, stem})
            self.assertNotIn("nikto", {tool_name, stem})
            self.assertNotIn(p.__class__.__name__, ("NmapPlugin", "NiktoPlugin"))


if __name__ == "__main__":
    unittest.main()
