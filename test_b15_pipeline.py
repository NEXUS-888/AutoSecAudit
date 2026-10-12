"""
Unit tests for Batch 15: One Pipeline (AUD-40, AUD-41, AUD-42).
"""

import os
import sys
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import config
from core.models import Finding, Report, VulnType
from core.utils import generate_report_id
from core.pipeline import run_scan_pipeline, ScanRequest, PipelinePaths
from core.engine import Engine
from reports.generator import ReportGenerator
import main
import mcp_server


class TestAUD40UnifiedScanPipeline(unittest.TestCase):
    """Test suite for AUD-40: Unified Scan Pipeline."""

    def test_correlator_instantiated_in_exactly_one_non_test_module(self):
        """Acceptance criterion: Correlator( is instantiated in exactly one non-test module."""
        repo_root = Path(__file__).parent.resolve()
        py_files = []
        for p in repo_root.rglob("*.py"):
            rel_str = str(p.relative_to(repo_root)).replace("\\", "/")
            # Exclude test files, test directories, audit scripts, and venv/git
            if (
                rel_str.startswith("test_")
                or "/test_" in rel_str
                or rel_str.startswith("tests/")
                or rel_str.startswith("audit/")
                or rel_str.startswith("testbed/")
                or ".venv" in rel_str
                or "build_" in rel_str
            ):
                continue
            py_files.append((p, rel_str))

        correlator_instantiations = []
        pattern = re.compile(r"\bCorrelator\s*\(")
        for path, rel_str in py_files:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Strip comments and docstrings roughly or check lines
            for line_idx, line in enumerate(content.splitlines(), start=1):
                clean_line = line.strip()
                if clean_line.startswith("#"):
                    continue
                if pattern.search(clean_line):
                    correlator_instantiations.append((rel_str, line_idx, clean_line))

        modules_instantiating = {rel_str for rel_str, _, _ in correlator_instantiations}
        self.assertEqual(
            modules_instantiating,
            {"core/pipeline.py"},
            f"Correlator( should only be instantiated in core/pipeline.py, but found: {correlator_instantiations}",
        )

    def test_mcp_scan_result_findings_include_cwe_id(self):
        """Acceptance criterion: An MCP scan result's findings include cwe_id."""
        result = mcp_server.handle_scan({
            "target": "http://127.0.0.1:8080",
            "mock": True,
            "profile": "full",
            "skip_reachability": True,
        })
        self.assertEqual(result.get("status"), "success")
        findings = result.get("findings", [])
        self.assertGreater(len(findings), 0, "MCP scan should return findings in mock mode")

        # Every finding dict should have a cwe_id key, and mapped vulnerabilities have valid CWE format
        has_cwe = False
        for f in findings:
            self.assertIn("cwe_id", f, f"Finding '{f.get('title')}' missing 'cwe_id' key")
            if f["cwe_id"] and f["cwe_id"].startswith("CWE-"):
                has_cwe = True

        self.assertTrue(has_cwe, "Expected at least some findings to have populated CWE-xxx IDs")

    def test_run_scan_pipeline_full_workflow(self):
        """run_scan_pipeline performs full workflow and returns (Report, PipelinePaths)."""
        stages_visited = []

        def callback(stage, msg, pct=0, detail="", status=None):
            stages_visited.append(stage)

        req = ScanRequest(
            target="http://127.0.0.1:8080",
            mock_mode=True,
            profile="full",
            skip_reachability=True,
            progress_callback=callback,
        )

        report, paths = run_scan_pipeline(req)

        self.assertIsInstance(report, Report)
        self.assertIsInstance(paths, PipelinePaths)
        self.assertTrue(os.path.exists(paths.json))
        self.assertTrue(os.path.exists(paths.html))

        # Check tuple unpacking and dict access
        j_path, h_path = paths
        self.assertEqual(j_path, paths.json)
        self.assertEqual(h_path, paths.html)
        self.assertEqual(paths["json"], paths.json)
        self.assertEqual(paths["html"], paths.html)

        # Check that post-processing steps occurred
        self.assertGreater(len(report.all_findings), 0)
        for f in report.all_findings:
            self.assertTrue(f.cwe_id, f"Finding {f.title} should have cwe_id from ComplianceMapper")
            self.assertIsNotNone(f.remediation, f"Finding {f.title} should have remediation")

        # Clean up created files
        for p in (paths.json, paths.html):
            if os.path.exists(p):
                os.remove(p)

        self.assertIn("init", stages_visited)
        self.assertIn("scanning", stages_visited)
        self.assertIn("processing", stages_visited)
        self.assertIn("enriching", stages_visited)
        self.assertIn("saving", stages_visited)
        self.assertIn("done", stages_visited)

    def test_run_scan_pipeline_disallowed_target(self):
        """run_scan_pipeline enforces scope check and raises PermissionError for disallowed target."""
        req = ScanRequest(
            target="http://10.example.com",
            mock_mode=True,
        )
        with self.assertRaises(PermissionError):
            run_scan_pipeline(req)

    def test_run_scan_pipeline_invalid_target(self):
        """run_scan_pipeline enforces target validation and raises ValueError for invalid target."""
        req = ScanRequest(
            target="not_a_valid_url",
            mock_mode=True,
        )
        with self.assertRaises(ValueError):
            run_scan_pipeline(req)

    def test_run_scan_pipeline_with_delta(self):
        """run_scan_pipeline correctly runs delta analysis when previous_report is passed."""
        prev_report = Report(
            target="http://127.0.0.1:8080",
            timestamp="2026-01-01 10:00:00",
            all_findings=[
                Finding(
                    id="OLD-1",
                    title="Old SQL Injection",
                    severity="High",
                    host="127.0.0.1",
                    port=8080,
                    description="Old finding",
                    raw_output="",
                    vuln_type="sqli",
                    endpoint="/old",
                )
            ],
        )

        req = ScanRequest(
            target="http://127.0.0.1:8080",
            mock_mode=True,
            skip_reachability=True,
            previous_report=prev_report,
        )
        report, paths = run_scan_pipeline(req)
        self.assertIsNotNone(report.delta)

        for p in (paths.json, paths.html):
            if os.path.exists(p):
                os.remove(p)

    def test_run_scan_pipeline_cancellation_halts_without_saving_reports(self):
        """Pass a cancel_check that returns True after 'scanning' stage; assert no reports created and run stopped."""
        from core.pipeline import ScanCancelledError

        temp_reports_dir = tempfile.mkdtemp()
        cancelled_flag = [False]

        def cancel_check():
            return cancelled_flag[0]

        def progress_callback(stage, msg, pct=0, detail="", status=None):
            if stage == "scanning" and pct >= 55:
                cancelled_flag[0] = True

        with patch("config.REPORTS_DIR", temp_reports_dir):
            req = ScanRequest(
                target="http://127.0.0.1:8080",
                mock_mode=True,
                skip_reachability=True,
                progress_callback=progress_callback,
                cancel_check=cancel_check,
            )

            with self.assertRaises(ScanCancelledError):
                run_scan_pipeline(req)

            # Assert that no scan_*.json or report_*.html was created in the patched REPORTS_DIR
            created_files = list(Path(temp_reports_dir).glob("*"))
            self.assertEqual(
                created_files,
                [],
                f"Expected no report files to be created upon cancellation, but found: {created_files}",
            )

        if os.path.exists(temp_reports_dir):
            try:
                os.rmdir(temp_reports_dir)
            except OSError:
                pass

    def test_ui_async_scan_cancelled_job_does_not_set_report_name(self):
        """A cancelled or error job in UI does not set report_name and stops execution."""
        from ui.app import _run_scan_background, scan_jobs
        import uuid

        # Case 1: Job already marked error before start
        scan_id1 = str(uuid.uuid4())
        scan_jobs[scan_id1] = {
            "id": scan_id1,
            "target": "http://127.0.0.1:8080",
            "status": "error",
            "events": [],
            "error": "Scan timed out after 300s",
        }
        _run_scan_background(scan_id1, "http://127.0.0.1:8080", is_demo=True, skip_reachability=True)
        job1 = scan_jobs.get(scan_id1, {})
        self.assertNotIn("report_name", job1)
        self.assertEqual(job1.get("status"), "error")

        # Case 2: Job marked error during execution (after plugins)
        scan_id2 = str(uuid.uuid4())
        scan_jobs[scan_id2] = {
            "id": scan_id2,
            "target": "http://127.0.0.1:8080",
            "status": "starting",
            "events": [],
        }

        orig_run_plugins = Engine.run_plugins
        def cancel_during_plugins(engine_self):
            res = orig_run_plugins(engine_self)
            scan_jobs[scan_id2]["status"] = "error"
            scan_jobs[scan_id2]["error"] = "Cancelled by user"
            return res

        with patch.object(Engine, "run_plugins", side_effect=cancel_during_plugins, autospec=True):
            _run_scan_background(scan_id2, "http://127.0.0.1:8080", is_demo=True, skip_reachability=True)

        job2 = scan_jobs.get(scan_id2, {})
        self.assertNotIn("report_name", job2)
        self.assertEqual(job2.get("status"), "error")


class TestAUD41CLIDefects(unittest.TestCase):
    """Test suite for AUD-41: CLI Defects."""

    def test_cli_scan_custom_html_output_file(self):
        """Acceptance criterion: main.py scan ... --mock --html out.html writes out.html."""
        temp_dir = tempfile.mkdtemp()
        out_html = os.path.join(temp_dir, "custom_scan_report.html")
        try:
            exit_code = main.run_scan(
                target="http://127.0.0.1:8080",
                output_html=out_html,
                mock_mode=True,
                skip_reachability=True,
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(out_html), f"Expected {out_html} to be created")
            content = Path(out_html).read_text(encoding="utf-8")
            self.assertIn("AutoSecAudit", content)
            self.assertIn("html", content.lower())
        finally:
            if os.path.exists(out_html):
                os.remove(out_html)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)

    def test_cli_flags_real_mock_only_on_subcommands(self):
        """Keep --real/--mock only on the subcommands; remove global duplicates."""
        import io
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", new_callable=io.StringIO):
                with patch.object(sys, "argv", ["main.py", "--mock", "scan", "http://127.0.0.1:8080"]):
                    main.main()

    def test_cli_subcommands_have_mock_and_real_flags(self):
        """Subcommands 'scan' and 'server' must have --real and --mock flags."""
        # Test scan subcommand accepts --mock and --real
        with patch.object(sys, "argv", ["main.py", "scan", "http://127.0.0.1:8080", "--mock", "--skip-reachability-check"]):
            with patch("main.run_scan", return_value=0) as mock_scan:
                main.main()
                mock_scan.assert_called_once()
                # mock_mode should be True
                _, kwargs = mock_scan.call_args
                self.assertTrue(kwargs.get("mock_mode"))

        with patch.object(sys, "argv", ["main.py", "scan", "http://127.0.0.1:8080", "--real", "--skip-reachability-check"]):
            with patch("main.run_scan", return_value=0) as mock_scan:
                main.main()
                mock_scan.assert_called_once()
                _, kwargs = mock_scan.call_args
                self.assertFalse(kwargs.get("mock_mode"))

    def test_cli_login_pass_from_env_when_user_provided(self):
        """Read password from AUTOSEC_LOGIN_PASS when --login-user is given without --login-pass."""
        with patch.dict(os.environ, {"AUTOSEC_LOGIN_PASS": "SecretEnvPass123"}):
            with patch("main.run_scan_pipeline") as mock_pipeline:
                mock_pipeline.return_value = (
                    Report(target="http://127.0.0.1:8080", timestamp=""),
                    PipelinePaths("test.json", "test.html"),
                )
                exit_code = main.run_scan(
                    target="http://127.0.0.1:8080",
                    login_user="admin",
                    login_pass=None,
                    mock_mode=True,
                    skip_reachability=True,
                )
                self.assertEqual(exit_code, 0)
                call_req = mock_pipeline.call_args[0][0]
                self.assertEqual(call_req.login_user, "admin")
                self.assertEqual(call_req.login_pass, "SecretEnvPass123")

    def test_cli_warns_when_login_pass_exposed_on_command_line(self):
        """Warn that --login-pass in CLI arguments is visible in the process list."""
        with patch.object(sys, "argv", ["main.py", "scan", "http://127.0.0.1:8080", "--login-user", "admin", "--login-pass", "exposed"]):
            with patch("main.run_scan_pipeline") as mock_pipeline:
                mock_pipeline.return_value = (
                    Report(target="http://127.0.0.1:8080", timestamp=""),
                    PipelinePaths("test.json", "test.html"),
                )
                with patch("builtins.print") as mock_print:
                    main.run_scan(
                        target="http://127.0.0.1:8080",
                        login_user="admin",
                        login_pass="exposed",
                        mock_mode=True,
                        skip_reachability=True,
                    )
                    printed_text = " ".join(str(call[0][0]) for call in mock_print.call_args_list if call[0])
                    self.assertIn("process table", printed_text.lower())

    def test_cli_warns_when_login_pass_with_equals_exposed_on_command_line(self):
        """Warn that --login-pass=secret via CLI arguments exposes secrets in the process table."""
        with patch.object(sys, "argv", ["main.py", "scan", "http://127.0.0.1:8080", "--login-user", "admin", "--login-pass=exposed"]):
            with patch("main.run_scan_pipeline") as mock_pipeline:
                mock_pipeline.return_value = (
                    Report(target="http://127.0.0.1:8080", timestamp=""),
                    PipelinePaths("test.json", "test.html"),
                )
                with patch("builtins.print") as mock_print:
                    main.run_scan(
                        target="http://127.0.0.1:8080",
                        login_user="admin",
                        login_pass="exposed",
                        mock_mode=True,
                        skip_reachability=True,
                    )
                    printed_text = " ".join(str(call[0][0]) for call in mock_print.call_args_list if call[0])
                    self.assertIn("process table", printed_text.lower())

    def test_cli_menu_counts_computed_dynamically(self):
        """Fix stale menu text: plugin and test counts are computed dynamically."""
        plugins_count, tests_count = main._compute_menu_counts()
        self.assertGreaterEqual(plugins_count, 10, "Discovered plugin count should be computed and >= 10")
        self.assertGreaterEqual(tests_count, 50, "Discovered test count should be computed and >= 50")


class TestAUD42ReportIDUniqueness(unittest.TestCase):
    """Test suite for AUD-42: Report ID collisions / mismatch."""

    def test_generate_report_id_format(self):
        """report_id format must match <YYYYmmdd_HHMMSS>_<6 hex>."""
        rep_id = generate_report_id()
        pattern = r"^\d{8}_\d{6}_[0-9a-f]{6}$"
        self.assertRegex(rep_id, pattern, f"Report ID '{rep_id}' does not match pattern {pattern}")

    def test_two_scans_in_same_second_get_different_ids(self):
        """Acceptance criterion: Two scans in the same second get different IDs."""
        ids = [generate_report_id() for _ in range(50)]
        self.assertEqual(len(ids), len(set(ids)), "All generated report IDs must be distinct")

    def test_json_and_html_share_same_report_id(self):
        """Acceptance criterion: JSON and HTML of a scan share the same report_id."""
        req = ScanRequest(
            target="http://127.0.0.1:8080",
            mock_mode=True,
            skip_reachability=True,
        )
        report, paths = run_scan_pipeline(req)

        json_file = Path(paths.json)
        html_file = Path(paths.html)

        self.assertTrue(json_file.exists())
        self.assertTrue(html_file.exists())

        # Extract report ID from filenames
        json_id = json_file.stem.replace("scan_", "").replace("report_", "")
        html_id = html_file.stem.replace("scan_", "").replace("report_", "")

        self.assertEqual(
            json_id,
            html_id,
            f"JSON report ID '{json_id}' and HTML report ID '{html_id}' must match exactly",
        )
        self.assertEqual(
            report.report_id,
            json_id,
            f"Report object report_id '{report.report_id}' must match filenames' report_id '{json_id}'",
        )

        # Clean up
        if json_file.exists():
            json_file.unlink()
        if html_file.exists():
            html_file.unlink()

    def test_engine_save_report_and_generator_use_shared_id(self):
        """Direct engine.save_report and generator.generate_report share report_id."""
        engine = Engine(mock_mode=True)
        engine.set_target("http://127.0.0.1:8080", check_reachable=False)
        report = engine.generate_report()

        self.assertIsNotNone(report.report_id)
        json_path = engine.save_report(report)
        gen = ReportGenerator()
        html_path = gen.generate_report(report)

        json_id = Path(json_path).stem.replace("scan_", "").replace("report_", "")
        html_id = Path(html_path).stem.replace("scan_", "").replace("report_", "")

        self.assertEqual(json_id, html_id)
        self.assertEqual(report.report_id, json_id)

        # Clean up
        if os.path.exists(json_path):
            os.remove(json_path)
        if os.path.exists(html_path):
            os.remove(html_path)


if __name__ == "__main__":
    unittest.main()
