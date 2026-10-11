import unittest
from unittest.mock import patch, MagicMock
import tempfile
import json
from pathlib import Path
import config
from mcp_server import handle_get_findings, handle_verify_fix, handle_scan
from core.engine import Engine
from core.models import Finding, Report, ScanResult
from plugins.sqli_plugin import SQLiScanner


class TestB03MCPServer(unittest.TestCase):
    """Test suite for Batch 03: MCP server correctness (AUD-07, AUD-08, AUD-09)."""

    def test_aud_07_get_findings_reads_all_findings_and_computes_grade(self):
        """AUD-07: handle_get_findings reads all_findings, maps real fields, validates report_id."""
        # Test invalid report_id pattern rejection
        bad_res = handle_get_findings({"report_id": "../evil_path"})
        self.assertIn("error", bad_res)
        bad_newline = handle_get_findings({"report_id": "valid_id\n"})
        self.assertIn("error", bad_newline)
        bad_type = handle_get_findings({"report_id": 12345})
        self.assertIn("error", bad_type)

        # Create a report with 3 findings (one Critical -> grade cannot be A+)
        report_data = {
            "target": "http://localhost:3000",
            "timestamp": "20261011_120000",
            "all_findings": [
                {
                    "id": "SQLI-001",
                    "title": "SQL Injection",
                    "severity": "Critical",
                    "description": "SQL injection in query",
                    "host": "localhost",
                    "port": 3000,
                    "raw_output": "syntax error near SELECT",
                    "confidence": "high",
                    "cwe_id": "CWE-89",
                    "tool_name": "SQLiScanner",
                    "owasp_tag": "A03:2021",
                },
                {
                    "id": "CORS-001",
                    "title": "CORS Wildcard",
                    "severity": "Medium",
                    "description": "Wildcard origin",
                    "host": "localhost",
                    "port": 3000,
                    "raw_output": "Access-Control-Allow-Origin: *",
                    "confidence": "medium",
                    "cwe_id": "CWE-942",
                    "tool_name": "CORSScanner",
                    "owasp_tag": "A05:2021",
                },
                {
                    "id": "HDR-001",
                    "title": "Missing HSTS",
                    "severity": "Low",
                    "description": "Strict-Transport-Security header missing",
                    "host": "localhost",
                    "port": 3000,
                    "raw_output": "No HSTS header found",
                    "confidence": "high",
                    "cwe_id": "CWE-319",
                    "tool_name": "MisconfigScanner",
                    "owasp_tag": "A05:2021",
                }
            ]
        }

        reports_dir = Path(config.REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file = reports_dir / "scan_20261011_120000.json"
        try:
            report_file.write_text(json.dumps(report_data), encoding="utf-8")

            res = handle_get_findings({"report_id": "20261011_120000"})
            self.assertEqual(res.get("findings_count"), 3)
            self.assertNotEqual(res.get("executive_grade"), "A+")
            self.assertEqual(len(res.get("findings", [])), 3)

            first_finding = res["findings"][0]
            self.assertEqual(first_finding.get("id"), "SQLI-001")
            self.assertEqual(first_finding.get("description"), "SQL injection in query")
            self.assertEqual(first_finding.get("confidence"), "high")
            tech = first_finding.get("technical_details", {})
            self.assertEqual(tech.get("cwe_id"), "CWE-89")
            self.assertEqual(tech.get("raw_output"), "syntax error near SELECT")
        finally:
            if report_file.exists():
                report_file.unlink()

    def test_aud_08_verify_fix_unreachable_target(self):
        """AUD-08: An unreachable target returns status != 'RESOLVED' and verified=False."""
        # Port 59123 on 127.0.0.1 is closed/unreachable
        res = handle_verify_fix({
            "target": "http://127.0.0.1:59123",
            "vulnerability_type": "sqli",
            "mock": False
        })
        self.assertNotEqual(res.get("status"), "RESOLVED")
        self.assertEqual(res.get("status"), "ERROR")
        self.assertFalse(res.get("verified"))

    def test_aud_08_verify_fix_only_runs_relevant_plugin(self):
        """AUD-08: Spies on Engine.run_plugins without patching Engine.run, asserting only SQLiScanner runs."""
        captured_plugins = []
        original_run_plugins = Engine.run_plugins

        def spy_run_plugins(engine_self):
            captured_plugins.extend([p.__class__.__name__ for p in engine_self.plugins])
            return original_run_plugins(engine_self)

        with patch.object(Engine, "run_plugins", side_effect=spy_run_plugins, autospec=True):
            res = handle_verify_fix({
                "target": "http://localhost:8080",
                "vulnerability_type": "sqli",
                "mock": True
            })
            self.assertEqual(captured_plugins, ["SQLiScanner"])
            self.assertEqual(res.get("status"), "STILL_VULNERABLE")
            self.assertFalse(res.get("verified"))

    def test_aud_08_verify_fix_plugin_error_returns_status_error(self):
        """AUD-08: When a stubbed SQLiScanner.run raises, handle_verify_fix returns status='ERROR' and verified=False."""
        mock_crawl = MagicMock()
        mock_crawl.get_injectable_endpoints.return_value = []
        mock_crawl.get_login_endpoints.return_value = []

        with patch("core.utils.check_target_reachable", return_value=(True, "OK")), \
             patch("core.crawler.WebCrawler.crawl", return_value=mock_crawl), \
             patch("requests.get"), \
             patch.object(SQLiScanner, "run", side_effect=RuntimeError("SQLi scanner error")):
            res = handle_verify_fix({
                "target": "http://localhost:8080",
                "vulnerability_type": "sqli",
                "mock": False
            })
            self.assertEqual(res.get("status"), "ERROR")
            self.assertFalse(res.get("verified"))
            self.assertIn("SQLi scanner error", res.get("error", ""))

    def test_aud_08_verify_fix_failed_scan_result_returns_status_error(self):
        """AUD-08: When plugin result status is failed, returns status='ERROR' and verified=False."""
        failed_result = ScanResult(
            tool_name="SQLiScanner",
            target="http://localhost:8080",
            timestamp="20261011_120000",
            status="failed",
            error="Scanner execution aborted"
        )
        with patch.object(Engine, "run_plugins", return_value=[failed_result]):
            res = handle_verify_fix({
                "target": "http://localhost:8080",
                "vulnerability_type": "sqli",
                "mock": True
            })
            self.assertEqual(res.get("status"), "ERROR")
            self.assertFalse(res.get("verified"))

    def test_aud_08_verify_fix_unsupported_vuln_type(self):
        """AUD-08: When vulnerability_type='foo', returns status='ERROR' and verified=False without scanning."""
        res = handle_verify_fix({
            "target": "http://localhost:8080",
            "vulnerability_type": "foo",
            "mock": True
        })
        self.assertEqual(res.get("status"), "ERROR")
        self.assertFalse(res.get("verified"))
        self.assertIn("foo", res.get("error", ""))

    def test_aud_08_verify_fix_resolved_when_no_active_findings(self):
        """AUD-08: When plugin finds 0 vulnerabilities, status is RESOLVED and verified=True."""
        clean_mock = {"tool_name": "SQLiScanner", "status": "success", "findings": []}
        with patch.object(SQLiScanner, "_get_mock_output", return_value=clean_mock):
            res = handle_verify_fix({
                "target": "http://localhost:8080",
                "vulnerability_type": "sqli",
                "mock": True
            })
            self.assertEqual(res.get("status"), "RESOLVED")
            self.assertTrue(res.get("verified"))
            self.assertEqual(res.get("remaining_findings_count"), 0)

    def test_aud_09_handle_scan_disallowed_target(self):
        """AUD-09: handle_scan returns structured error for disallowed target."""
        res = handle_scan({"target": "http://10.example.com", "mock": True})
        self.assertEqual(res.get("status"), "error")
        self.assertIn("error", res)


if __name__ == "__main__":
    unittest.main()
