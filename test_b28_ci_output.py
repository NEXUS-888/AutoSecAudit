import os
import sys
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from core.models import Report, Finding, ScanResult


class TestCIOutput(unittest.TestCase):
    """Test suite for AUD-73: SARIF and JUnit CI/CD reporting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _build_sample_report(self) -> Report:
        """Create a synthetic report with findings of all severity levels."""
        findings = [
            Finding(
                id="FINDING-001",
                tool_name="SQLiScanner",
                vuln_type="sqli",
                title="SQL Injection in user parameter",
                severity="Critical",
                confidence="high",
                host="127.0.0.1",
                port=8080,
                endpoint="/api/users",
                param="id",
                method="GET",
                description="Unsanitized user input allows SQL injection.",
                raw_output="SQL error syntax near '1'",
                evidence="SELECT * FROM users WHERE id = '1' OR '1'='1'",
                cwe_id="CWE-89",
            ),
            Finding(
                id="FINDING-002",
                tool_name="XSSScanner",
                vuln_type="xss",
                title="Reflected XSS in search",
                severity="High",
                confidence="high",
                host="127.0.0.1",
                port=8080,
                endpoint="/search",
                param="q",
                method="GET",
                description="Cross-site scripting reflected in DOM.",
                raw_output="Reflected string: <script>alert(1)</script>",
                evidence="<script>alert(1)</script>",
                cwe_id="CWE-79",
            ),
            Finding(
                id="FINDING-003",
                tool_name="CSRFScanner",
                vuln_type="csrf",
                title="Missing CSRF Token",
                severity="Medium",
                confidence="medium",
                host="127.0.0.1",
                port=8080,
                endpoint="/transfer",
                param="amount",
                method="POST",
                description="State-changing endpoint lacks anti-CSRF protection.",
                raw_output="No anti-CSRF token detected in form or headers",
                evidence="POST /transfer HTTP/1.1 without CSRF header",
                cwe_id="CWE-352",
            ),
            Finding(
                id="FINDING-004",
                tool_name="MisconfigScanner",
                vuln_type="misconfig",
                title="Missing Security Headers",
                severity="Low",
                confidence="low",
                host="127.0.0.1",
                port=8080,
                endpoint="/",
                param=None,
                method="GET",
                description="Strict-Transport-Security header is not set.",
                raw_output="HSTS header absent",
                evidence="HSTS header absent",
                cwe_id="CWE-16",
            ),
            Finding(
                id="FINDING-005",
                tool_name="PortScanner",
                vuln_type="port_scan",
                title="Open Port 8080",
                severity="Info",
                confidence="medium",
                host="127.0.0.1",
                port=8080,
                endpoint="/",
                param=None,
                method="GET",
                description="TCP port 8080 is open.",
                raw_output="Port 8080 open",
                evidence="Port 8080 answered SYN-ACK",
                cwe_id="CWE-200",
            ),
            Finding(
                id="FINDING-006",
                tool_name="SQLiScanner",
                vuln_type="sqli",  # duplicate vuln_type to test rule uniqueness
                title="Second SQL Injection",
                severity="High",
                confidence="medium",
                host="127.0.0.1",
                port=8080,
                endpoint="/login",
                param="username",
                method="POST",
                description="Second SQL injection finding.",
                raw_output="SQL error",
                evidence="OR 1=1",
                cwe_id="CWE-89",
            ),
        ]

        scan_result = ScanResult(
            tool_name="AutoSecAudit",
            target="http://127.0.0.1:8080",
            timestamp="2026-10-17 00:00:00",
            findings=findings,
            status="success",
        )

        return Report(
            target="http://127.0.0.1:8080",
            timestamp="2026-10-17 00:00:00",
            scan_results=[scan_result],
            all_findings=findings,
            summary={"total": len(findings), "critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1},
        )

    def test_sarif_generation_schema_and_structure(self):
        """Assert SARIF 2.1.0 schema, version, driver name, rule uniqueness, and level mapping."""
        from reports.sarif import generate_sarif_report

        report = self._build_sample_report()
        sarif_path = os.path.join(self.temp_dir.name, "report.sarif")
        sarif_data = generate_sarif_report(report, sarif_path)

        self.assertTrue(os.path.exists(sarif_path), "SARIF file must be written to output path")
        with open(sarif_path, "r", encoding="utf-8") as f:
            disk_data = json.load(f)

        self.assertEqual(sarif_data, disk_data)
        self.assertEqual(sarif_data.get("version"), "2.1.0")
        self.assertTrue(sarif_data.get("$schema", "").startswith("https://"))

        runs = sarif_data.get("runs", [])
        self.assertEqual(len(runs), 1, "SARIF must have exactly one run")

        run = runs[0]
        driver = run.get("tool", {}).get("driver", {})
        self.assertEqual(driver.get("name"), "AutoSecAudit")

        # Check rules
        rules = driver.get("rules", [])
        self.assertGreater(len(rules), 0)
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)), "Rule IDs must be unique")

        # Check distinct vuln_types mapped
        expected_vuln_types = {"sqli", "xss", "csrf", "misconfig", "port_scan"}
        self.assertEqual(set(rule_ids), expected_vuln_types)

        # Check CWE in rule properties
        for r in rules:
            self.assertIn("shortDescription", r)
            self.assertIn("text", r["shortDescription"])
            props = r.get("properties", {})
            self.assertIn("cwe", props)
            self.assertTrue(str(props["cwe"]).startswith("CWE-"))

        # Check results
        results = run.get("results", [])
        self.assertEqual(len(results), len(report.all_findings))

        rule_id_set = set(rule_ids)
        level_map = {
            "Critical": "error",
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Info": "note",
        }

        for res, finding in zip(results, report.all_findings):
            self.assertIn(res["ruleId"], rule_id_set, "Result ruleId must exist in rules")
            expected_level = level_map[finding.severity]
            self.assertEqual(res["level"], expected_level, f"Level mapping for {finding.severity} must be {expected_level}")

            # Message
            self.assertIn("text", res.get("message", {}))

            # Locations
            locs = res.get("locations", [])
            self.assertGreater(len(locs), 0)
            uri = locs[0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertEqual(uri, finding.endpoint or "/")

            # Properties: severity and confidence
            res_props = res.get("properties", {})
            self.assertEqual(res_props.get("severity"), finding.severity)
            self.assertEqual(res_props.get("confidence"), finding.confidence)

    def test_junit_generation_structure_and_thresholds(self):
        """Assert JUnit XML structure, test count, failure elements, and fail_on thresholds."""
        from reports.junit import generate_junit_report

        report = self._build_sample_report()

        # 1. No threshold: ALL findings are failures
        junit_path = os.path.join(self.temp_dir.name, "report_all_fail.xml")
        xml_str = generate_junit_report(report, junit_path, fail_on=None)
        self.assertTrue(os.path.exists(junit_path))

        tree = ET.parse(junit_path)
        root = tree.getroot()
        self.assertEqual(root.tag, "testsuite")
        self.assertEqual(root.attrib.get("name"), "AutoSecAudit")
        self.assertEqual(int(root.attrib.get("tests", 0)), len(report.all_findings))
        self.assertEqual(int(root.attrib.get("failures", 0)), len(report.all_findings))

        testcases = root.findall("testcase")
        self.assertEqual(len(testcases), len(report.all_findings))
        for tc in testcases:
            failures = tc.findall("failure")
            self.assertEqual(len(failures), 1, "Without threshold, all testcases must have failure child")
            self.assertTrue(failures[0].attrib.get("type"))
            self.assertTrue(failures[0].attrib.get("message"))

        # 2. fail_on="high": only Critical (1) and High (2) = 3 failures
        junit_path_high = os.path.join(self.temp_dir.name, "report_fail_high.xml")
        generate_junit_report(report, junit_path_high, fail_on="high")
        tree_high = ET.parse(junit_path_high)
        root_high = tree_high.getroot()
        self.assertEqual(int(root_high.attrib.get("tests", 0)), len(report.all_findings))
        self.assertEqual(int(root_high.attrib.get("failures", 0)), 3)

        high_testcases = root_high.findall("testcase")
        self.assertEqual(len(high_testcases), len(report.all_findings))
        failures_count = sum(len(tc.findall("failure")) for tc in high_testcases)
        self.assertEqual(failures_count, 3)

        # 3. fail_on="critical": only Critical (1) = 1 failure
        junit_path_crit = os.path.join(self.temp_dir.name, "report_fail_crit.xml")
        generate_junit_report(report, junit_path_crit, fail_on="critical")
        tree_crit = ET.parse(junit_path_crit)
        root_crit = tree_crit.getroot()
        self.assertEqual(int(root_crit.attrib.get("failures", 0)), 1)

    def test_authenticated_scan_credentials_redacted_from_reports(self):
        """Assert scan password and session cookies do not appear in SARIF or JUnit files."""
        from http.server import ThreadingHTTPServer
        import threading
        import config
        from test_b28_authenticated_dashboard import FixtureCSRFAuthServer
        from core.pipeline import run_scan_pipeline, ScanRequest
        from reports.sarif import generate_sarif_report
        from reports.junit import generate_junit_report

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureCSRFAuthServer)
        server.daemon_threads = True
        port = server.server_port
        target_url = f"http://127.0.0.1:{port}"

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        orig_profiles = dict(getattr(config, "SCAN_PROFILES", {}))
        config.SCAN_PROFILES["fast_ci_test"] = {
            "name": "Fast CI Profile",
            "description": "Fast profile for CI tests",
            "plugins": ["CSRFScanner"]
        }

        secret_password = "Correct_P@ss_2026!"
        secret_cookie = "admin_logged_in_token"

        try:
            req = ScanRequest(
                target=target_url,
                profile="fast_ci_test",
                mock_mode=False,
                skip_reachability=True,
                login_user="admin",
                login_pass=secret_password,
                login_url="/login",
            )
            report, _ = run_scan_pipeline(req)

            sarif_path = os.path.join(self.temp_dir.name, "auth_test.sarif")
            junit_path = os.path.join(self.temp_dir.name, "auth_test.xml")

            generate_sarif_report(report, sarif_path)
            generate_junit_report(report, junit_path, fail_on="medium")

            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif_text = f.read()
            with open(junit_path, "r", encoding="utf-8") as f:
                junit_text = f.read()

            # Positive control assertions ensuring reports contain findings and valid structure
            self.assertIn("AutoSecAudit", sarif_text)
            self.assertIn("testsuite", junit_text)

            # Assert secret password and session cookie are completely absent
            self.assertNotIn(secret_password, sarif_text, "Password must not appear in SARIF report")
            self.assertNotIn(secret_cookie, sarif_text, "Session cookie must not appear in SARIF report")
            self.assertNotIn(secret_password, junit_text, "Password must not appear in JUnit report")
            self.assertNotIn(secret_cookie, junit_text, "Session cookie must not appear in JUnit report")
        finally:
            server.shutdown()
            server.server_close()
            config.SCAN_PROFILES = orig_profiles

    def test_cli_sarif_and_junit_flags(self):
        """Assert CLI 'scan' accepts --sarif and --junit, writes both, keeping JSON/HTML intact."""
        from main import main

        # Run 1: with --sarif and --junit
        sarif_out = os.path.join(self.temp_dir.name, "cli_output.sarif")
        junit_out = os.path.join(self.temp_dir.name, "cli_output.xml")
        json_out1 = os.path.join(self.temp_dir.name, "cli_output1.json")
        html_out1 = os.path.join(self.temp_dir.name, "cli_output1.html")

        test_args1 = [
            "main.py",
            "scan",
            "http://127.0.0.1:8080",
            "--mock",
            "--sarif", sarif_out,
            "--junit", junit_out,
            "--json", json_out1,
            "--html", html_out1,
        ]

        with patch.object(sys, "argv", test_args1):
            exit_code1 = main()

        self.assertEqual(exit_code1, 0)
        self.assertTrue(os.path.exists(sarif_out), "CLI must create SARIF report")
        self.assertTrue(os.path.exists(junit_out), "CLI must create JUnit report")
        self.assertTrue(os.path.exists(json_out1), "CLI must create JSON report")
        self.assertTrue(os.path.exists(html_out1), "CLI must create HTML report")

        # Validate SARIF parseable
        with open(sarif_out, "r", encoding="utf-8") as f:
            s_data = json.load(f)
        self.assertEqual(s_data.get("version"), "2.1.0")

        # Validate JUnit parseable
        tree = ET.parse(junit_out)
        self.assertEqual(tree.getroot().tag, "testsuite")

        # Run 2: without --sarif and --junit
        json_out2 = os.path.join(self.temp_dir.name, "cli_output2.json")
        html_out2 = os.path.join(self.temp_dir.name, "cli_output2.html")

        test_args2 = [
            "main.py",
            "scan",
            "http://127.0.0.1:8080",
            "--mock",
            "--json", json_out2,
            "--html", html_out2,
        ]

        with patch.object(sys, "argv", test_args2):
            exit_code2 = main()

        self.assertEqual(exit_code2, 0)
        self.assertTrue(os.path.exists(json_out2))
        self.assertTrue(os.path.exists(html_out2))

        # Assert JSON reports are identical after dropping volatile keys
        with open(json_out1, "r", encoding="utf-8") as f:
            data1 = json.load(f)
        with open(json_out2, "r", encoding="utf-8") as f:
            data2 = json.load(f)

        def normalize_report(data):
            d = dict(data)
            volatile_keys = {
                "timestamp", "report_id", "duration", "scan_duration",
                "generated_at", "elapsed_seconds", "coverage"
            }
            for k in volatile_keys:
                d.pop(k, None)

            def norm_finding(f):
                fc = dict(f)
                for k in volatile_keys:
                    fc.pop(k, None)
                refs = fc.get("references")
                if refs and isinstance(refs, list):
                    norm_refs = []
                    for r in refs:
                        if isinstance(r, str) and r.startswith("Related findings: "):
                            prefix, ids_str = r.split(": ", 1)
                            ids = sorted([i.strip() for i in ids_str.split(",")])
                            norm_refs.append(prefix + ": " + ", ".join(ids))
                        else:
                            norm_refs.append(r)
                    norm_refs.sort(key=str)
                    fc["references"] = norm_refs
                return fc

            sr_list = []
            for sr in d.get("scan_results", []):
                sr_copy = dict(sr)
                for k in volatile_keys:
                    sr_copy.pop(k, None)
                sr_findings = [norm_finding(f) for f in sr_copy.get("findings", [])]
                sr_findings.sort(key=lambda x: (x.get("title", ""), x.get("endpoint", ""), str(x.get("description", ""))))
                sr_copy["findings"] = sr_findings
                sr_list.append(sr_copy)
            sr_list.sort(key=lambda x: x.get("tool_name", ""))
            d["scan_results"] = sr_list

            all_f = [norm_finding(f) for f in d.get("all_findings", [])]
            all_f.sort(key=lambda x: (x.get("title", ""), x.get("endpoint", ""), str(x.get("description", ""))))
            d["all_findings"] = all_f
            return d

        self.assertEqual(
            normalize_report(data1),
            normalize_report(data2),
            "JSON report contents must remain identical whether or not --sarif/--junit are used"
        )


if __name__ == "__main__":
    unittest.main()
