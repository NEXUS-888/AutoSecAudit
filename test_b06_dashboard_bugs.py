import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import config
import core.auth as auth
from ui.app import app, _resolve_report_data


class TestB06DashboardBugs(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

        # Ensure admin user exists and is logged in
        auth.init_user_db()
        admin = auth.get_user_by_username("admin")
        if not admin:
            auth.create_user("admin", "Admin123456!", "admin")
            admin = auth.get_user_by_username("admin")
        self.admin_id = admin["id"]

        auth.login_test_client(self.client, self.admin_id)

        self.reports_dir = Path(config.REPORTS_DIR)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.created_files = []

    def tearDown(self):
        for f in self.created_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

    # -----------------------------------------------------------------------
    # AUD-16: save_json NameError in JSON download & no files written on GET
    # -----------------------------------------------------------------------
    def test_aud16_download_report_returns_200_json_without_writing_files(self):
        """AUD-16: Downloading a report returns 200 JSON and writes no files to disk."""
        report_data = {
            "target": "http://localhost:3000",
            "timestamp": "2099-01-01 00:00:01",
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [{"id": "F01", "title": "Test Finding", "severity": "high"}]
        }
        # Create a report file named b06_custom.json (only clean_id.json)
        file_path = self.reports_dir / "b06_custom.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f)
        self.created_files.append(str(file_path))

        # Check existing files in REPORTS_DIR before GET
        files_before = set(os.listdir(self.reports_dir))

        # Download via scan_ prefix when only b06_custom.json exists - hits save_json and crashes with NameError!
        resp = self.client.get("/download/scan_b06_custom")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Content-Type"), "application/json")
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertIn("report_b06_custom.json", resp.headers.get("Content-Disposition", ""))

        payload = json.loads(resp.data.decode("utf-8"))
        self.assertEqual(payload["target"], "http://localhost:3000")
        self.assertEqual(len(payload["findings"]), 1)

        # Confirm the route wrote NO new files
        files_after = set(os.listdir(self.reports_dir))
        self.assertEqual(files_before, files_after, "GET /download/<id> must not write any files to disk")

    def test_aud16_download_report_found_via_various_naming_schemes(self):
        """AUD-16: Downloading report found via scan_<id>.json naming scheme works."""
        report_data = {
            "target": "http://localhost:3000",
            "summary": {"total": 0},
            "findings": []
        }
        file_path = self.reports_dir / "scan_b06_various.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f)
        self.created_files.append(str(file_path))

        # Test download with scan_ prefix
        resp = self.client.get("/download/scan_b06_various")
        self.assertEqual(resp.status_code, 200)
        payload = json.loads(resp.data.decode("utf-8"))
        self.assertEqual(payload["target"], "http://localhost:3000")

    def test_aud16_download_report_404_when_nonexistent(self):
        """AUD-16: Nonexistent report returns 404."""
        resp = self.client.get("/download/nonexistent_report_id_12345")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # AUD-17: Skip reachability does not silently switch to demo mode
    # -----------------------------------------------------------------------
    def test_aud17_post_scan_async_real_mode_with_skip_reachability(self):
        """AUD-17: POST /scan/async with mode=real&skip_reachability=true yields mode == 'real'."""
        with patch("ui.app.check_target_reachable") as mock_reach, \
             patch("ui.app._run_scan_background") as mock_bg:
            resp = self.client.post("/scan/async", data={
                "target": "http://localhost:3000",
                "mode": "real",
                "skip_reachability": "true"
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data.get("mode"), "real", "Mode must remain 'real' when skip_reachability=true")
            # Reachability probe must have been skipped
            mock_reach.assert_not_called()
            # Background scan must be launched with is_demo=False
            self.assertTrue(mock_bg.called)
            # args: (scan_id, target, previous_path, openapi_path, profile, skip_reachability, login_user, login_pass, login_url, is_demo)
            args = mock_bg.call_args[0]
            is_demo_arg = args[9] if len(args) > 9 else mock_bg.call_args[1].get("is_demo")
            self.assertFalse(is_demo_arg, "is_demo passed to background task must be False")

    def test_aud17_post_scan_async_demo_mode_remains_demo(self):
        """AUD-17: POST /scan/async with mode=demo yields mode == 'demo'."""
        with patch("ui.app.check_target_reachable") as mock_reach, \
             patch("ui.app._run_scan_background") as mock_bg:
            resp = self.client.post("/scan/async", data={
                "target": "http://localhost:3000",
                "mode": "demo",
                "skip_reachability": "true"
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data.get("mode"), "demo")
            mock_reach.assert_not_called()

    # -----------------------------------------------------------------------
    # AUD-18: Report lookup exact matching & dev-ticket 404 on unknown finding
    # -----------------------------------------------------------------------
    def test_aud18_report_lookup_exact_only_no_substring_fallback(self):
        """AUD-18: with only scan_20990101_000001.json present, GET /report/2 returns 404."""
        report_data = {
            "target": "http://localhost:3000",
            "timestamp": "2099-01-01 00:00:01",
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [{"id": "F01", "title": "SQL Injection", "severity": "high"}]
        }
        file_path = self.reports_dir / "scan_20990101_000001.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f)
        self.created_files.append(str(file_path))

        # Exact ID works
        resp_exact = self.client.get("/report/20990101_000001")
        self.assertEqual(resp_exact.status_code, 200)

        # Substring '2' must NOT match scan_20990101_000001.json and must return 404
        resp_substring = self.client.get("/report/2")
        self.assertEqual(resp_substring.status_code, 404, "GET /report/2 must return 404, not substring match")

    def test_aud18_dev_ticket_returns_404_for_unknown_finding(self):
        """AUD-18: GET /api/report/<id>/dev-ticket/NOPE returns 404."""
        report_data = {
            "target": "http://localhost:3000",
            "timestamp": "2099-01-01 00:00:01",
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [
                {
                    "id": "SEC-001",
                    "title": "SQL Injection in /api/search",
                    "severity": "critical",
                    "tool": "sqli_scanner",
                    "owasp": "A03:2021-Injection"
                }
            ]
        }
        file_path = self.reports_dir / "scan_20990101_000001.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f)
        self.created_files.append(str(file_path))

        # Known finding returns 200 markdown
        resp_known = self.client.get("/api/report/20990101_000001/dev-ticket/SEC-001")
        self.assertEqual(resp_known.status_code, 200)
        self.assertIn("text/markdown", resp_known.headers.get("Content-Type", ""))

        # Unknown finding must return 404, NOT fallback to findings[0]
        resp_unknown = self.client.get("/api/report/20990101_000001/dev-ticket/NOPE")
        self.assertEqual(resp_unknown.status_code, 404, "Unknown finding ID must return 404")


if __name__ == "__main__":
    unittest.main()
