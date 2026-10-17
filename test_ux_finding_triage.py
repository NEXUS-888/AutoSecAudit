import os
import json
import unittest
from pathlib import Path

from ui.app import app
import core.auth as auth
import config


class TestUXFindingTriage(unittest.TestCase):
    """Acceptance tests for AUD-79: Mark a finding as false positive or accepted risk."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        auth.init_user_db()
        user = auth.get_user_by_username("triage_owner")
        if not user:
            ok, msg, u = auth.create_user("triage_owner", "owner@example.com", "Password123!", role="developer")
            cls.owner_id = u["id"]
        else:
            cls.owner_id = user["id"]

        other = auth.get_user_by_username("triage_other")
        if not other:
            ok, msg, u = auth.create_user("triage_other", "other@example.com", "Password123!", role="developer")
            cls.other_id = u["id"]
        else:
            cls.other_id = other["id"]

        admin = auth.get_user_by_username("triage_admin")
        if not admin:
            ok, msg, u = auth.create_user("triage_admin", "admin@example.com", "Password123!", role="admin")
            cls.admin_id = u["id"]
        else:
            cls.admin_id = admin["id"]

    def setUp(self):
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        auth.login_test_client(self.client, self.owner_id)

        self.reports_dir = Path(config.REPORTS_DIR)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.report_id = "test_triage_sample"
        self.scan_file = self.reports_dir / f"scan_{self.report_id}.json"
        self.triage_dir = self.reports_dir / "triage"
        self.triage_dir.mkdir(parents=True, exist_ok=True)
        self.triage_file = self.triage_dir / f"{self.report_id}.json"

        # Create sample scan report
        self.sample_report = {
            "id": self.report_id,
            "target": "http://127.0.0.1:8080",
            "owner": self.owner_id,
            "scan_mode": "demo",
            "timestamp": "2026-10-17T08:00:00Z",
            "all_findings": [
                {
                    "id": "FINDING-001",
                    "title": "SQL Injection in User Login",
                    "severity": "HIGH",
                    "confidence": "high",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "endpoint": "/api/login",
                    "tool_name": "SQLiScanner",
                    "fingerprint": "fp_sql_001"
                },
                {
                    "id": "FINDING-002",
                    "title": "Reflected Cross-Site Scripting",
                    "severity": "MEDIUM",
                    "confidence": "medium",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "endpoint": "/search",
                    "tool_name": "XSSScanner",
                    "fingerprint": "fp_xss_002"
                }
            ],
            "findings": [
                {
                    "id": "FINDING-001",
                    "title": "SQL Injection in User Login",
                    "severity": "HIGH",
                    "confidence": "high"
                },
                {
                    "id": "FINDING-002",
                    "title": "Reflected Cross-Site Scripting",
                    "severity": "MEDIUM",
                    "confidence": "medium"
                }
            ]
        }
        with open(self.scan_file, "w", encoding="utf-8") as f:
            json.dump(self.sample_report, f, indent=2)

    def tearDown(self):
        if self.scan_file.exists():
            self.scan_file.unlink()
        if self.triage_file.exists():
            self.triage_file.unlink()

    def test_default_state_is_open(self):
        """A report without triage records reports 'open' for each finding."""
        resp = self.client.get(f"/report/{self.report_id}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertEqual(html.count('data-testid="finding-triage"'), 2)
        self.assertEqual(html.count('data-triage-state="open"'), 2)
        self.assertIn('data-finding-id="FINDING-001"', html)
        self.assertIn('data-finding-id="FINDING-002"', html)

    def test_setting_and_clearing_state(self):
        """Set finding triage to false_positive and accepted_risk, then clear back to open."""
        # Set to false_positive
        resp = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": "Verified testing artifact"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("state"), "false_positive")
        self.assertTrue(self.triage_file.exists(), "Sidecar triage JSON file must exist")

        # Set to accepted_risk
        resp = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "accepted_risk", "note": "Business risk accepted by secops"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json().get("state"), "accepted_risk")

        # Clear state (reset to open)
        resp = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "open", "note": ""}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json().get("state"), "open")

        # Assert sidecar contents after clearing to open
        with open(self.triage_file, "r", encoding="utf-8") as f:
            sidecar_data = json.load(f)
        self.assertIn("FINDING-001", sidecar_data)
        self.assertEqual(sidecar_data["FINDING-001"]["state"], "open")
        self.assertEqual(sidecar_data["FINDING-001"]["note"], "")

    def test_persistence_across_fresh_app_and_test_client(self):
        """Triage state persists in sidecar JSON and reloads across fresh test clients."""
        resp = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-002", "state": "false_positive", "note": "Sanitized upstream"}
        )
        self.assertEqual(resp.status_code, 200)

        # Fresh client without shared state
        fresh_client = app.test_client()
        auth.login_test_client(fresh_client, self.owner_id)
        resp2 = fresh_client.get(f"/report/{self.report_id}")
        self.assertEqual(resp2.status_code, 200)
        html = resp2.get_data(as_text=True)

        card2_start = html.find('data-finding-id="FINDING-002"')
        self.assertNotEqual(card2_start, -1)
        card2_chunk = html[max(0, card2_start - 350):card2_start + 350]
        self.assertIn('data-triage-state="false_positive"', card2_chunk)
        self.assertIn("Sanitized upstream", html)

        card1_start = html.find('data-finding-id="FINDING-001"')
        self.assertNotEqual(card1_start, -1)
        card1_chunk = html[max(0, card1_start - 350):card1_start + 350]
        self.assertIn('data-triage-state="open"', card1_chunk)

    def test_user_who_does_not_own_report_gets_404_or_403(self):
        """A user who does not own the report cannot mutate triage state; admin can."""
        other_client = app.test_client()
        auth.login_test_client(other_client, self.other_id)

        resp = other_client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": "Hacked"}
        )
        self.assertIn(resp.status_code, (403, 404))

        # Admin can triage
        admin_client = app.test_client()
        auth.login_test_client(admin_client, self.admin_id)
        resp_admin = admin_client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": "Admin reviewed"}
        )
        self.assertEqual(resp_admin.status_code, 200)

    def test_missing_csrf_token_rejected(self):
        """With WTF_CSRF_ENABLED=True, POST without CSRF token returns 400."""
        app.config["WTF_CSRF_ENABLED"] = True
        try:
            resp = self.client.post(
                f"/report/{self.report_id}/triage",
                json={"finding_id": "FINDING-001", "state": "false_positive"}
            )
            self.assertEqual(resp.status_code, 400)
        finally:
            app.config["WTF_CSRF_ENABLED"] = False

    def test_invalid_state_unknown_id_and_501_char_note_rejected_with_400(self):
        """Validation failures return 400."""
        # Non-dict body (e.g. list [1]) returns 400
        resp_list = self.client.post(
            f"/report/{self.report_id}/triage",
            json=[1]
        )
        self.assertEqual(resp_list.status_code, 400)

        # Non-string finding_id returns 400
        resp_non_str1 = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": ["x"], "state": "open"}
        )
        self.assertEqual(resp_non_str1.status_code, 400)

        resp_non_str2 = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": {"x": 1}, "state": "open"}
        )
        self.assertEqual(resp_non_str2.status_code, 400)

        # Invalid state
        resp1 = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "not_a_valid_state"}
        )
        self.assertEqual(resp1.status_code, 400)

        # Unknown finding id
        resp2 = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "NON-EXISTENT-999", "state": "false_positive"}
        )
        self.assertEqual(resp2.status_code, 400)

        # Note > 500 characters
        long_note = "A" * 501
        resp3 = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": long_note}
        )
        self.assertEqual(resp3.status_code, 400)

        # Exactly 500 characters succeeds
        valid_note = "A" * 500
        resp4 = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": valid_note}
        )
        self.assertEqual(resp4.status_code, 200)

    def test_sidecar_does_not_collide_with_report_globs_or_resolver(self):
        """Sidecar is stored in REPORTS_DIR/triage/<clean_id>.json and does not appear in history or resolver."""
        resp = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": "Confidential note"}
        )
        self.assertEqual(resp.status_code, 200)

        # /history shows no extra entry
        resp_hist = self.client.get("/history")
        self.assertEqual(resp_hist.status_code, 200)
        hist_html = resp_hist.get_data(as_text=True)
        self.assertNotIn("scan_test_triage_sample.triage", hist_html)
        self.assertNotIn(".triage", hist_html)

        # GET /report/scan_<id>.triage returns 404
        resp_leak = self.client.get(f"/report/scan_{self.report_id}.triage")
        self.assertEqual(resp_leak.status_code, 404)

    def test_scan_json_byte_identical_before_and_after(self):
        """The original scan report JSON is never modified by triage actions."""
        with open(self.scan_file, "rb") as f:
            bytes_before = f.read()

        resp = self.client.post(
            f"/report/{self.report_id}/triage",
            json={"finding_id": "FINDING-001", "state": "false_positive", "note": "Safe"}
        )
        self.assertEqual(resp.status_code, 200)

        with open(self.scan_file, "rb") as f:
            bytes_after = f.read()

        self.assertEqual(bytes_before, bytes_after, "Scan JSON file must be byte-identical before and after triage")

    def test_report_html_contains_finding_triage_control(self):
        """The report template renders data-testid='finding-triage' for each finding and summary counts."""
        resp = self.client.get(f"/report/{self.report_id}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('data-testid="finding-triage"', html)
        self.assertIn('data-testid="hide-triaged-toggle"', html)


if __name__ == "__main__":
    unittest.main()
