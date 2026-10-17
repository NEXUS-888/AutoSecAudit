import os
import json
import unittest
from pathlib import Path

from ui.app import app
import core.auth as auth
import config


class TestUXCompareScans(unittest.TestCase):
    """Acceptance tests for AUD-80: Compare two scans from the history page."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        auth.init_user_db()
        user = auth.get_user_by_username("compare_user_1")
        if not user:
            ok, msg, u = auth.create_user("compare_user_1", "user1@example.com", "Password123!", role="developer")
            cls.user1_id = u["id"]
        else:
            cls.user1_id = user["id"]

        other = auth.get_user_by_username("compare_user_2")
        if not other:
            ok, msg, u = auth.create_user("compare_user_2", "user2@example.com", "Password123!", role="developer")
            cls.user2_id = u["id"]
        else:
            cls.user2_id = other["id"]

    def setUp(self):
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        auth.login_test_client(self.client, self.user1_id)

        self.reports_dir = Path(config.REPORTS_DIR)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.id_old = "scan_compare_old"
        self.id_new = "scan_compare_new"
        self.id_diff_target = "scan_compare_difftarget"
        self.id_other_user = "scan_compare_otheruser"

        self.file_old = self.reports_dir / f"scan_{self.id_old}.json"
        self.file_new = self.reports_dir / f"scan_{self.id_new}.json"
        self.file_diff_target = self.reports_dir / f"scan_{self.id_diff_target}.json"
        self.file_other_user = self.reports_dir / f"scan_{self.id_other_user}.json"

        # Scan Old: has Finding A (to be fixed) and Finding B (unchanged)
        report_old = {
            "id": self.id_old,
            "target": "http://127.0.0.1:8080",
            "owner": self.user1_id,
            "scan_mode": "demo",
            "timestamp": "2026-10-10T10:00:00Z",
            "all_findings": [
                {
                    "id": "FINDING-A",
                    "title": "SQL Injection in Search",
                    "severity": "HIGH",
                    "endpoint": "/search",
                    "tool_name": "SQLiScanner",
                    "fingerprint": "fp_sqli_search"
                },
                {
                    "id": "FINDING-B",
                    "title": "Missing Strict-Transport-Security",
                    "severity": "LOW",
                    "endpoint": "/",
                    "tool_name": "HeaderScanner",
                    "fingerprint": "fp_hsts_root"
                }
            ],
            "findings": []
        }

        # Scan New: has Finding B (unchanged) and Finding C (new)
        report_new = {
            "id": self.id_new,
            "target": "http://127.0.0.1:8080",
            "owner": self.user1_id,
            "scan_mode": "demo",
            "timestamp": "2026-10-15T12:00:00Z",
            "all_findings": [
                {
                    "id": "FINDING-B",
                    "title": "Missing Strict-Transport-Security",
                    "severity": "LOW",
                    "endpoint": "/",
                    "tool_name": "HeaderScanner",
                    "fingerprint": "fp_hsts_root"
                },
                {
                    "id": "FINDING-C",
                    "title": "Open Redirect on Login",
                    "severity": "MEDIUM",
                    "endpoint": "/login",
                    "tool_name": "RedirectScanner",
                    "fingerprint": "fp_redirect_login"
                }
            ],
            "findings": []
        }

        # Scan Different Target: target is different domain
        report_diff = {
            "id": self.id_diff_target,
            "target": "http://other-service.local:9000",
            "owner": self.user1_id,
            "scan_mode": "demo",
            "timestamp": "2026-10-16T14:00:00Z",
            "all_findings": [],
            "findings": []
        }

        # Scan Other User
        report_other = {
            "id": self.id_other_user,
            "target": "http://127.0.0.1:8080",
            "owner": self.user2_id,
            "scan_mode": "demo",
            "timestamp": "2026-10-16T15:00:00Z",
            "all_findings": [],
            "findings": []
        }

        for path, rep in [(self.file_old, report_old), (self.file_new, report_new),
                          (self.file_diff_target, report_diff), (self.file_other_user, report_other)]:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=2)

    def tearDown(self):
        for path in [self.file_old, self.file_new, self.file_diff_target, self.file_other_user]:
            if path.exists():
                path.unlink()

    def test_two_owned_scans_returns_200_with_sections_and_counts(self):
        """Comparing two owned scans gives 200 with New, Fixed and Unchanged sections and exact counts."""
        resp = self.client.get(f"/compare/{self.id_old}/{self.id_new}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn("New", html)
        self.assertIn("Fixed", html)
        self.assertIn("Unchanged", html)
        self.assertIn("http://127.0.0.1:8080", html)
        self.assertIn("2026-10-10", html)
        self.assertIn("2026-10-15", html)

        # Assert summary counts: New=1, Fixed=1, Unchanged=1
        self.assertIn('<div class="summary-num num-new">1</div>', html)
        self.assertIn('<div class="summary-num num-fixed">1</div>', html)
        self.assertIn('<div class="summary-num num-unchanged">1</div>', html)

        # Slice HTML between section headings
        new_start = html.rfind("New Findings")
        fixed_start = html.rfind("Fixed Findings")
        unchanged_start = html.rfind("Unchanged Findings")
        self.assertTrue(0 < new_start < fixed_start < unchanged_start)

        new_section = html[new_start:fixed_start]
        fixed_section = html[fixed_start:unchanged_start]
        unchanged_section = html[unchanged_start:]

        # Exactly expected title in each section:
        # Open Redirect in New, SQLi in Fixed, HSTS in Unchanged
        self.assertIn("Open Redirect on Login", new_section)
        self.assertNotIn("SQL Injection in Search", new_section)
        self.assertNotIn("Missing Strict-Transport-Security", new_section)

        self.assertIn("SQL Injection in Search", fixed_section)
        self.assertNotIn("Open Redirect on Login", fixed_section)
        self.assertNotIn("Missing Strict-Transport-Security", fixed_section)

        self.assertIn("Missing Strict-Transport-Security", unchanged_section)
        self.assertNotIn("Open Redirect on Login", unchanged_section)
        self.assertNotIn("SQL Injection in Search", unchanged_section)

    def test_swapping_order_swaps_new_and_fixed(self):
        """Swapping older and newer swaps the New and Fixed counts and classifications."""
        resp2 = self.client.get(f"/compare/{self.id_new}/{self.id_old}")
        self.assertEqual(resp2.status_code, 200)
        html2 = resp2.get_data(as_text=True)

        # Assert summary counts: New=1, Fixed=1, Unchanged=1
        self.assertIn('<div class="summary-num num-new">1</div>', html2)
        self.assertIn('<div class="summary-num num-fixed">1</div>', html2)
        self.assertIn('<div class="summary-num num-unchanged">1</div>', html2)

        # Slice HTML between section headings
        new_start = html2.rfind("New Findings")
        fixed_start = html2.rfind("Fixed Findings")
        unchanged_start = html2.rfind("Unchanged Findings")
        self.assertTrue(0 < new_start < fixed_start < unchanged_start)

        new_section = html2[new_start:fixed_start]
        fixed_section = html2[fixed_start:unchanged_start]
        unchanged_section = html2[unchanged_start:]

        # Now SQLi is in New and Open Redirect is in Fixed
        self.assertIn("SQL Injection in Search", new_section)
        self.assertNotIn("Open Redirect on Login", new_section)

        self.assertIn("Open Redirect on Login", fixed_section)
        self.assertNotIn("SQL Injection in Search", fixed_section)

        self.assertIn("Missing Strict-Transport-Security", unchanged_section)

    def test_other_user_report_returns_404(self):
        """Comparing with another user's scan returns 404 (no information leak)."""
        resp = self.client.get(f"/compare/{self.id_old}/{self.id_other_user}")
        self.assertEqual(resp.status_code, 404)

        resp2 = self.client.get(f"/compare/{self.id_other_user}/{self.id_new}")
        self.assertEqual(resp2.status_code, 404)

    def test_unknown_and_malformed_ids_return_404(self):
        """Unknown or invalid scan identifiers return 404."""
        resp1 = self.client.get(f"/compare/unknown_scan_id/{self.id_new}")
        self.assertEqual(resp1.status_code, 404)

        resp2 = self.client.get(f"/compare/{self.id_old}/unknown_scan_id")
        self.assertEqual(resp2.status_code, 404)

        resp3 = self.client.get(f"/compare/../etc/passwd/{self.id_new}")
        self.assertEqual(resp3.status_code, 404)

        # Exercising regex validation directly with invalid characters
        resp4 = self.client.get(f"/compare/bad$id/{self.id_new}")
        self.assertEqual(resp4.status_code, 404)

        resp5 = self.client.get(f"/compare/{self.id_old}/bad$id")
        self.assertEqual(resp5.status_code, 404)

    def test_different_targets_shows_warning(self):
        """Comparing scans across different targets displays a clear warning banner."""
        resp = self.client.get(f"/compare/{self.id_old}/{self.id_diff_target}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertTrue(
            "different targets" in html.lower() or "target mismatch" in html.lower(),
            "Comparison must warn when scans have different target URLs"
        )

    def test_history_page_contains_compare_scans_control(self):
        """The history page contains the 'compare-scans' control."""
        resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('data-testid="compare-scans"', html)


if __name__ == "__main__":
    unittest.main()
