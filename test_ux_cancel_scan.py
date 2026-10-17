import os
import time
import unittest
import threading
from pathlib import Path
from unittest.mock import patch

from ui.app import app, scan_jobs, scan_jobs_lock, _scan_executor
import core.auth as auth
from core.engine import Engine
from core.pipeline import ScanCancelledError
import config


class SlowMockEngine(Engine):
    """Engine mock that simulates a long plugin scan and checks cancel_check."""
    def run_plugins(self):
        for _ in range(50):
            if hasattr(self, "cancel_check") and self.cancel_check and self.cancel_check():
                raise ScanCancelledError("Scan cancelled during plugins")
            time.sleep(0.05)
        return []


class TestUXCancelScan(unittest.TestCase):
    """Acceptance tests for AUD-81: Cancel a running scan."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        auth.init_user_db()
        user = auth.get_user_by_username("cancel_user_1")
        if not user:
            ok, msg, u = auth.create_user("cancel_user_1", "cancel_user1@example.com", "Password123!", role="developer")
            cls.user1_id = u["id"] if u else auth.get_user_by_username("cancel_user_1")["id"]
        else:
            cls.user1_id = user["id"]

        other = auth.get_user_by_username("cancel_user_2")
        if not other:
            ok, msg, u = auth.create_user("cancel_user_2", "cancel_user2@example.com", "Password123!", role="developer")
            cls.user2_id = u["id"] if u else auth.get_user_by_username("cancel_user_2")["id"]
        else:
            cls.user2_id = other["id"]

        admin = auth.get_user_by_username("cancel_admin")
        if not admin:
            ok, msg, u = auth.create_user("cancel_admin", "cancel_admin@example.com", "Password123!", role="admin")
            cls.admin_id = u["id"] if u else auth.get_user_by_username("cancel_admin")["id"]
        else:
            cls.admin_id = admin["id"]

    def setUp(self):
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        auth.login_test_client(self.client, self.user1_id)

    def test_cancel_running_scan_ends_it_as_cancelled_within_few_seconds(self):
        """Cancelling a running scan terminates it with status 'cancelled'."""
        reports_before = set(os.listdir(config.REPORTS_DIR))
        resp_h1 = self.client.get("/history")
        hist_before = resp_h1.get_data(as_text=True)

        with patch("core.pipeline.Engine", SlowMockEngine):
            # Start real scan via POST /scan/async
            resp_scan = self.client.post("/scan/async", data={"target": "http://127.0.0.1:8080", "mode": "demo"})
            self.assertEqual(resp_scan.status_code, 200)
            scan_id = resp_scan.get_json().get("scan_id")
            self.assertTrue(scan_id)

            # Let thread start and enter engine loop
            time.sleep(0.15)

            # POST /scan/cancel/<id>
            resp_cancel = self.client.post(f"/scan/cancel/{scan_id}")
            self.assertEqual(resp_cancel.status_code, 200)
            self.assertEqual(resp_cancel.get_json().get("status"), "cancelled")

            # Poll for completion within about 5 seconds
            deadline = time.time() + 5.0
            final_status = None
            job = None
            while time.time() < deadline:
                with scan_jobs_lock:
                    job = scan_jobs.get(scan_id)
                    if job:
                        final_status = job.get("status")
                        t = job.get("thread")
                        if final_status == "cancelled" and (t is None or not t.is_alive()):
                            break
                time.sleep(0.1)

            # 1. Final status is cancelled (not error or done)
            self.assertEqual(final_status, "cancelled")

            # Ensure thread exits
            if job and job.get("thread"):
                job["thread"].join(timeout=2.0)

            # 2. No new file appears in REPORTS_DIR
            reports_after = set(os.listdir(config.REPORTS_DIR))
            self.assertEqual(reports_after - reports_before, set(), "No new report files may appear in REPORTS_DIR")

            # 3. /history is unchanged
            resp_h2 = self.client.get("/history")
            hist_after = resp_h2.get_data(as_text=True)
            self.assertNotIn(scan_id, hist_after)

            # 4. _scan_executor.can_accept() is True after thread exits
            self.assertTrue(_scan_executor.can_accept(), "Concurrency slot must be freed")

            # 5. A second POST /scan/async succeeds right after
            resp_second = self.client.post("/scan/async", data={"target": "http://127.0.0.1:8080", "mode": "demo"})
            self.assertEqual(resp_second.status_code, 200)
            second_scan_id = resp_second.get_json().get("scan_id")
            self.assertTrue(second_scan_id)
            self.client.post(f"/scan/cancel/{second_scan_id}")

    def test_cancelled_scan_has_no_report_in_history(self):
        """A cancelled scan does not write a report into history."""
        scan_id = "test_cancel_no_report_456"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "scan_id": scan_id,
                "status": "cancelled",
                "target": "http://127.0.0.1:8080",
                "owner": self.user1_id,
                "report_name": None,
                "error": None,
                "subscribers": [],
                "created_at": time.time()
            }

        try:
            resp = self.client.get("/history")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertNotIn(scan_id, html)
        finally:
            with scan_jobs_lock:
                scan_jobs.pop(scan_id, None)

    def test_other_user_cannot_cancel_scan(self):
        """Another non-admin user gets 404 (no leak). Admin can cancel."""
        scan_id = "test_cancel_other_user_789"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "scan_id": scan_id,
                "status": "running",
                "target": "http://127.0.0.1:8080",
                "owner": self.user1_id,
                "report_name": None,
                "error": None,
                "subscribers": [],
                "created_at": time.time()
            }

        try:
            other_client = app.test_client()
            auth.login_test_client(other_client, self.user2_id)
            resp = other_client.post(f"/scan/cancel/{scan_id}")
            self.assertEqual(resp.status_code, 404)

            # Admin can cancel
            admin_client = app.test_client()
            auth.login_test_client(admin_client, self.admin_id)
            resp_admin = admin_client.post(f"/scan/cancel/{scan_id}")
            self.assertEqual(resp_admin.status_code, 200)
        finally:
            with scan_jobs_lock:
                scan_jobs.pop(scan_id, None)

    def test_unknown_id_returns_404(self):
        """Cancelling an unknown scan id returns 404."""
        resp = self.client.post("/scan/cancel/nonexistent_scan_id_99999")
        self.assertEqual(resp.status_code, 404)

    def test_cancelling_twice_is_harmless(self):
        """Cancelling twice returns a valid response (200 or 409), never a 500."""
        scan_id = "test_cancel_twice_111"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "scan_id": scan_id,
                "status": "running",
                "target": "http://127.0.0.1:8080",
                "owner": self.user1_id,
                "report_name": None,
                "error": None,
                "subscribers": [],
                "created_at": time.time()
            }

        try:
            resp1 = self.client.post(f"/scan/cancel/{scan_id}")
            self.assertEqual(resp1.status_code, 200)

            resp2 = self.client.post(f"/scan/cancel/{scan_id}")
            self.assertIn(resp2.status_code, (200, 409))
        finally:
            with scan_jobs_lock:
                scan_jobs.pop(scan_id, None)

    def test_cancel_during_report_generation_discards_files_and_omits_webhook(self):
        """AUD-81: When a scan is cancelled during report generation (after JSON is written),
        the final status is 'cancelled', REPORTS_DIR has no new files, scan is absent from /history,
        and webhook is not called."""
        reports_before = set(os.listdir(config.REPORTS_DIR))
        from reports.generator import ReportGenerator

        class CancellingGenerator(ReportGenerator):
            def generate_report(self, report):
                # JSON has already been written by engine.save_report!
                # Mark scan job cancelled:
                with scan_jobs_lock:
                    for s_id, j in scan_jobs.items():
                        if j.get("target") == getattr(report, "target", None):
                            j["status"] = "cancelled"
                return super().generate_report(report)

            def generate_html(self, report, output_path=None):
                with scan_jobs_lock:
                    for s_id, j in scan_jobs.items():
                        if j.get("target") == getattr(report, "target", None):
                            j["status"] = "cancelled"
                return super().generate_html(report, output_path=output_path)

        with patch("reports.generator.ReportGenerator", CancellingGenerator), \
             patch("core.pipeline.ReportGenerator", CancellingGenerator), \
             patch("core.notifications.WebhookNotifier") as mock_notifier_cls:
            mock_notifier = mock_notifier_cls.return_value

            resp_scan = self.client.post("/scan/async", data={
                "target": "http://127.0.0.1:8080",
                "mode": "demo",
                "webhook": "https://example.com/webhook",
            })
            self.assertEqual(resp_scan.status_code, 200)
            scan_id = resp_scan.get_json().get("scan_id")
            self.assertTrue(scan_id)

            # Wait for background scan thread to finish
            deadline = time.time() + 5.0
            final_status = None
            job = None
            while time.time() < deadline:
                with scan_jobs_lock:
                    job = scan_jobs.get(scan_id)
                    if job:
                        final_status = job.get("status")
                        t = job.get("thread")
                        if final_status == "cancelled" and (t is None or not t.is_alive()):
                            break
                time.sleep(0.05)

            if job and job.get("thread"):
                job["thread"].join(timeout=2.0)

            # 1. Final status is cancelled
            self.assertEqual(final_status, "cancelled")

            # 2. os.listdir(REPORTS_DIR) shows no new files
            reports_after = set(os.listdir(config.REPORTS_DIR))
            self.assertEqual(reports_after - reports_before, set(), "No new report files may remain in REPORTS_DIR")

            # 3. The scan is absent from /history
            resp_hist = self.client.get("/history")
            self.assertEqual(resp_hist.status_code, 200)
            self.assertNotIn(scan_id, resp_hist.get_data(as_text=True))

            # 4. Webhook is not called
            mock_notifier_cls.assert_not_called()
            mock_notifier.send_notification.assert_not_called()

    def test_missing_csrf_token_rejected(self):
        """With WTF_CSRF_ENABLED=True, POST /scan/cancel without token returns 400."""
        app.config["WTF_CSRF_ENABLED"] = True
        try:
            resp = self.client.post("/scan/cancel/any_scan_id")
            self.assertEqual(resp.status_code, 400)
        finally:
            app.config["WTF_CSRF_ENABLED"] = False


if __name__ == "__main__":
    unittest.main()
