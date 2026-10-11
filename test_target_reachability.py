"""Unit and integration tests for target liveness and pre-flight reachability checks."""
import unittest
from unittest.mock import patch, MagicMock
from core.utils import check_target_reachable, validate_target
from core.engine import Engine
from main import run_scan
from ui.app import app


class TestTargetReachability(unittest.TestCase):
    """Test suite for target liveness / reachability validation."""

    def setUp(self):
        app.config["WTF_CSRF_ENABLED"] = False
        import core.auth as auth
        self.admin = auth.get_user_by_username("admin")
        if not self.admin:
            auth.init_user_db()
            self.admin = auth.get_user_by_username("admin")

    def tearDown(self):
        app.config["WTF_CSRF_ENABLED"] = True

    def _auth_client(self, client):
        with client.session_transaction() as sess:
            sess["user_id"] = self.admin["id"]
        return client

    def test_offline_port_detected_as_unreachable(self):
        """Verify that an offline local port is detected as unreachable."""
        reachable, msg = check_target_reachable("http://127.0.0.1:59123", timeout=1.0)
        self.assertFalse(reachable)
        self.assertIn("Connection refused", msg)

    def test_reachable_success_with_mocked_http(self):
        """Verify that a successful HTTP response marks the target as reachable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason = "OK"

        with patch("requests.head", return_value=mock_resp):
            reachable, msg = check_target_reachable("http://127.0.0.1:8000")
            self.assertTrue(reachable)
            self.assertIn("HTTP 200", msg)

    def test_ssl_error_still_counts_as_listening(self):
        """Verify that an SSL certificate error still identifies a listening service."""
        import requests
        with patch("requests.head", side_effect=requests.exceptions.SSLError("Self-signed cert")):
            reachable, msg = check_target_reachable("https://127.0.0.1:8443")
            self.assertTrue(reachable)
            self.assertIn("SSL certificate observed", msg)

    def test_cli_run_scan_aborts_on_offline_target(self):
        """Verify that run_scan halts immediately with exit code 1 if target is unreachable."""
        with patch("main.check_target_reachable", return_value=(False, "Connection refused")):
            exit_code = run_scan("http://localhost:3000", fail_on=None)
            self.assertEqual(exit_code, 1)

    def test_cli_run_scan_allows_skip_reachability(self):
        """Verify that run_scan bypasses the reachability check if skip_reachability=True."""
        with patch("main.check_target_reachable") as mock_check, \
             patch("main.Engine") as mock_engine_cls:
            mock_eng = MagicMock()
            mock_eng.load_plugins.return_value = 5
            mock_eng.set_target.return_value = True
            mock_rep = MagicMock()
            mock_rep.summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            mock_rep.all_findings = []
            mock_rep.delta = None
            mock_rep.target = "localhost"
            mock_rep.to_dict.return_value = {"summary": mock_rep.summary, "all_findings": []}
            mock_eng.generate_report.return_value = mock_rep
            mock_eng._generate_summary.return_value = mock_rep.summary
            mock_engine_cls.return_value = mock_eng

            exit_code = run_scan("http://localhost:3000", skip_reachability=True, mock_mode=True)
            self.assertEqual(exit_code, 0)
            mock_check.assert_not_called()

    def test_ui_async_scan_blocks_offline_target(self):
        """Verify that the Web UI /scan/async endpoint rejects offline targets with HTTP 400."""
        with patch("ui.app.check_target_reachable", return_value=(False, "Connection refused on localhost:3000. No active service")):
            with app.test_client() as client:
                self._auth_client(client)
                response = client.post("/scan/async", data={"target": "http://localhost:3000"})
                self.assertEqual(response.status_code, 400)
                data = response.get_json()
                self.assertIn("Target is offline or unreachable", data["error"])

    def test_ui_async_scan_allows_demo_skip_reachability(self):
        """Verify that the Web UI /scan/async endpoint permits offline demo when requested."""
        with patch("ui.app.check_target_reachable") as mock_check:
            with app.test_client() as client:
                self._auth_client(client)
                response = client.post("/scan/async", data={
                    "target": "http://localhost:3000",
                    "skip_reachability": "true"
                })
                self.assertEqual(response.status_code, 200)
                data = response.get_json()
                self.assertIn("scan_id", data)
                mock_check.assert_not_called()

    def test_cli_run_scan_demo_mode_bypasses_reachability(self):
        """Verify that run_scan in demo mode completely bypasses reachability check even on offline target."""
        with patch("main.check_target_reachable") as mock_check, \
             patch("main.Engine") as mock_engine_cls:
            mock_eng = MagicMock()
            mock_eng.load_plugins.return_value = 5
            mock_eng.set_target.return_value = True
            mock_rep = MagicMock()
            mock_rep.summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            mock_rep.all_findings = []
            mock_rep.delta = None
            mock_rep.target = "localhost"
            mock_rep.to_dict.return_value = {"summary": mock_rep.summary, "all_findings": []}
            mock_eng.generate_report.return_value = mock_rep
            mock_eng._generate_summary.return_value = mock_rep.summary
            mock_engine_cls.return_value = mock_eng

            exit_code = run_scan("http://localhost:3000", mock_mode=True)
            self.assertEqual(exit_code, 0)
            mock_check.assert_not_called()

    def test_ui_async_scan_demo_mode_bypasses_reachability(self):
        """Verify that the Web UI /scan/async endpoint with mode='demo' bypasses reachability check."""
        with patch("ui.app.check_target_reachable") as mock_check:
            with app.test_client() as client:
                self._auth_client(client)
                response = client.post("/scan/async", data={
                    "target": "http://localhost:3000",
                    "mode": "demo"
                })
                self.assertEqual(response.status_code, 200)
                data = response.get_json()
                self.assertIn("scan_id", data)
                self.assertEqual(data.get("mode"), "demo")
                mock_check.assert_not_called()

    def test_ui_async_scan_real_mode_blocks_offline_target(self):
        """Verify that the Web UI /scan/async endpoint with mode='real' enforces reachability and blocks offline targets."""
        with patch("ui.app.check_target_reachable", return_value=(False, "Connection refused on localhost:3000")):
            with app.test_client() as client:
                self._auth_client(client)
                response = client.post("/scan/async", data={
                    "target": "http://localhost:3000",
                    "mode": "real"
                })
                self.assertEqual(response.status_code, 400)
                data = response.get_json()
                self.assertIn("Target is offline or unreachable", data["error"])
                self.assertIn("Real Active Scan requires the target server to be running", data["error"])
                self.assertIn("Real Active Scan requires the target server to be running", data["error"])

    def test_engine_set_target_refuses_offline_in_real_mode(self):
        """Verify that Engine.set_target in real mode refuses offline targets."""
        engine = Engine(mock_mode=False)
        with patch("core.engine.check_target_reachable", return_value=(False, "Connection refused")):
            success = engine.set_target("http://localhost:9999", check_reachable=True)
            self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
