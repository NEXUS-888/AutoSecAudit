import ast
import json
import os
import pathlib
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import config
import core.auth as auth
from core.pipeline import ScanRequest, run_scan_pipeline
from testbed.app import app as testbed_app
from ui.app import app, scan_jobs, scan_jobs_lock


class TestAud65ReportAndScanOwnership(unittest.TestCase):
    """AUD-65: Per-user ownership enforcement for reports, downloads, history, and scan jobs."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp_dir.name)
        self.reports_dir = self.data_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.env_patch = patch.dict(
            os.environ,
            {
                "AUTOSEC_DATA_DIR": str(self.data_dir),
                "AUTOSEC_ADMIN_PASSWORD": "AdminPassword!234",
            },
        )
        self.env_patch.start()

        self.db_patch = patch.object(auth, "DB_PATH", self.data_dir / "users.db")
        self.db_patch.start()
        auth._initialized_dbs.clear()
        auth.init_user_db()

        self.admin = auth.get_user_by_username("admin")
        ok_a, _, self.user_a = auth.create_user("user_a", "a@example.local", "PassA123!", role="developer")
        ok_b, _, self.user_b = auth.create_user("user_b", "b@example.local", "PassB123!", role="developer")
        self.assertTrue(ok_a)
        self.assertTrue(ok_b)

        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

        with scan_jobs_lock:
            scan_jobs.clear()

        # Create User A's report
        self.rep_a_id = "20261013_100001_aaaaaa"
        self.rep_a_path = self.reports_dir / f"scan_{self.rep_a_id}.json"
        self.rep_a_data = {
            "report_id": self.rep_a_id,
            "owner": self.user_a["id"],
            "target": "http://127.0.0.1:8001",
            "timestamp": "2026-10-13 10:00:01",
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "all_findings": [
                {
                    "id": "F-1",
                    "title": "SQL Injection",
                    "severity": "High",
                    "host": "http://127.0.0.1:8001",
                    "port": 8001,
                    "description": "SQLi in id",
                    "raw_output": "err",
                    "tool_name": "sqli_scanner",
                    "owasp_tag": "A03:2021-Injection",
                }
            ],
            "scan_results": [],
        }
        self.rep_a_path.write_text(json.dumps(self.rep_a_data), encoding="utf-8")

        # Create legacy owner-less report
        self.rep_legacy_id = "20261013_100002_legacy"
        self.rep_legacy_path = self.reports_dir / f"scan_{self.rep_legacy_id}.json"
        self.rep_legacy_data = {
            "report_id": self.rep_legacy_id,
            "target": "http://127.0.0.1:8002",
            "timestamp": "2026-10-13 10:00:02",
            "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            "all_findings": [
                {
                    "id": "F-2",
                    "title": "RCE",
                    "severity": "Critical",
                    "host": "http://127.0.0.1:8002",
                    "port": 8002,
                    "description": "RCE",
                    "raw_output": "uid=0",
                    "tool_name": "command_injection_scanner",
                }
            ],
            "scan_results": [],
        }
        self.rep_legacy_path.write_text(json.dumps(self.rep_legacy_data), encoding="utf-8")

        # Create User A's scan job
        self.scan_a_id = "scana123"
        cond = threading.Condition()
        with scan_jobs_lock:
            scan_jobs[self.scan_a_id] = {
                "status": "done",
                "owner": self.user_a["id"],
                "target": "http://127.0.0.1:8001",
                "profile": "full",
                "events": [{"id": 1, "stage": "done", "message": "Done", "progress": 100}],
                "condition": cond,
                "report_name": self.rep_a_id,
                "error": None,
                "created_at": time.time(),
            }

    def tearDown(self):
        app.config["WTF_CSRF_ENABLED"] = True
        with scan_jobs_lock:
            scan_jobs.clear()
        self.db_patch.stop()
        self.env_patch.stop()
        auth._initialized_dbs.clear()
        self.tmp_dir.cleanup()

    def _client_for(self, user_dict):
        c = app.test_client()
        auth.login_test_client(c, user_dict["id"])
        return c

    def test_aud65_user_b_gets_404_on_all_user_a_routes_while_a_and_admin_get_200(self):
        client_a = self._client_for(self.user_a)
        client_b = self._client_for(self.user_b)
        client_admin = self._client_for(self.admin)

        routes = [
            f"/report/{self.rep_a_id}",
            f"/download/{self.rep_a_id}",
            f"/download_pdf/{self.rep_a_id}",
            f"/api/report/{self.rep_a_id}/waf-rules",
            f"/api/report/{self.rep_a_id}/dev-ticket/F-1",
            f"/scan/status/{self.scan_a_id}",
            f"/scan/progress/{self.scan_a_id}",
        ]

        for route in routes:
            with self.subTest(caller="user_b", route=route):
                resp_b = client_b.get(route)
                self.assertEqual(resp_b.status_code, 404, f"User B expected 404 on {route}, got {resp_b.status_code}")

            with self.subTest(caller="user_a", route=route):
                resp_a = client_a.get(route)
                self.assertEqual(resp_a.status_code, 200, f"User A expected 200 on {route}, got {resp_a.status_code}")

            with self.subTest(caller="admin", route=route):
                resp_adm = client_admin.get(route)
                self.assertEqual(resp_adm.status_code, 200, f"Admin expected 200 on {route}, got {resp_adm.status_code}")

        from core.models import Report
        reloaded = Report.from_dict(self.rep_a_data)
        self.assertEqual(reloaded.owner, self.user_a["id"])

    def test_aud65_history_isolation_and_ownerless_report_visibility(self):
        client_a = self._client_for(self.user_a)
        client_b = self._client_for(self.user_b)
        client_admin = self._client_for(self.admin)

        # History checks
        hist_b = client_b.get("/history")
        self.assertEqual(hist_b.status_code, 200)
        html_b = hist_b.data.decode("utf-8")
        self.assertNotIn(self.rep_a_id, html_b)
        self.assertNotIn("http://127.0.0.1:8001", html_b)
        self.assertNotIn(self.rep_legacy_id, html_b)

        hist_a = client_a.get("/history")
        self.assertEqual(hist_a.status_code, 200)
        html_a = hist_a.data.decode("utf-8")
        self.assertIn(self.rep_a_id, html_a)
        self.assertNotIn(self.rep_legacy_id, html_a)

        hist_admin = client_admin.get("/history")
        self.assertEqual(hist_admin.status_code, 200)
        html_admin = hist_admin.data.decode("utf-8")
        self.assertIn(self.rep_a_id, html_admin)
        self.assertIn(self.rep_legacy_id, html_admin)

        # Owner-less report route checks: 404 for A, 200 for admin
        for route in [
            f"/report/{self.rep_legacy_id}",
            f"/download/{self.rep_legacy_id}",
            f"/download_pdf/{self.rep_legacy_id}",
            f"/api/report/{self.rep_legacy_id}/waf-rules",
        ]:
            with self.subTest(route=route):
                self.assertEqual(client_a.get(route).status_code, 404)
                self.assertEqual(client_admin.get(route).status_code, 200)

    def test_aud65_pipeline_and_scan_async_record_owner(self):
        req = ScanRequest(
            target="http://127.0.0.1:8080",
            profile="recon",
            mock_mode=True,
            skip_reachability=True,
            owner=self.user_a["id"],
        )
        report, paths = run_scan_pipeline(req)
        self.assertEqual(report.owner, self.user_a["id"])
        saved_json = json.loads(Path(paths.json).read_text(encoding="utf-8"))
        self.assertEqual(saved_json.get("owner"), self.user_a["id"])

        client_a = self._client_for(self.user_a)
        with patch("ui.app._run_scan_background"):
            resp = client_a.post(
                "/scan/async",
                data={"target": "http://127.0.0.1:8080", "mode": "demo", "skip_reachability": "true"},
            )
            self.assertEqual(resp.status_code, 200)
            sid = resp.get_json()["scan_id"]
            with scan_jobs_lock:
                self.assertEqual(scan_jobs[sid].get("owner"), self.user_a["id"])


class TestAud66SessionAndSmallCorrectness(unittest.TestCase):
    """AUD-66: Session cookie flags, POST /logout with CSRF, sid enforcement, testbed time import, remediation AST."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp_dir.name)
        self.env_patch = patch.dict(
            os.environ,
            {
                "AUTOSEC_DATA_DIR": str(self.data_dir),
                "AUTOSEC_ADMIN_PASSWORD": "AdminPassword!234",
            },
        )
        self.env_patch.start()
        self.db_patch = patch.object(auth, "DB_PATH", self.data_dir / "users.db")
        self.db_patch.start()
        auth._initialized_dbs.clear()
        auth.init_user_db()
        self.admin = auth.get_user_by_username("admin")

    def tearDown(self):
        app.config["WTF_CSRF_ENABLED"] = True
        self.db_patch.stop()
        self.env_patch.stop()
        auth._initialized_dbs.clear()
        self.tmp_dir.cleanup()

    def test_aud66_login_cookie_flags_samesite_httponly_secure_and_lifetime(self):
        app.config["WTF_CSRF_ENABLED"] = False
        client = app.test_client()

        # Standard HTTP login -> SameSite=Lax, HttpOnly, permanent session (12h)
        resp = client.post("/login", data={"identifier": "admin", "password": "AdminPassword!234"})
        self.assertEqual(resp.status_code, 302)
        set_cookie = resp.headers.get("Set-Cookie", "")
        self.assertIn("SameSite=Lax", set_cookie)
        self.assertIn("HttpOnly", set_cookie)

        lifetime = app.config.get("PERMANENT_SESSION_LIFETIME")
        if isinstance(lifetime, timedelta):
            self.assertEqual(lifetime.total_seconds(), 12 * 3600)
        else:
            self.assertEqual(int(lifetime), 12 * 3600)

        # HTTPS login -> Secure flag set by default
        client_https = app.test_client()
        resp_https = client_https.post(
            "/login",
            data={"identifier": "admin", "password": "AdminPassword!234"},
            base_url="https://localhost",
        )
        self.assertIn("Secure", resp_https.headers.get("Set-Cookie", ""))

        # AUTOSEC_COOKIE_SECURE=true override on HTTP
        with patch.dict(os.environ, {"AUTOSEC_COOKIE_SECURE": "true"}):
            client_override = app.test_client()
            resp_ov = client_override.post(
                "/login",
                data={"identifier": "admin", "password": "AdminPassword!234"},
            )
            self.assertIn("Secure", resp_ov.headers.get("Set-Cookie", ""))

    def test_aud66_logout_requires_post_with_csrf_and_get_does_not_logout(self):
        app.config["WTF_CSRF_ENABLED"] = True
        client = app.test_client()

        # Fetch login page to obtain CSRF token
        login_page = client.get("/login")
        html = login_page.data.decode("utf-8")
        import re
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(m, "CSRF token input not found on /login")
        csrf_token = m.group(1)

        resp_login = client.post(
            "/login",
            data={"identifier": "admin", "password": "AdminPassword!234", "csrf_token": csrf_token},
        )
        self.assertEqual(resp_login.status_code, 302)
        self.assertTrue(client.get("/api/auth/status").get_json()["authenticated"])

        # GET /logout must NOT log the user out
        resp_get_logout = client.get("/logout")
        self.assertEqual(resp_get_logout.status_code, 405)
        self.assertTrue(client.get("/api/auth/status").get_json()["authenticated"])

        # POST /logout without CSRF token must fail (400) and NOT log the user out
        resp_no_csrf = client.post("/logout")
        self.assertEqual(resp_no_csrf.status_code, 400)
        self.assertTrue(client.get("/api/auth/status").get_json()["authenticated"])

        # Landing page renders a POST form to /logout with csrf_token
        landing_html = client.get("/").data.decode("utf-8")
        self.assertNotIn('href="/logout"', landing_html)
        self.assertIn('action="/logout"', landing_html)
        m2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', landing_html)
        self.assertIsNotNone(m2)

        # POST /logout with valid CSRF token logs out and revokes session
        resp_post_logout = client.post("/logout", data={"csrf_token": m2.group(1)})
        self.assertEqual(resp_post_logout.status_code, 302)
        self.assertFalse(client.get("/api/auth/status").get_json()["authenticated"])

    def test_aud66_forged_session_without_sid_rejected_with_302(self):
        app.config["WTF_CSRF_ENABLED"] = False
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = self.admin["id"]
            sess.pop("sid", None)

        resp = client.get("/dashboard")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))
        self.assertFalse(client.get("/api/auth/status").get_json()["authenticated"])

    def test_aud66_testbed_api_exec_sleep_returns_200_after_2s(self):
        tb_client = testbed_app.test_client()
        t0 = time.monotonic()
        resp = tb_client.get("/api/exec?command=sleep")
        elapsed = time.monotonic() - t0
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(elapsed, 1.8)
        self.assertLess(elapsed, 4.0)

    def test_aud66_remediation_py_has_no_duplicate_dict_keys_ast(self):
        rem_path = Path(__file__).resolve().parent / "intelligence" / "remediation.py"
        tree = ast.parse(rem_path.read_text(encoding="utf-8"))
        duplicates = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                seen = set()
                for key_node in node.keys:
                    if isinstance(key_node, ast.Constant):
                        if key_node.value in seen:
                            duplicates.append((key_node.value, key_node.lineno))
                        seen.add(key_node.value)
        self.assertEqual(duplicates, [], f"Duplicate dict keys found in intelligence/remediation.py: {duplicates}")


if __name__ == "__main__":
    unittest.main()
