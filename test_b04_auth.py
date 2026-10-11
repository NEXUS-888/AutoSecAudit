import os
import sys
import tempfile
import sqlite3
import io
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, ".")

import core.auth as auth
from ui.app import app


class TestB04Auth(unittest.TestCase):
    """Test suite for Batch 04: Dashboard access control (AUD-10, AUD-11, AUD-12)."""

    def setUp(self):
        self.client = app.test_client()

    def tearDown(self):
        # Clean up any test users created
        try:
            with sqlite3.connect(str(auth.DB_PATH)) as conn:
                conn.execute("DELETE FROM users WHERE username IN ('hacker123', 'newdev42', 'connuser')")
                conn.commit()
        except Exception:
            pass

    def test_aud_10_unauthenticated_protected_routes_never_return_200(self):
        """AUD-10: Unauthenticated GET /history, GET /report/latest, GET /download/x,
        GET /api/report/x/waf-rules, POST /scan/async never return 200."""
        # HTML routes redirect to /login?next=... (302)
        resp = self.client.get("/history")
        self.assertNotEqual(resp.status_code, 200)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))
        self.assertIn("next=", resp.headers.get("Location", ""))

        resp = self.client.get("/report/latest")
        self.assertNotEqual(resp.status_code, 200)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

        resp = self.client.get("/download/sample_report")
        self.assertNotEqual(resp.status_code, 200)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

        # JSON/API and SSE routes return 401
        resp = self.client.get("/api/report/sample_report/waf-rules")
        self.assertNotEqual(resp.status_code, 200)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json().get("status"), "unauthorized")

        resp = self.client.post("/scan/async", json={"target": "http://localhost:3000"})
        self.assertNotEqual(resp.status_code, 200)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json().get("status"), "unauthorized")

    def test_aud_10_exempt_routes_remain_open(self):
        """AUD-10: /, /landing, /login, /register, /logout, /api/auth/status remain accessible."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get("/landing")
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get("/api/auth/status")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json().get("authenticated"))

    def test_aud_11_fresh_db_unset_env_admin_password_not_default(self):
        """AUD-11: On fresh DB with AUTOSEC_ADMIN_PASSWORD unset, verify_user('admin', 'AutoSec@2026') fails,
        password generated and printed to stderr once, and never logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_db = Path(tmpdir) / "test_users.db"
            orig_db_path = auth.DB_PATH
            auth.DB_PATH = temp_db

            # Ensure env var is unset
            env_backup = os.environ.pop("AUTOSEC_ADMIN_PASSWORD", None)
            try:
                stderr_capture = io.StringIO()
                with patch("sys.stderr", stderr_capture), self.assertLogs("core.auth", level="INFO") as log_capture:
                    auth.init_user_db()

                # Verify default hardcoded password fails
                ok, msg, user = auth.verify_user("admin", "AutoSec@2026")
                self.assertFalse(ok)

                # Verify password printed to stderr
                stderr_output = stderr_capture.getvalue()
                self.assertIn("AutoSec default admin password:", stderr_output)

                # Verify no password appears in log output
                for record in log_capture.output:
                    self.assertNotIn("AutoSec@2026", record)
                    # Extract generated token from stderr and ensure it is not in logs
                    token = stderr_output.split(":")[-1].strip()
                    self.assertNotIn(token, record)
            finally:
                auth.DB_PATH = orig_db_path
                if env_backup is not None:
                    os.environ["AUTOSEC_ADMIN_PASSWORD"] = env_backup

    def test_aud_12_registration_disabled_by_default(self):
        """AUD-12: With AUTOSEC_ALLOW_REGISTRATION unset, POST /register does not create a user."""
        env_backup = os.environ.pop("AUTOSEC_ALLOW_REGISTRATION", None)
        try:
            resp = self.client.post("/register", data={
                "username": "hacker123",
                "email": "hacker@example.com",
                "password": "Password123!",
                "full_name": "Hacker"
            })
            self.assertEqual(resp.status_code, 403)

            # Check that user was not created
            user = auth.get_user_by_username("hacker123") if hasattr(auth, "get_user_by_username") else None
            if user:
                self.fail("User hacker123 should not have been created")
        finally:
            if env_backup is not None:
                os.environ["AUTOSEC_ALLOW_REGISTRATION"] = env_backup

    def test_aud_12_registration_enabled_forces_developer_role(self):
        """AUD-12: When AUTOSEC_ALLOW_REGISTRATION=true, POST /register creates user with role='developer'."""
        with patch.dict(os.environ, {"AUTOSEC_ALLOW_REGISTRATION": "true"}):
            resp = self.client.post("/register", json={
                "username": "newdev42",
                "email": "newdev42@example.com",
                "password": "Password123!",
                "full_name": "New Developer",
                "role": "admin"  # Malicious attempt to self-register as admin
            })
            self.assertIn(resp.status_code, (200, 302))

            # Verify created user has role 'developer'
            ok, msg, user = auth.verify_user("newdev42", "Password123!")
            self.assertTrue(ok)
            self.assertEqual(user.get("role"), "developer")

    def test_aud_12_connections_are_closed_and_db_can_be_deleted(self):
        """AUD-12: Connections are wrapped with contextlib.closing; DB file can be deleted on Windows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_db = Path(tmpdir) / "test_conn_leak.db"
            orig_db_path = auth.DB_PATH
            auth.DB_PATH = temp_db
            try:
                auth.init_user_db()
                auth.create_user("connuser", "conn@example.com", "Password123!")
                auth.verify_user("connuser", "Password123!")
                auth.get_user_by_id("some-id")

                # On Windows, if any connection is unclosed, deleting will raise PermissionError
                temp_db.unlink()
                self.assertFalse(temp_db.exists())
            finally:
                auth.DB_PATH = orig_db_path


if __name__ == "__main__":
    unittest.main()
