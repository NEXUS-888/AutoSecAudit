import os
import re
import sys
import time
import json
import zlib
import base64
import logging
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
from unittest.mock import patch

from ui.app import app, scan_jobs, scan_jobs_lock, _scan_executor
from core.models import Report


def extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract and decompress all stream chunks from raw PDF bytes."""
    extracted = []
    for s in re.findall(b"stream[\r\n]+(.*?)endstream", pdf_bytes, re.DOTALL):
        cur = s.strip()
        try:
            if not cur.startswith(b"<~"):
                cur = b"<~" + cur
            if not cur.endswith(b"~>"):
                cur = cur + b"~>"
            a85 = base64.a85decode(cur, adobe=True)
            decomp = zlib.decompress(a85)
            extracted.append(decomp.decode("latin-1", errors="ignore"))
        except Exception:
            try:
                decomp = zlib.decompress(cur)
                extracted.append(decomp.decode("latin-1", errors="ignore"))
            except Exception:
                extracted.append(cur.decode("latin-1", errors="ignore"))
    extracted.append(pdf_bytes.decode("latin-1", errors="ignore"))
    return "\n".join(extracted)


class FixtureCSRFAuthServer(BaseHTTPRequestHandler):
    """Loopback fixture app with CSRF form login and a secret protected page."""
    valid_sessions = set()
    current_token = "csrf_token_test_abc123"

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def finish(self):
        try:
            super().finish()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def log_message(self, format, *args):
        # Silence default HTTP server logging
        return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        cookie_hdr = self.headers.get("Cookie", "")
        is_auth = "auth_session=admin_logged_in_token" in cookie_hdr

        if path in ("/login", "/login/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "pre_session=pre123; Path=/; SameSite=Lax")
            self.end_headers()
            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Login</title></head>
            <body>
                <form action="/login" method="POST">
                    <input type="hidden" name="csrf_token" value="{self.current_token}" />
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <button type="submit">Sign In</button>
                </form>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
            return

        elif path == "/secret_admin_area":
            # Check for authenticated session cookie
            if is_auth:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                resp = "<html><body><h1>Admin Secret Area</h1><p>Welcome Admin!</p><form action='/secret_admin_area' method='POST'><input type='text' name='action'/><button type='submit'>Save</button></form><a href='/logout'>Logout</a></body></html>"
                self.wfile.write(resp.encode("utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Unauthorized - Login Required")
            return

        elif path in ("/", ""):
            # Root index page
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if is_auth:
                self.wfile.write(b"<html><body><h1>Public Index</h1><p>Welcome back, admin user dashboard session.</p><a href='/logout'>Logout</a><a href='/secret_admin_area'>Admin Link</a></body></html>")
            else:
                self.wfile.write(b"<html><body><h1>Public Index</h1><a href='/login'>Login</a></body></html>")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/login", "/login/"):
            content_length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_length).decode("utf-8")
            data = urllib.parse.parse_qs(post_body)

            user = data.get("username", [""])[0]
            pwd = data.get("password", [""])[0]
            token = data.get("csrf_token", [""])[0]

            if token == self.current_token and user == "admin" and pwd == "Correct_P@ss_2026!":
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", "auth_session=admin_logged_in_token; Path=/; HttpOnly; SameSite=Lax")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body><p>Invalid email or password</p></body></html>")
            return

        self.send_response(404)
        self.end_headers()


class TestAuthenticatedDashboard(unittest.TestCase):
    """Test suite for AUD-74: Harden dashboard authenticated-scan fields."""

    @classmethod
    def setUpClass(cls):
        import config
        cls._orig_profiles = dict(getattr(config, "SCAN_PROFILES", {}))
        config.SCAN_PROFILES["fast_auth_test"] = {
            "name": "Fast Auth Test Profile",
            "description": "Fast test profile with only CSRF scanner",
            "plugins": ["CSRFScanner"]
        }

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureCSRFAuthServer)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_port
        cls.target_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        import config
        config.SCAN_PROFILES = cls._orig_profiles

    def setUp(self):
        self.app_client = app.test_client()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

        import core.auth as auth
        auth.init_user_db()
        admin = auth.get_user_by_username("admin")
        if not admin:
            admin_id = auth.create_user("admin", "Admin123456!", "admin")
        else:
            admin_id = admin["id"]
        auth.login_test_client(self.app_client, admin_id)

    def test_form_has_labels_aria_labels_and_autocomplete_off(self):
        """Rendered scan form has <label for="...">, aria-label on all 3 inputs, and autocomplete='off' on password."""
        resp = self.app_client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Check login_user input
        user_input_pattern = r'<input[^>]*name=["\']login_user["\'][^>]*>'
        user_match = re.search(user_input_pattern, html)
        self.assertIsNotNone(user_match, "login_user input must exist")
        user_tag = user_match.group(0)
        self.assertIn('aria-label=', user_tag)
        self.assertIn('id=', user_tag)

        # Check login_pass input
        pass_input_pattern = r'<input[^>]*name=["\']login_pass["\'][^>]*>'
        pass_match = re.search(pass_input_pattern, html)
        self.assertIsNotNone(pass_match, "login_pass input must exist")
        pass_tag = pass_match.group(0)
        self.assertIn('aria-label=', pass_tag)
        self.assertIn('autocomplete="off"', pass_tag)
        self.assertIn('id=', pass_tag)

        # Check login_url input
        url_input_pattern = r'<input[^>]*name=["\']login_url["\'][^>]*>'
        url_match = re.search(url_input_pattern, html)
        self.assertIsNotNone(url_match, "login_url input must exist")
        url_tag = url_match.group(0)
        self.assertIn('aria-label=', url_tag)
        self.assertIn('id=', url_tag)

        # Check associated <label> tags
        self.assertIn('<label for="login_user_input"', html)
        self.assertIn('<label for="login_pass_input"', html)
        self.assertIn('<label for="login_url_input"', html)

    def test_invalid_login_url_rejected_with_http_400(self):
        """Off-origin or drive-letter login_url is rejected with HTTP 400 and value in error message."""
        # 1. Drive-letter path
        bad_drive_path = "C:/Program Files/Git/login"
        resp1 = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "real",
            "login_user": "admin",
            "login_pass": "pass123",
            "login_url": bad_drive_path,
        })
        self.assertEqual(resp1.status_code, 400)
        data1 = resp1.get_json()
        self.assertIn("error", data1)
        self.assertIn(bad_drive_path, data1["error"])

        # 2. Off-origin URL
        bad_off_origin = "http://evil-domain.com/login"
        resp2 = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "real",
            "login_user": "admin",
            "login_pass": "pass123",
            "login_url": bad_off_origin,
        })
        self.assertEqual(resp2.status_code, 400)
        data2 = resp2.get_json()
        self.assertIn("error", data2)
        self.assertIn(bad_off_origin, data2["error"])

        # 3. Backslash path
        bad_backslash = r"/login\attempt"
        resp3 = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "real",
            "login_user": "admin",
            "login_pass": "pass123",
            "login_url": bad_backslash,
        })
        self.assertEqual(resp3.status_code, 400)
        data3 = resp3.get_json()
        self.assertIn("error", data3)
        self.assertIn(bad_backslash, data3["error"])

    def test_demo_mode_ignores_login_fields(self):
        """In demo mode, login fields are ignored even if invalid login_url provided."""
        resp = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "demo",
            "login_user": "admin",
            "login_pass": "pass123",
            "login_url": "C:/Program Files/Git/login",
        })
        # Should not fail with 400 because demo mode ignores login fields
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("scan_id", data)

    def test_authenticated_scan_coverage_and_auth_status(self):
        """Authenticated scan discovers protected finding; wrong password reports auth_status failure."""
        # Run unauthenticated scan first
        resp_unauth = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "real",
            "profile": "fast_auth_test",
            "skip_reachability": "true",
        })
        self.assertEqual(resp_unauth.status_code, 200)
        scan_id_unauth = resp_unauth.get_json()["scan_id"]

        # Wait for unauth scan completion
        for _ in range(120):
            status_resp = self.app_client.get(f"/scan/status/{scan_id_unauth}")
            if status_resp.get_json().get("status") in ("done", "error"):
                break
            time.sleep(0.5)

        report_unauth_name = status_resp.get_json().get("report_name")
        self.assertIsNotNone(report_unauth_name)

        rep_unauth_resp = self.app_client.get(f"/download/{report_unauth_name}")
        unauth_report_data = rep_unauth_resp.get_json()
        unauth_endpoints = [f.get("endpoint", "") for f in unauth_report_data.get("all_findings", [])]
        self.assertFalse(any("/secret_admin_area" in ep for ep in unauth_endpoints))

        # Run authenticated scan with WRONG password
        resp_wrong = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "real",
            "profile": "fast_auth_test",
            "login_user": "admin",
            "login_pass": "Wrong_Password_1234",
            "login_url": "/login",
            "skip_reachability": "true",
        })
        self.assertEqual(resp_wrong.status_code, 200)
        scan_id_wrong = resp_wrong.get_json()["scan_id"]

        for _ in range(120):
            st = self.app_client.get(f"/scan/status/{scan_id_wrong}").get_json()
            if st.get("status") in ("done", "error"):
                break
            time.sleep(0.5)

        report_wrong_name = st.get("report_name")
        self.assertIsNotNone(report_wrong_name)

        # Load wrong password report to verify auth_status failure
        rep_wrong_resp = self.app_client.get(f"/download/{report_wrong_name}")
        wrong_report_data = rep_wrong_resp.get_json()
        self.assertIn("auth_status", wrong_report_data)
        self.assertIsNotNone(wrong_report_data["auth_status"])
        self.assertIn("fail", wrong_report_data["auth_status"].lower())

        # Run authenticated scan with CORRECT password
        resp_auth = self.app_client.post("/scan/async", data={
            "target": self.target_url,
            "mode": "real",
            "profile": "fast_auth_test",
            "login_user": "admin",
            "login_pass": "Correct_P@ss_2026!",
            "login_url": "/login",
            "skip_reachability": "true",
        })
        self.assertEqual(resp_auth.status_code, 200)
        scan_id_auth = resp_auth.get_json()["scan_id"]

        for _ in range(120):
            st_auth = self.app_client.get(f"/scan/status/{scan_id_auth}").get_json()
            if st_auth.get("status") in ("done", "error"):
                break
            time.sleep(0.5)

        report_auth_name = st_auth.get("report_name")
        self.assertIsNotNone(report_auth_name)

        rep_auth_resp = self.app_client.get(f"/download/{report_auth_name}")
        auth_report_data = rep_auth_resp.get_json()
        self.assertIn("auth_status", auth_report_data)
        self.assertEqual(auth_report_data["auth_status"], "Authenticated")

        # Protected endpoint finding check:
        auth_endpoints = [f.get("endpoint", "") for f in auth_report_data.get("all_findings", [])]
        self.assertTrue(
            any("/secret_admin_area" in ep for ep in auth_endpoints),
            "Authenticated scan must report finding on the protected page"
        )

    def test_password_redaction_everywhere(self):
        """Assert distinctive password string is never in jobs, status/progress, reports or logs."""
        distinctive_pwd = "SuperUniqueSecretPassword_!XYZ987!"

        orig_root_level = logging.getLogger().level
        log_capture = []
        class LogHandler(logging.Handler):
            def emit(self, record):
                log_capture.append(self.format(record))

        handler = LogHandler()
        handler.setLevel(logging.NOTSET)
        logging.getLogger().addHandler(handler)

        try:
            logging.getLogger().setLevel(logging.DEBUG)

            resp = self.app_client.post("/scan/async", data={
                "target": self.target_url,
                "mode": "real",
                "profile": "fast_auth_test",
                "login_user": "admin",
                "login_pass": distinctive_pwd,
                "login_url": "/login",
                "skip_reachability": "true",
            })
            self.assertEqual(resp.status_code, 200)
            scan_id = resp.get_json()["scan_id"]

            # 1. Check job dict immediately
            with scan_jobs_lock:
                job = scan_jobs.get(scan_id, {})
                job_str = str(job)
                self.assertNotIn(distinctive_pwd, job_str, "Password must not be in scan_jobs record")

            # 2. Check /scan/status response
            status_res = self.app_client.get(f"/scan/status/{scan_id}")
            self.assertEqual(status_res.status_code, 200)
            self.assertNotIn(distinctive_pwd, status_res.get_data(as_text=True))

            # 3. Check /scan/progress response
            prog_res = self.app_client.get(f"/scan/progress/{scan_id}")
            self.assertEqual(prog_res.status_code, 200)
            self.assertNotIn(distinctive_pwd, prog_res.get_data(as_text=True))

            # Wait for completion
            for _ in range(120):
                st = self.app_client.get(f"/scan/status/{scan_id}").get_json()
                if st.get("status") in ("done", "error"):
                    break
                time.sleep(0.5)

            report_name = st.get("report_name")
            self.assertIsNotNone(report_name, "report_name must not be None after scan completion")

            # Re-assert scan_jobs record and final /scan/status body after completion
            with scan_jobs_lock:
                final_job = scan_jobs.get(scan_id, {})
                self.assertNotIn(distinctive_pwd, str(final_job), "Password must not be in final scan_jobs record")

            final_status_res = self.app_client.get(f"/scan/status/{scan_id}")
            self.assertEqual(final_status_res.status_code, 200)
            self.assertNotIn(distinctive_pwd, final_status_res.get_data(as_text=True), "Password must not be in final status response")

            # 4. Check JSON report
            json_res = self.app_client.get(f"/download/{report_name}")
            self.assertEqual(json_res.status_code, 200)
            self.assertNotIn(distinctive_pwd, json_res.get_data(as_text=True), "Password must not be in JSON report")

            # 5. Check HTML report
            html_res = self.app_client.get(f"/report/{report_name}")
            self.assertEqual(html_res.status_code, 200)
            self.assertNotIn(distinctive_pwd, html_res.get_data(as_text=True), "Password must not be in HTML report")

            # 6. Check PDF report
            pdf_res = self.app_client.get(f"/download_pdf/{report_name}")
            self.assertEqual(pdf_res.status_code, 200)
            pdf_text = extract_pdf_text(pdf_res.data)
            # Positive control: verify PDF decompressed text contains application identity or target host
            self.assertTrue(
                "AutoSecAudit" in pdf_text or "127.0.0.1" in pdf_text,
                "Positive control failed: Expected target host or AutoSecAudit in decompressed PDF text"
            )
            self.assertNotIn(distinctive_pwd, pdf_text, "Password must not appear in decompressed PDF text")

            # 7. Check captured logs
            full_log_text = "\n".join(log_capture)
            self.assertNotIn(distinctive_pwd, full_log_text, "Password must not appear in any log message")

        finally:
            logging.getLogger().removeHandler(handler)
            logging.getLogger().setLevel(orig_root_level)


if __name__ == "__main__":
    unittest.main()
