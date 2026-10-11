import os
import sys
import tempfile
import time
import subprocess
import unittest
import re
from pathlib import Path

import config
from ui.app import app, reset_login_throttles
import core.auth as auth


class TestCSRFProtection(unittest.TestCase):
    """AUD-13: CSRF protection on state-changing POSTs."""

    def setUp(self):
        reset_login_throttles()
        app.config["WTF_CSRF_ENABLED"] = True
        self.client = app.test_client()

    def tearDown(self):
        app.config["WTF_CSRF_ENABLED"] = False

    def test_post_login_without_csrf_returns_400(self):
        """With CSRF enabled, POST /login without a token -> 400."""
        resp = self.client.post("/login", data={"identifier": "admin", "password": "any"})
        self.assertEqual(resp.status_code, 400)

    def test_post_register_without_csrf_returns_400(self):
        """With CSRF enabled, POST /register without a token -> 400."""
        resp = self.client.post("/register", data={"username": "newuser", "password": "any"})
        self.assertEqual(resp.status_code, 400)

    def test_post_scan_async_without_csrf_returns_400(self):
        """With CSRF enabled, POST /scan/async without a token -> 400."""
        resp = self.client.post("/scan/async", data={"target": "http://127.0.0.1:8080"})
        self.assertEqual(resp.status_code, 400)

    def test_csrf_can_be_disabled_via_config(self):
        """It must be disableable in tests via app.config['WTF_CSRF_ENABLED'] = False."""
        app.config["WTF_CSRF_ENABLED"] = False
        resp = self.client.post("/login", data={"identifier": "admin", "password": "wrongpassword"})
        self.assertEqual(resp.status_code, 401)

    def test_post_login_with_valid_token_succeeds(self):
        """With a valid CSRF token, POST /login reaches the route handler."""
        resp_get = self.client.get("/login")
        self.assertEqual(resp_get.status_code, 200)

        html = resp_get.get_data(as_text=True)
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(match, "CSRF token hidden input missing from /login form")
        token = match.group(1)

        resp_post = self.client.post("/login", data={
            "csrf_token": token,
            "identifier": "admin",
            "password": "wrongpassword"
        })
        self.assertEqual(resp_post.status_code, 401)


class TestOpenRedirect(unittest.TestCase):
    """AUD-14: Open redirect protection through `next` parameter."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.orig_db = auth.DB_PATH
        auth.DB_PATH = Path(cls.temp_dir.name) / "test_auth.db"
        os.environ["AUTOSEC_ADMIN_PASSWORD"] = "TestAdminPass123!"
        auth.init_user_db()

    @classmethod
    def tearDownClass(cls):
        auth.DB_PATH = cls.orig_db
        cls.temp_dir.cleanup()
        os.environ.pop("AUTOSEC_ADMIN_PASSWORD", None)

    def setUp(self):
        reset_login_throttles()
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_login_rejects_scheme_redirect(self):
        """next=https://evil.example redirects to a safe local path, not external scheme."""
        resp = self.client.post("/login", data={
            "identifier": "admin",
            "password": "TestAdminPass123!",
            "next": "https://evil.example"
        })
        self.assertEqual(resp.status_code, 302)
        location = resp.headers.get("Location", "")
        self.assertFalse(location.startswith("https://evil.example"))
        self.assertFalse(location.startswith("http://"))
        self.assertFalse(location.startswith("//"))
        self.assertTrue(location.startswith("/") or location == "")

    def test_login_rejects_protocol_relative_redirect(self):
        """next=//evil.example redirects to a safe local path."""
        resp = self.client.post("/login", data={
            "identifier": "admin",
            "password": "TestAdminPass123!",
            "next": "//evil.example"
        })
        self.assertEqual(resp.status_code, 302)
        location = resp.headers.get("Location", "")
        self.assertFalse(location.startswith("//"))
        self.assertNotIn("evil.example", location)

    def test_login_rejects_backslash_redirect(self):
        """next=/\\evil.example redirects to a safe local path."""
        resp = self.client.post("/login", data={
            "identifier": "admin",
            "password": "TestAdminPass123!",
            "next": "/\\evil.example"
        })
        self.assertEqual(resp.status_code, 302)
        location = resp.headers.get("Location", "")
        self.assertFalse(location.startswith("/\\"))
        self.assertNotIn("\\", location)
        self.assertNotIn("evil.example", location)

    def test_login_allows_valid_relative_redirect(self):
        """next=/history redirects to /history."""
        resp = self.client.post("/login", data={
            "identifier": "admin",
            "password": "TestAdminPass123!",
            "next": "/history"
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers.get("Location", "").endswith("/history"))

    def test_json_login_sanitizes_next_redirect(self):
        """JSON login also sanitizes the redirect field in response."""
        resp = self.client.post("/login", json={
            "identifier": "admin",
            "password": "TestAdminPass123!",
            "next": "https://evil.example"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["redirect"].startswith("https://"))
        self.assertFalse(data["redirect"].startswith("//"))
        self.assertTrue(data["redirect"].startswith("/"))


class TestUnsafeServerDefaults(unittest.TestCase):
    """AUD-15: Server host, secret key persistence, and login throttling."""

    def test_no_literal_host_0000_in_code(self):
        """No literal host='0.0.0.0' in the code."""
        root = Path(__file__).parent
        offenders = []
        pattern = 'host="' + '0.0.0.0"'
        pattern_single = "host='" + "0.0.0.0'"
        for py_file in root.glob("*.py"):
            if py_file.name == Path(__file__).name:
                continue
            text = py_file.read_text(encoding="utf-8", errors="ignore")
            if pattern in text or pattern_single in text:
                offenders.append(str(py_file.name))
        for py_file in (root / "ui").glob("*.py"):
            text = py_file.read_text(encoding="utf-8", errors="ignore")
            if pattern in text or pattern_single in text:
                offenders.append(f"ui/{py_file.name}")
        self.assertEqual(offenders, [], f"Found literal host='0.0.0.0' in: {offenders}")

    def test_secret_key_persistence_across_processes(self):
        """Two fresh processes see the same config.SECRET_KEY when AUTOSEC_SECRET_KEY is unset."""
        env = os.environ.copy()
        env.pop("AUTOSEC_SECRET_KEY", None)

        cmd = [sys.executable, "-c", "import config; print(config.SECRET_KEY)"]
        proc1 = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=str(Path(__file__).parent))
        proc2 = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=str(Path(__file__).parent))

        key1 = proc1.stdout.strip().splitlines()[-1]
        key2 = proc2.stdout.strip().splitlines()[-1]

        self.assertEqual(key1, key2, f"Secret keys differ between processes: {key1} vs {key2}")
        self.assertGreaterEqual(len(key1), 32)

    def test_login_throttling_triggers_429_on_sixth_failure(self):
        """At most 5 failures per IP per 5 minutes (in-memory), 6th bad login -> 429."""
        reset_login_throttles()

        app.config["WTF_CSRF_ENABLED"] = False
        client = app.test_client()

        # Send 5 failed login attempts from IP 198.51.100.1
        for i in range(5):
            resp = client.post("/login", data={
                "identifier": "nonexistent_user",
                "password": "wrongpassword"
            }, environ_base={"REMOTE_ADDR": "198.51.100.1"})
            self.assertEqual(resp.status_code, 401, f"Attempt {i+1} got status {resp.status_code}")

        # 6th attempt from the same IP must return 429
        resp6 = client.post("/login", data={
            "identifier": "nonexistent_user",
            "password": "wrongpassword"
        }, environ_base={"REMOTE_ADDR": "198.51.100.1"})
        self.assertEqual(resp6.status_code, 429, f"6th attempt expected 429, got {resp6.status_code}")

        # Another IP should not be blocked
        resp_other = client.post("/login", data={
            "identifier": "nonexistent_user",
            "password": "wrongpassword"
        }, environ_base={"REMOTE_ADDR": "198.51.100.2"})
        self.assertEqual(resp_other.status_code, 401)

    def test_login_throttling_cannot_be_bypassed_with_rotated_xff(self):
        """Rotating client-supplied X-Forwarded-For headers does not bypass throttling."""
        reset_login_throttles()

        app.config["WTF_CSRF_ENABLED"] = False
        client = app.test_client()

        # Send 5 failed attempts from same REMOTE_ADDR with varying XFF
        for i in range(5):
            resp = client.post("/login", data={
                "identifier": "nonexistent_user",
                "password": "wrongpassword"
            }, headers={"X-Forwarded-For": f"10.0.0.{i+1}"}, environ_base={"REMOTE_ADDR": "198.51.100.55"})
            self.assertEqual(resp.status_code, 401)

        # 6th attempt with yet another XFF header must return 429 because REMOTE_ADDR matches
        resp6 = client.post("/login", data={
            "identifier": "nonexistent_user",
            "password": "wrongpassword"
        }, headers={"X-Forwarded-For": "10.0.0.99"}, environ_base={"REMOTE_ADDR": "198.51.100.55"})
        self.assertEqual(resp6.status_code, 429, f"Expected 429 on rotated XFF, got {resp6.status_code}")

    def test_login_throttling_parallel_threads_race_free(self):
        """15 concurrent bad login requests behind a barrier return at most 5 401s and the rest 429s."""
        import threading
        from unittest.mock import patch

        reset_login_throttles()
        app.config["WTF_CSRF_ENABLED"] = False

        num_threads = 15
        barrier = threading.Barrier(num_threads)
        results = []
        results_lock = threading.Lock()

        def slow_failed_verify(identifier, password):
            time.sleep(0.15)
            return False, "Invalid credentials.", None

        def worker():
            client = app.test_client()
            barrier.wait()
            resp = client.post("/login", data={
                "identifier": "attacker",
                "password": "wrong"
            }, environ_base={"REMOTE_ADDR": "198.51.100.99"})
            with results_lock:
                results.append(resp.status_code)

        with patch("core.auth.verify_user", side_effect=slow_failed_verify):
            threads = [threading.Thread(target=worker) for _ in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        self.assertEqual(len(results), num_threads)
        status_401_count = results.count(401)
        status_429_count = results.count(429)

        self.assertLessEqual(status_401_count, 5, f"Expected at most 5 401s, got {status_401_count}")
        self.assertEqual(status_401_count + status_429_count, num_threads, f"Unexpected status codes: {results}")
        self.assertEqual(status_429_count, num_threads - status_401_count)


if __name__ == "__main__":
    unittest.main()
