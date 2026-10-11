"""
Unit tests for AutoSecAudit Automated Form & API Authentication (Auto-Login).
"""

import unittest
from unittest.mock import MagicMock, patch
import requests

from core.authenticator import AutoAuthenticator, AuthResult, _LoginFormParser
from core.crawler import WebCrawler
from core.engine import Engine
from plugins.base_plugin import BaseScanner


class TestLoginFormParser(unittest.TestCase):
    """Test HTML login form parsing and CSRF token extraction."""

    def test_extract_login_form_with_csrf(self):
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="hidden" name="csrfmiddlewaretoken" value="abc123tokenXYZ" />
                <label>Email</label>
                <input type="email" name="user_email" placeholder="Enter email" />
                <label>Password</label>
                <input type="password" name="user_password" />
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """
        parser = _LoginFormParser()
        parser.feed(html)

        self.assertEqual(len(parser.forms), 1)
        form = parser.forms[0]
        self.assertEqual(form["action"], "/login")
        self.assertEqual(form["method"], "POST")
        self.assertTrue(form["has_password"])
        self.assertIn("csrfmiddlewaretoken", form["hidden_fields"])
        self.assertEqual(form["hidden_fields"]["csrfmiddlewaretoken"], "abc123tokenXYZ")
        self.assertIn("user_email", form["inputs"])
        self.assertIn("user_password", form["inputs"])


class TestAutoAuthenticator(unittest.TestCase):
    """Test automated authentication workflows."""

    def test_html_form_login_success(self):
        html_form = """
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="token_999" />
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
        """

        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = {"session_id": "auth_cookie_value_12345"}

        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.text = html_form
        get_resp.headers = {"Content-Type": "text/html"}

        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 302
        post_resp.url = "http://localhost:3000/dashboard"
        post_resp.text = "Redirecting..."
        post_resp.json.side_effect = ValueError("Not JSON")

        session.get.return_value = get_resp
        session.post.return_value = post_resp

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="admin",
            password="password123",
            login_url="/login",
            session=session
        )

        result = auth.authenticate()
        self.assertTrue(result.success)
        self.assertIn("session_id", result.cookies)
        self.assertEqual(result.cookies["session_id"], "auth_cookie_value_12345")

        # Verify POST payload contained CSRF token and credentials
        session.post.assert_called_once()
        call_args = session.post.call_args
        payload = call_args[1]["data"]
        self.assertEqual(payload["username"], "admin")
        self.assertEqual(payload["password"], "password123")
        self.assertEqual(payload["csrf_token"], "token_999")

    def test_json_api_login_success(self):
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = {}

        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.text = '{"message": "API auth endpoint"}'
        get_resp.headers = {"Content-Type": "application/json"}

        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 200
        post_resp.text = '{"status": "ok", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ"}'
        post_resp.json.return_value = {
            "status": "ok",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ"
        }

        session.get.return_value = get_resp
        session.post.return_value = post_resp

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="admin@example.com",
            password="secret_password",
            login_url="/api/login",
            session=session
        )

        result = auth.authenticate()
        self.assertTrue(result.success)
        self.assertIsNotNone(result.token)
        self.assertIn("Authorization", result.headers)
        self.assertTrue(result.headers["Authorization"].startswith("Bearer eyJhbG"))

    def test_auth_rejection_failure(self):
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = {}

        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.text = '<form action="/login"><input type="password" name="password"></form>'
        get_resp.headers = {"Content-Type": "text/html"}

        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 401
        post_resp.text = "Invalid username or password"
        post_resp.json.side_effect = ValueError("Not JSON")

        session.get.return_value = get_resp
        session.post.return_value = post_resp

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="wrong_user",
            password="wrong_password",
            login_url="/login",
            session=session
        )

        result = auth.authenticate()
        self.assertFalse(result.success)
        self.assertIn("rejected", result.message.lower())


class TestCrawlerAndPluginAuthPropagation(unittest.TestCase):
    """Test session cookies and headers propagation to WebCrawler and BaseScanner."""

    def test_crawler_carries_auth_session(self):
        auth_headers = {"Authorization": "Bearer test_token_xyz"}
        auth_cookies = {"session_id": "sess_123"}

        crawler = WebCrawler(
            mock_mode=False,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies
        )

        self.assertEqual(crawler._session.headers.get("Authorization"), "Bearer test_token_xyz")
        self.assertEqual(crawler._session.cookies.get("session_id"), "sess_123")

    def test_base_scanner_auth_helpers(self):
        class DummyScanner(BaseScanner):
            def configure(self, target): self.target = target
            def run(self): pass
            def parse_output(self): return {"findings": []}
            def _get_tool_name(self): return "internal"
            def _get_mock_output(self): return {}

        scanner = DummyScanner()
        scanner.set_auth(
            headers={"Authorization": "Bearer dummy_jwt"},
            cookies={"user_session": "cookie_val"}
        )

        self.assertEqual(scanner.auth_headers["Authorization"], "Bearer dummy_jwt")
        self.assertEqual(scanner.auth_cookies["user_session"], "cookie_val")

        session = scanner.get_authenticated_session()
        self.assertEqual(session.headers["Authorization"], "Bearer dummy_jwt")
        self.assertEqual(session.cookies["user_session"], "cookie_val")


class TestEngineAuthIntegration(unittest.TestCase):
    """Test engine level auto-authentication and report generation."""

    def test_engine_sets_credentials_and_custom_headers(self):
        engine = Engine(mock_mode=True)
        engine.set_auth_credentials("test_user", "test_pass", login_url="/custom-login")
        engine.set_custom_headers({"X-API-Key": "key_12345"})

        self.assertEqual(engine.auth_credentials["username"], "test_user")
        self.assertEqual(engine.auth_credentials["password"], "test_pass")
        self.assertEqual(engine.auth_credentials["login_url"], "/custom-login")
        self.assertEqual(engine.custom_headers["X-API-Key"], "key_12345")

    def test_engine_generate_report_includes_auth_status(self):
        engine = Engine(mock_mode=True)
        engine.set_target("http://localhost:3000")
        engine.auth_result = AuthResult(success=True, cookies={"sess": "123"}, message="OK")

        report = engine.generate_report()
        self.assertEqual(report.auth_status, "Authenticated")
        self.assertEqual(report.to_dict()["auth_status"], "Authenticated")

    def test_engine_run_plugins_executes_authenticator(self):
        engine = Engine(mock_mode=False)
        engine.set_target("http://localhost:3000")
        engine.set_auth_credentials("admin", "pass")
        mock_plugin = MagicMock()
        mock_plugin.get_standardized_output.return_value = {"tool_name": "MockPlugin", "findings": []}
        engine.plugins = [mock_plugin]

        mock_auth_res = AuthResult(
            success=True,
            cookies={"session": "active_sess_id"},
            headers={"Authorization": "Bearer tok123"},
            message="Success"
        )

        with patch("core.authenticator.AutoAuthenticator.authenticate", return_value=mock_auth_res), \
             patch("core.crawler.WebCrawler.crawl") as mock_crawl:
            
            mock_crawl_res = MagicMock()
            mock_crawl_res.get_injectable_endpoints.return_value = []
            mock_crawl_res.get_login_endpoints.return_value = []
            mock_crawl.return_value = mock_crawl_res

            engine.run_plugins()
            self.assertIsNotNone(engine.auth_result)
            self.assertTrue(engine.auth_result.success)


if __name__ == "__main__":
    unittest.main()
