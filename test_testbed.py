"""
Integration tests for Vulnerable Testbed Sandbox App.
"""

import unittest
from testbed.app import app


class TestTestbedSandbox(unittest.TestCase):
    """Test suite for the embedded sandbox testbed app endpoints."""

    def setUp(self):
        self.client = app.test_client()

    def test_index_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"AutoSecAudit Target Testbed", res.data)

    def test_search_xss_and_sqli(self):
        # Normal query
        res = self.client.get("/search?q=phone")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Search Results for: phone", res.data)

        # SQLi error injection
        res_sqli = self.client.get("/search?q=' OR 1=1--")
        self.assertEqual(res_sqli.status_code, 500)
        self.assertIn(b"OperationalError", res_sqli.data)

    def test_login_csrf_and_auth(self):
        # Form has no CSRF token
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"form method=\"POST\"", res.data)
        self.assertNotIn(b"csrf_token", res.data)

        # Auth bypass
        res_auth = self.client.post("/login", data={"username": "' or '1'='1", "password": "any"})
        self.assertEqual(res_auth.status_code, 302)

    def test_open_redirect(self):
        res = self.client.get("/redirect?next=https://example.com")
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers.get("Location"), "https://example.com")

    def test_bola_idor_api(self):
        res = self.client.get("/api/users/1")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertEqual(json_data["username"], "alice")

        res_victim = self.client.get("/api/users/2")
        self.assertEqual(res_victim.status_code, 200)
        self.assertEqual(res_victim.get_json()["username"], "bob")

    def test_secret_exposure(self):
        res = self.client.get("/.env")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"DATABASE_URL", res.data)


if __name__ == "__main__":
    unittest.main()
