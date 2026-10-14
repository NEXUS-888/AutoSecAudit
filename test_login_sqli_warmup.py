"""Login SQLi probing warms up the form with a GET before POSTing (as a browser does).

Found in the 2026-10-13 retest: vulpy's /user/login returns 404 for a POST in a cold session and
the correct SQL 200/500/200 status differential only after the form has been GET first. Real
browsers always fetch the login form before posting; without that, a genuine login-form SQL
injection is missed. This test asserts the behavioural fix (GET precedes the first POST) fast and
deterministically, instead of driving the full, request-heavy login-probe flow.
"""
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, ".")

from plugins.sqli_plugin import SQLiScanner


class TestLoginWarmup(unittest.TestCase):
    def test_get_precedes_first_post_to_each_login_path(self):
        base = "http://127.0.0.1:9"
        calls = []

        class FakeResp:
            status_code = 200
            text = "<form><input name=username><input name=password type=password></form>"
            headers = {}
            cookies = {}

        def fake_request(self, method, url, **kwargs):
            calls.append((method.upper(), url))
            return FakeResp()

        plugin = SQLiScanner(mock_mode=False)
        plugin.configure(base)
        plugin.set_discovered_endpoints([
            {"path": "/user/login", "param": "username", "method": "POST",
             "source": "form", "fields": {"username": "", "password": ""}},
        ])
        plugin.results = []
        with patch.object(SQLiScanner, "_safe_request", fake_request):
            plugin._test_login_endpoints(base)

        # For every login path that is POSTed to, a GET to that same path must come first.
        first_method = {}
        for method, url in calls:
            first_method.setdefault(url, method)
        posted = {url for method, url in calls if method == "POST"}
        self.assertIn(f"{base}/user/login", posted)
        for url in posted:
            self.assertEqual(first_method.get(url), "GET",
                             f"first request to {url} was {first_method.get(url)}, expected a warm-up GET")


if __name__ == "__main__":
    unittest.main()
