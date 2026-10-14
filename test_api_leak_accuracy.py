"""Sensitive-data leakage must not fire on API-documentation example values.

Found in the 2026-10-13 retest: VAmPI's /openapi.json contains example addresses
(mail1@mail.com) as documentation, which were reported as a High 'email pattern' leak.
"""
import sys
import threading
import unittest

sys.path.insert(0, ".")

from flask import Flask, Response, jsonify
from werkzeug.serving import make_server

from plugins.api_abuse_plugin import APIAbuseScanner

SPEC = """{
  "openapi": "3.0.0",
  "paths": {"/users": {"get": {"responses": {"200": {"content": {"application/json":
  {"example": {"email": "mail1@mail.com", "contact": "admin@example.com"}}}}}}}}
}"""


class TestApiLeakAccuracy(unittest.TestCase):
    def _scan(self, app):
        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            plugin = APIAbuseScanner(mock_mode=False)
            plugin.configure(f"http://127.0.0.1:{srv.server_port}")
            plugin.run()
            return plugin.parse_output()["findings"]
        finally:
            srv.shutdown()

    def _email_leaks(self, findings):
        return [f for f in findings if "email" in f["title"].lower() and "leak" in f["title"].lower()]

    def test_example_emails_in_openapi_spec_are_not_reported(self):
        app = Flask(__name__)

        @app.route("/openapi.json")
        def spec():
            return Response(SPEC, content_type="application/json")

        self.assertEqual(self._email_leaks(self._scan(app)), [],
                         "example emails in the API spec must not be a leak finding")

    def test_placeholder_emails_in_a_live_response_are_not_reported(self):
        app = Flask(__name__)

        @app.route("/api/Users")
        def users():
            return jsonify([{"email": "user@example.com"}, {"email": "test@example.org"}])

        self.assertEqual(self._email_leaks(self._scan(app)), [])

    def test_real_looking_emails_in_a_live_response_are_still_reported(self):
        app = Flask(__name__)

        @app.route("/api/Users")
        def users():
            return jsonify([{"email": "jane.doe@acmecorp.com"}, {"email": "bob@realbank.co"}])

        self.assertTrue(self._email_leaks(self._scan(app)),
                        "a genuine-looking email in live data should still be reported")


if __name__ == "__main__":
    unittest.main()
