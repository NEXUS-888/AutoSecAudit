"""
Tests for AUD-71: Robust login-form SQL injection status differential.
"""

import sys
import time
import unittest
from flask import Flask, request, Response

from testsupport import run_fixture_server
import config
from plugins.sqli_plugin import SQLiScanner


class TestAUD71LoginSQLi(unittest.TestCase):
    """Acceptance tests for AUD-71."""

    def test_fixture_app_with_timing_session_and_rate_limit_detected(self):
        """
        A fixture app that:
        (a) answers POST only with 404 unless the form was fetched within the last 2 seconds in the same session,
        (b) returns 429 for the 6th POST in any 3-second window, and
        (c) otherwise returns 500 for an odd number of ' in any field and 200 otherwise,
        is detected: exactly one login-form SQLi finding is reported on the real field.
        The total number of POSTs is at most config.MAX_LOGIN_PROBE_REQUESTS.
        """
        app = Flask("aud71_vulnerable_app")

        sessions = {}  # session_id -> last_get_time
        post_timestamps = []
        post_count = [0]

        @app.route("/user/login", methods=["GET", "POST"])
        def login():
            session_id = request.cookies.get("session_id", "default_sess")
            now = time.time()

            if request.method == "GET":
                sessions[session_id] = now
                resp = Response(
                    '<html><body><form method="POST" action="/user/login">'
                    '<input name="username" type="text">'
                    '<input name="password" type="password">'
                    '</form></body></html>',
                    status=200,
                    mimetype="text/html",
                )
                resp.set_cookie("session_id", session_id)
                return resp

            # POST handling
            post_count[0] += 1
            # (b) returns 429 for the 6th POST in any 3-second window
            post_timestamps.append(now)
            recent_posts = [t for t in post_timestamps if now - t <= 3.0]
            if len(recent_posts) >= 6:
                return Response("Rate limit exceeded", status=429, mimetype="text/plain")

            # (a) answers POST only with 404 unless form was fetched within last 2 seconds in same session
            last_get = sessions.get(session_id, 0.0)
            if now - last_get > 2.0:
                return Response("Not Found / Session Expired", status=404, mimetype="text/plain")

            # (c) otherwise returns 500 for an odd number of ' in any field and 200 otherwise
            data = request.form or (request.get_json(silent=True) or {})
            total_single_quotes = sum(str(v).count("'") for v in data.values())
            if total_single_quotes % 2 == 1:
                return Response("Internal Server Error", status=500, mimetype="text/plain")
            return Response("OK / Invalid credentials", status=200, mimetype="text/plain")

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner()
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {"path": "/user/login", "method": "POST", "param": "username"},
                {"path": "/user/login", "method": "POST", "param": "password"},
            ])
            scanner.run()
            output = scanner.parse_output()
            findings = output.get("findings", [])

            login_findings = [f for f in findings if f.get("endpoint") == "/user/login"]
            self.assertEqual(len(login_findings), 1, f"Expected exactly 1 login finding, got: {login_findings}")
            self.assertEqual(login_findings[0].get("param"), "username")
            self.assertLessEqual(post_count[0], config.MAX_LOGIN_PROBE_REQUESTS)

    def test_fixture_always_500_not_reported(self):
        """A fixture whose login always returns 500 is not reported."""
        app = Flask("aud71_always_500_app")

        @app.route("/login", methods=["GET", "POST"])
        def login():
            if request.method == "GET":
                return Response(
                    '<html><body><form method="POST" action="/login">'
                    '<input name="username" type="text">'
                    '<input name="password" type="password">'
                    '</form></body></html>',
                    status=200,
                )
            return Response("Crash 500", status=500)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner()
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {"path": "/login", "method": "POST", "param": "username"},
            ])
            scanner.run()
            output = scanner.parse_output()
            login_findings = [f for f in output.get("findings", []) if f.get("endpoint") == "/login"]
            self.assertEqual(len(login_findings), 0, f"Expected 0 findings for always-500, got: {login_findings}")

    def test_fixture_500_on_every_special_char_not_reported(self):
        """A fixture that returns 500 for every special character including '' is not reported."""
        app = Flask("aud71_special_char_500_app")

        @app.route("/login", methods=["GET", "POST"])
        def login():
            if request.method == "GET":
                return Response(
                    '<html><body><form method="POST" action="/login">'
                    '<input name="username" type="text">'
                    '<input name="password" type="password">'
                    '</form></body></html>',
                    status=200,
                )
            data = request.form or (request.get_json(silent=True) or {})
            val = str(data.get("username", ""))
            # Returns 500 if any special character (including quote, doubled quote, dash, space) is present
            if any(c in val for c in "'\"- ;=()"):
                return Response("Input Validation Error 500", status=500)
            return Response("OK", status=200)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner()
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {"path": "/login", "method": "POST", "param": "username"},
            ])
            scanner.run()
            output = scanner.parse_output()
            login_findings = [f for f in output.get("findings", []) if f.get("endpoint") == "/login"]
            self.assertEqual(len(login_findings), 0, f"Expected 0 findings for special char 500, got: {login_findings}")


if __name__ == "__main__":
    unittest.main()
