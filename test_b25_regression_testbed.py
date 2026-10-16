"""
Tests for Batch 25: AUD-60 (Regression testbed sandbox 2) and AUD-61 (login-url validation).
"""

import os
import sys
import unittest
from urllib.parse import urlparse

import requests

from testsupport import run_fixture_server
from testbed.app2 import app as app2, LOGIN_CSRF_TOKEN
from core.authenticator import validate_login_url, AutoAuthenticator, AuthResult
from core.pipeline import run_scan_pipeline, ScanRequest
from core.engine import Engine
from reports.generator import ReportGenerator


class FastScanEngine(Engine):
    """Engine subclass that restricts execution to plugins needed by assertions and eliminates pacing delays."""
    def __init__(self, *args, **kwargs):
        from core.politeness import PolitenessEngine
        kwargs.setdefault("politeness", PolitenessEngine(request_interval_ms=0, min_jitter_ms=0, max_jitter_ms=0))
        super().__init__(*args, **kwargs)
        if hasattr(self, "http_client") and self.http_client:
            orig_req = self.http_client.request
            def robust_req(method, url, *a, **kw):
                to = kw.get("timeout")
                if isinstance(to, tuple) and len(to) == 2:
                    kw["timeout"] = (max(to[0] or 0.0, 30.0), max(to[1] or 0.0, 30.0))
                elif isinstance(to, (int, float)):
                    kw["timeout"] = max(to, 30.0)
                elif to is None:
                    kw["timeout"] = (30.0, 30.0)
                return orig_req(method, url, *a, **kw)
            self.http_client.request = robust_req

    def load_plugins(self, *args, **kwargs):
        super().load_plugins(*args, **kwargs)
        needed_plugins = {
            "SQLiScanner",
            "XSSScanner",
            "CommandInjectionScanner",
            "SSTIScanner",
            "MisconfigScanner",
            "APIAbuseScanner",
            "CSRFScanner",
        }
        self.plugins = [
            p for p in self.plugins
            if p.__class__.__name__ in needed_plugins
        ]
        return len(self.plugins)


class TestB25LoginUrlValidation(unittest.TestCase):
    """Tests for AUD-61: Mangled --login-url validation and error reporting."""

    def test_validate_login_url_rejected_values(self):
        target = "http://127.0.0.1:5103"

        # Drive letter path
        git_bash_path = "C:/Program Files/Git/login/"
        ok, msg = validate_login_url(git_bash_path, target)
        self.assertFalse(ok)
        self.assertIn(git_bash_path, msg)
        self.assertIn("MSYS_NO_PATHCONV=1", msg)

        # Backslash path
        bs_path = r"..\login"
        ok, msg = validate_login_url(bs_path, target)
        self.assertFalse(ok)
        self.assertIn(bs_path, msg)

        # Off-origin URL
        off_origin = "http://other.example/login"
        ok, msg = validate_login_url(off_origin, target)
        self.assertFalse(ok)
        self.assertIn(off_origin, msg)

    def test_validate_login_url_rejects_scheme_mismatch(self):
        target = "http://127.0.0.1:5103"
        scheme_mismatch = "https://127.0.0.1:5103/login/"
        ok, msg = validate_login_url(scheme_mismatch, target)
        self.assertFalse(ok)
        self.assertIn(scheme_mismatch, msg)

    def test_validate_login_url_accepted_values(self):
        target = "http://127.0.0.1:5103"

        ok, msg = validate_login_url("/login/", target)
        self.assertTrue(ok)
        self.assertIsNone(msg)

        same_origin = "http://127.0.0.1:5103/login/"
        ok, msg = validate_login_url(same_origin, target)
        self.assertTrue(ok)
        self.assertIsNone(msg)

    def test_authenticator_rejects_mangled_login_url(self):
        mangled = "C:/Program Files/Git/login/"
        auth = AutoAuthenticator(
            base_url="http://127.0.0.1:5103",
            username="admin",
            password="password",
            login_url=mangled,
        )
        res = auth.authenticate()
        self.assertFalse(res.success)
        self.assertIn(mangled, res.message)

    def test_cli_rejects_mangled_login_url(self):
        import main
        ret = main.run_scan(
            target="http://127.0.0.1:5103",
            profile="quick",
            mock_mode=False,
            login_user="admin",
            login_pass="password",
            login_url="C:/Program Files/Git/login/",
        )
        self.assertNotEqual(ret, 0)

        # Also verify CLI exit code via subprocess invocation
        import subprocess
        proc = subprocess.run(
            [sys.executable, "main.py", "scan", "http://127.0.0.1:5103", "--login-url", "C:/Program Files/Git/login/"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Windows drive-letter path detected", proc.stdout + proc.stderr)


class TestB25RegressionTestbedSandbox2(unittest.TestCase):
    """Tests for AUD-60: End-to-end pipeline scan against testbed/app2."""

    def test_login_rejects_wrong_credentials(self):
        client = app2.test_client()
        resp = client.post(
            "/login",
            data={
                "csrf_token": LOGIN_CSRF_TOKEN,
                "username": "user",
                "password": "wrongpassword",
            },
        )
        self.assertEqual(resp.status_code, 401)
        self.assertNotIn("session_token", resp.headers.get("Set-Cookie", ""))

    def test_dom_xss_sink_detection_distinguishes_concatenation_from_static_nav(self):
        from unittest.mock import MagicMock
        from plugins.xss_plugin import XSSScanner

        def check_snippet(html_snippet: str):
            scanner = XSSScanner("http://127.0.0.1:5103")
            def mock_safe_req(method, url, **kwargs):
                if url.endswith("/"):
                    m = MagicMock()
                    m.status_code = 200
                    m.text = f"<html><body>{html_snippet}</body></html>"
                    return m
                return None
            scanner._safe_request = MagicMock(side_effect=mock_safe_req)
            scanner._test_dom_xss_indicators("http://127.0.0.1:5103")
            return [r for r in scanner.results if r.get("type") == "dom_xss_indicator"]

        # Benign static navigation -> 0 findings
        benign = check_snippet("<button onclick=\"window.location.href='/labs/sqli'\">Click</button>")
        self.assertEqual(len(benign), 0, f"Expected 0 findings for static navigation, got {benign}")

        # Dynamic concatenation with document.cookie -> 1 finding
        dynamic_cookie = check_snippet("<button onclick=\"location.href='/x?c='+document.cookie\">Click</button>")
        self.assertEqual(len(dynamic_cookie), 1, f"Expected 1 finding for document.cookie sink, got {dynamic_cookie}")

        # Dynamic concatenation with location.hash -> 1 finding
        dynamic_hash = check_snippet("<button onclick=\"window.location='/a'+location.hash\">Click</button>")
        self.assertEqual(len(dynamic_hash), 1, f"Expected 1 finding for location.hash sink, got {dynamic_hash}")

    def test_broken_auth_probe_is_credential_free(self):
        """
        Verify that APIAbuseScanner probes broken-auth endpoints anonymously:
        an endpoint requiring a session cookie (/admin/panel) does NOT produce a finding,
        while an unauthenticated endpoint (/api/v1/_debug) produces exactly one finding.
        """
        from flask import Flask, request, Response, jsonify
        from plugins.api_abuse_plugin import APIAbuseScanner

        test_app = Flask("test_broken_auth_fixture")

        @test_app.route("/admin/panel")
        def admin_panel():
            if request.cookies.get("session_token") == "admin_secret":
                return Response("Admin Panel OK", status=200, mimetype="text/plain")
            return Response("Unauthorized", status=401, mimetype="text/plain")

        @test_app.route("/api/v1/_debug")
        def api_debug():
            return jsonify([{"id": 1, "username": "admin"}]), 200

        with run_fixture_server(test_app) as srv:
            scanner = APIAbuseScanner()
            scanner.configure(srv.base_url)
            scanner.set_auth(cookies={"session_token": "admin_secret"})
            scanner.set_discovered_endpoints([
                {"path": "/admin/panel", "method": "GET"},
                {"path": "/api/v1/_debug", "method": "GET"},
            ])
            scanner.run()
            output = scanner.parse_output()
            findings = output.get("findings", [])

            broken_auth_findings = [
                f for f in findings
                if "broken function-level authorization" in (f.get("title") or "").lower()
                or (f.get("endpoint") or "").startswith(("/admin/panel", "/api/v1/_debug"))
            ]
            endpoints_reported = [f.get("endpoint") for f in broken_auth_findings]
            self.assertEqual(
                endpoints_reported,
                ["/api/v1/_debug"],
                f"Expected exactly 1 broken-auth finding on /api/v1/_debug and none on /admin/panel, got: {endpoints_reported}",
            )
            self.assertEqual(len(broken_auth_findings), 1)
            self.assertEqual(broken_auth_findings[0]["endpoint"], "/api/v1/_debug")

    def test_broken_auth_probe_does_not_follow_redirects_to_login(self):
        """
        Verify that APIAbuseScanner does not follow 302 redirects to /login:
        /admin/panel returns 200 with session cookie and redirect("/login", 302) otherwise.
        /login always returns 200 with a login form.
        /api/v1/_debug always returns 200.
        Assert exactly one broken-auth finding on /api/v1/_debug and none on /admin/panel.
        """
        from flask import Flask, request, Response, jsonify, redirect
        from plugins.api_abuse_plugin import APIAbuseScanner

        test_app = Flask("test_broken_auth_redirect_fixture")

        @test_app.route("/admin/panel")
        def admin_panel():
            if request.cookies.get("session_token") == "admin_secret":
                return Response("Admin Panel OK", status=200, mimetype="text/plain")
            return redirect("/login", code=302)

        @test_app.route("/login")
        def login_page():
            return Response("<html><body>Login Form</body></html>", status=200, mimetype="text/html")

        @test_app.route("/api/v1/_debug")
        def api_debug():
            return jsonify([{"id": 1, "username": "admin"}]), 200

        with run_fixture_server(test_app) as srv:
            scanner = APIAbuseScanner()
            scanner.configure(srv.base_url)
            scanner.set_auth(cookies={"session_token": "admin_secret"})
            scanner.set_discovered_endpoints([
                {"path": "/admin/panel", "method": "GET"},
                {"path": "/api/v1/_debug", "method": "GET"},
            ])
            scanner.run()
            output = scanner.parse_output()
            findings = output.get("findings", [])

            broken_auth_findings = [
                f for f in findings
                if "broken function-level authorization" in (f.get("title") or "").lower()
                or (f.get("endpoint") or "").startswith(("/admin/panel", "/api/v1/_debug"))
            ]
            endpoints_reported = [f.get("endpoint") for f in broken_auth_findings]
            self.assertEqual(
                endpoints_reported,
                ["/api/v1/_debug"],
                f"Expected exactly 1 broken-auth finding on /api/v1/_debug and none on /admin/panel, got: {endpoints_reported}",
            )
            self.assertEqual(len(broken_auth_findings), 1)
            self.assertEqual(broken_auth_findings[0]["endpoint"], "/api/v1/_debug")

    def test_app2_full_scan_with_credentials(self):
        with run_fixture_server(app2) as srv:
            try:
                srv.server.socket.listen(128)
            except Exception:
                pass
            target_url = srv.base_url
            fixture_netloc = urlparse(target_url).netloc
            recorded_urls = []

            orig_send = requests.Session.send

            def send_spy(session_self, request, *a, **kw):
                recorded_urls.append(request.url)
                to = kw.get("timeout")
                if isinstance(to, tuple) and len(to) == 2:
                    kw["timeout"] = (max(to[0] or 0.0, 30.0), max(to[1] or 0.0, 30.0))
                elif isinstance(to, (int, float)):
                    kw["timeout"] = max(to, 30.0)
                elif to is None:
                    kw["timeout"] = (30.0, 30.0)
                return orig_send(session_self, request, *a, **kw)

            requests.Session.send = send_spy
            import config
            from unittest.mock import patch
            try:
                req = ScanRequest(
                    target=target_url,
                    profile="full",
                    login_user="admin",
                    login_pass="admin",
                    login_url="/login",
                    mock_mode=False,
                    skip_reachability=True,
                )
                with patch.object(config, "SCAN_DEADLINE_SECONDS", 600), \
                     patch.object(config, "SCAN_TIMEOUT", 600), \
                     patch.object(config, "CRAWL_MAX_SECONDS", 180), \
                     patch.object(config, "HTTP_TIMEOUT", 30), \
                     patch.object(config, "MAX_REQUEST_SECONDS", 60):
                    report, _ = run_scan_pipeline(
                        req,
                        engine_cls=FastScanEngine,
                        generator_cls=ReportGenerator,
                    )
            finally:
                requests.Session.send = orig_send

            # 1. Assert no off-origin requests were made
            self.assertGreater(len(recorded_urls), 0)
            seen_netlocs = {urlparse(u).netloc for u in recorded_urls}
            self.assertEqual(seen_netlocs, {fixture_netloc})

            # 2. Assert coverage is NOT degraded and crawl visited all pages
            coverage = getattr(report, "coverage", {})
            self.assertFalse(coverage.get("degraded", True), f"Coverage was degraded: {coverage}")
            crawl_stats = coverage.get("crawl", {})
            self.assertTrue(crawl_stats.get("start_ok", False))
            self.assertGreaterEqual(crawl_stats.get("pages_visited", 0), 6)
            self.assertGreaterEqual(crawl_stats.get("forms", 0), 5)

            # Collect findings by endpoint
            findings_by_ep = {}
            for f in report.all_findings:
                ep = (f.endpoint or "").split("?")[0]
                findings_by_ep.setdefault(ep, []).append(f)

            # 3. Assert each planted vulnerability is reported exactly once

            # (a) Simulated SQL error leak on /labs/sqli (exactly 1 finding)
            sqli_findings = [f for f in findings_by_ep.get("/labs/sqli", []) if f.vuln_type == "sqli"]
            self.assertEqual(len(sqli_findings), 1, f"Expected 1 SQLi on /labs/sqli, got {len(sqli_findings)}")
            self.assertEqual(sqli_findings[0].param, "query")

            # (b) Bare 500 status differential on /labs/sqli_bare500 (exactly 1 finding)
            bare500_findings = [f for f in findings_by_ep.get("/labs/sqli_bare500", []) if f.vuln_type == "sqli"]
            self.assertEqual(len(bare500_findings), 1, f"Expected 1 bare500 SQLi, got {len(bare500_findings)}")
            self.assertEqual(bare500_findings[0].param, "id")

            # (c) Reflected XSS on /labs/xss (exactly 1 finding)
            xss_findings = [f for f in findings_by_ep.get("/labs/xss", []) if f.vuln_type == "xss"]
            self.assertEqual(len(xss_findings), 1, f"Expected 1 XSS on /labs/xss, got {len(xss_findings)}")
            self.assertEqual(xss_findings[0].param, "comment")

            # (d) Command execution on /labs/rce (exactly 1 finding)
            rce_findings = [f for f in findings_by_ep.get("/labs/rce", []) if f.vuln_type == "command_injection"]
            self.assertEqual(len(rce_findings), 1, f"Expected 1 CMDi on /labs/rce, got {len(rce_findings)}")
            self.assertEqual(rce_findings[0].param, "domain")

            # (e) SSTI on /labs/ssti (exactly 1 finding)
            ssti_findings = [f for f in findings_by_ep.get("/labs/ssti", []) if f.vuln_type == "ssti"]
            self.assertEqual(len(ssti_findings), 1, f"Expected 1 SSTI on /labs/ssti, got {len(ssti_findings)}")
            self.assertEqual(ssti_findings[0].param, "name")

            # (f) Insecure session cookie (missing HttpOnly/SameSite)
            cookie_findings = [f for f in report.all_findings if "session_token" in str(f.param or "") or "session_token" in str(f.title or "")]
            self.assertEqual(len(cookie_findings), 1, f"Expected exactly 1 cookie finding for session_token, got {len(cookie_findings)}: {cookie_findings}")

            # (g) OpenAPI exposed spec on /openapi.json (exactly 1 finding)
            openapi_findings = [f for f in findings_by_ep.get("/openapi.json", []) if "openapi" in f.title.lower() or "api doc" in f.title.lower()]
            self.assertEqual(len(openapi_findings), 1, f"Expected 1 OpenAPI finding, got {len(openapi_findings)}")

            # (h) Unauthenticated debug endpoint on /api/v1/_debug (exactly 1 finding)
            debug_findings = [f for f in report.all_findings if (f.endpoint or "").rstrip("/") == "/api/v1/_debug"]
            self.assertEqual(len(debug_findings), 1, f"Expected 1 finding on /api/v1/_debug, got {len(debug_findings)}: {debug_findings}")

            # 4. Assert decoys produce NO findings
            # /go decoy must NOT produce any findings of any type
            go_findings = [f for f in report.all_findings if (f.endpoint or "").rstrip("/") == "/go"]
            self.assertEqual(go_findings, [], f"Decoy /go produced findings: {go_findings}")

            # /login decoy must NOT produce CSRF findings
            login_csrf_findings = [
                f for f in report.all_findings
                if f.vuln_type == "csrf" and (f.endpoint or "").rstrip("/") == "/login"
            ]
            self.assertEqual(login_csrf_findings, [], f"Decoy /login produced CSRF findings: {login_csrf_findings}")


if __name__ == "__main__":
    unittest.main()
