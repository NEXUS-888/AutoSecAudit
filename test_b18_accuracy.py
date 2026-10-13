"""Unit tests for Batch 18: Detection Accuracy (AUD-48, AUD-49, AUD-50)."""

import unittest
from unittest.mock import MagicMock, patch
import urllib.parse
import requests

from core.models import Finding, compute_canonical_key, normalize_endpoint_path
from intelligence.correlator import Correlator
from intelligence.taxonomy import TAXONOMY_ENTRIES, get_taxonomy
from plugins.command_injection_plugin import CommandInjectionScanner
from plugins.xss_plugin import XSSScanner
from plugins.ssrf_plugin import SSRFScanner
from plugins.sqli_plugin import SQLiScanner
from testbed.app import app


def make_flask_safe_request(test_client):
    """Adapt Flask test_client calls to requests.Response objects for plugins."""
    def _handler(method, url, params=None, json_data=None, data=None, headers=None, **kwargs):
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        query = {}
        if parsed.query:
            for k, v in urllib.parse.parse_qsl(parsed.query):
                query[k] = v
        if params:
            query.update(params)
        open_kwargs = {}
        if headers:
            open_kwargs["headers"] = headers
        if query:
            open_kwargs["query_string"] = query
        if data:
            open_kwargs["data"] = data
        elif json_data is not None:
            open_kwargs["json"] = json_data
        flask_res = test_client.open(path, method=method, **open_kwargs)
        resp = requests.Response()
        resp.status_code = flask_res.status_code
        resp._content = flask_res.get_data()
        resp.headers = requests.structures.CaseInsensitiveDict(dict(flask_res.headers))
        for k, v in flask_res.headers:
            if k.lower() == "set-cookie":
                parts = v.split(";")[0].split("=")
                if len(parts) >= 2:
                    resp.cookies.set(parts[0].strip(), parts[1].strip())
        return resp
    return _handler


class TestB18Accuracy(unittest.TestCase):
    """Test suite for AUD-48, AUD-49, AUD-50."""

    # -------------------------------------------------------------------------
    # AUD-48: Reflection reported as command execution
    # -------------------------------------------------------------------------

    def test_aud48_echo_server_yields_no_command_injection_finding(self):
        """AUD-48: A server that merely echoes its input yields no command-injection finding."""
        scanner = CommandInjectionScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/search", "param": "q", "method": "GET"},
            {"path": "/view", "param": "file", "method": "GET"},
        ]

        def fake_echo_request(method, url, params=None, json_data=None, **kwargs):
            p_val = (params or {}).get("q") or (params or {}).get("file") or ""
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.text = f"<html><body>Search results: {p_val}</body></html>"
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_echo_request):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                findings = output.get("findings", [])
                self.assertEqual(
                    len(findings), 0,
                    f"Echo server must yield 0 command injection findings, got {len(findings)}: {findings}"
                )

    def test_aud48_static_page_tokens_yield_no_finding(self):
        """AUD-48: Fake server echoing q in page with static uid=7 or root:x:0:0 yields 0 findings."""
        for static_text in ('<a href="/profile?uid=7">Profile</a>', "root:x:0:0:root:/root:/bin/bash"):
            scanner = CommandInjectionScanner(mock_mode=False)
            scanner.configure("http://test.local")
            scanner.discovered_endpoints = [
                {"path": "/search", "param": "q", "method": "GET"},
            ]

            def fake_static_echo(method, url, params=None, json_data=None, **kwargs):
                val = (params or {}).get("q") or ""
                resp = MagicMock(spec=requests.Response)
                resp.status_code = 200
                resp.text = f"<html><body>Static content: {static_text}. Search query was: {val}</body></html>"
                return resp

            with patch.object(scanner, "_safe_request", side_effect=fake_static_echo):
                with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                    scanner.run()
                    output = scanner.parse_output()
                    findings = output.get("findings", [])
                    self.assertEqual(
                        len(findings), 0,
                        f"Page with static '{static_text}' echoing input must yield 0 findings, got: {findings}"
                    )

    def test_aud48_real_command_execution_is_reported(self):
        """AUD-48: Real command execution (evidence not identical to reflected input) is reported."""
        scanner = CommandInjectionScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/api/exec", "param": "command", "method": "POST"},
        ]

        def fake_exec_request(method, url, params=None, json_data=None, data=None, **kwargs):
            cmd = (json_data or {}).get("command") or (data or {}).get("command") or ""
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            if "AUTOSEC_RCE_TEST" in str(cmd):
                resp.text = "command output: AUTOSEC_RCE_TEST"
            else:
                resp.text = '{"status": "exec_ready", "output": "Executed"}'
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_exec_request):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                findings = output.get("findings", [])
                self.assertGreaterEqual(len(findings), 1)
                self.assertEqual(findings[0]["vuln_type"], "command_injection")
                self.assertEqual(findings[0]["severity"], "Critical")
                self.assertEqual(findings[0]["endpoint"], "/api/exec")

    def test_aud48_echo_and_run_server_yields_finding(self):
        """AUD-48: A fake server that runs the command AND echoes the input yields exactly 1 finding."""
        scanner = CommandInjectionScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/api/exec", "param": "command", "method": "POST"},
        ]

        def fake_echo_and_run(method, url, params=None, json_data=None, data=None, **kwargs):
            cmd = (json_data or {}).get("command") or (data or {}).get("command") or ""
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            if "AUTOSEC_RCE_TEST" in str(cmd) or "$((6*7))" in str(cmd):
                resp.text = f"ran {cmd}: command output: AUTOSEC_RCE_TEST"
            else:
                resp.text = f"ran {cmd}: echo only"
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_echo_and_run):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                findings = output.get("findings", [])
                self.assertEqual(len(findings), 1, "Server running command and echoing input must yield 1 finding")
                self.assertEqual(findings[0]["vuln_type"], "command_injection")

    def test_aud48_testbed_app_execution_and_suppression(self):
        """AUD-48: Against real testbed app, /api/exec is reported; /search, /fetch, /template, /view are not."""
        scanner = CommandInjectionScanner(mock_mode=False)
        scanner.configure("http://127.0.0.1:8080")
        scanner.discovered_endpoints = [
            {"path": "/search", "param": "q", "method": "GET"},
            {"path": "/fetch", "param": "url", "method": "GET"},
            {"path": "/template", "param": "name", "method": "GET"},
            {"path": "/view", "param": "file", "method": "GET"},
            {"path": "/api/exec", "param": "command", "method": "POST"},
        ]

        req_handler = make_flask_safe_request(app.test_client())
        with patch.object(scanner, "_safe_request", side_effect=req_handler):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                findings = output.get("findings", [])
                endpoints_reported = [f.get("endpoint") for f in findings]

                # /api/exec must be reported
                self.assertTrue(any("/api/exec" in ep for ep in endpoints_reported),
                                f"Expected /api/exec in findings, got: {endpoints_reported}")

                # /search, /fetch, /template, /view must NOT be reported
                for excluded in ("/search", "/fetch", "/template", "/view"):
                    self.assertFalse(any(excluded in ep for ep in endpoints_reported),
                                     f"{excluded} was incorrectly reported as command injection: {endpoints_reported}")

    def test_aud48_json_only_post_endpoint_yields_one_finding(self):
        """AUD-48: Fake server that reads only JSON body (415 for form bodies) yields 1 finding on discovered POST endpoint not in json_endpoints."""
        scanner = CommandInjectionScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/api/run", "param": "command", "method": "POST"},
        ]

        recorded_calls = []

        def fake_json_only_server(method, url, params=None, json_data=None, data=None, **kwargs):
            recorded_calls.append({
                "method": method,
                "url": url,
                "params": params,
                "json_data": json_data,
                "data": data,
            })
            resp = MagicMock(spec=requests.Response)
            if not url.endswith("/api/run"):
                resp.status_code = 404
                resp.text = "Not Found"
                return resp

            # Follow requests precedence: if data is truthy, json_data is dropped -> server gets form body -> 415
            if data:
                resp.status_code = 415
                resp.text = "Unsupported Media Type: Expected application/json"
                return resp
            if json_data is None:
                resp.status_code = 400
                resp.text = "Bad Request: Missing JSON body"
                return resp
            cmd = json_data.get("command", "")
            resp.status_code = 200
            if "$((6*7))" in str(cmd):
                resp.text = '{"output": "AUTOSEC_42_RCE"}'
            elif "AUTOSEC_RCE_TEST" in str(cmd):
                resp.text = '{"output": "command output: AUTOSEC_RCE_TEST"}'
            else:
                resp.text = f'{{"output": "Executed: {cmd}"}}'
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_json_only_server):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                findings = output.get("findings", [])
                self.assertEqual(len(findings), 1, f"Expected 1 finding on JSON-only POST endpoint, got: {findings}")
                finding = findings[0]
                self.assertEqual(finding["vuln_type"], "command_injection")
                self.assertEqual(finding["endpoint"], "/api/run")
                self.assertEqual(finding["method"], "POST")
                self.assertEqual(finding["param"], "command")
                self.assertNotIn("JSON body", finding["title"])

                winning_payload = scanner.results[0]["payload"]
                matching_calls = [
                    c for c in recorded_calls
                    if c["url"].endswith("/api/run")
                    and c["json_data"] == {"command": winning_payload}
                    and not c["data"]
                ]
                self.assertEqual(
                    len(matching_calls), 1,
                    f"Expected probe producing the finding to be sent with json_data and without data; calls={recorded_calls}",
                )

    # -------------------------------------------------------------------------
    # AUD-49: Content-type-blind detections and missed login injection
    # -------------------------------------------------------------------------

    def test_aud49_xss_ignored_on_json_content_type(self):
        """AUD-49: Reflected XSS is not reported on application/json endpoints (e.g. /fetch)."""
        scanner = XSSScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/fetch", "param": "url", "method": "GET"},
            {"path": "/search", "param": "q", "method": "GET"},
        ]

        def fake_xss_request(method, url, params=None, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            if "/fetch" in url:
                resp.headers = {"Content-Type": "application/json"}
                resp.text = f'{{"status": "remote_fetch_ok", "url": "{params.get("url")}"}}'
            else:
                resp.headers = {"Content-Type": "text/html; charset=utf-8"}
                q_val = (params or {}).get("q", "")
                resp.text = f"<h2>Search Results for: {q_val}</h2>"
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_xss_request):
            scanner.run()
            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "xss"]

            fetch_findings = [f for f in findings if "/fetch" in f.get("endpoint", "")]
            search_findings = [f for f in findings if "/search" in f.get("endpoint", "")]

            self.assertEqual(len(fetch_findings), 0, "No XSS finding should be reported on application/json /fetch")
            self.assertGreaterEqual(len(search_findings), 1, "Reflected XSS must be reported on text/html /search")

    def test_aud49_ssrf_requires_fetched_evidence_not_mere_reflection(self):
        """AUD-49: SSRF is not reported on file parameter reflection (e.g. /view)."""
        scanner = SSRFScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/view", "param": "file", "method": "GET"},
            {"path": "/fetch", "param": "url", "method": "GET"},
        ]

        def fake_ssrf_request(method, url, params=None, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            if "/view" in url:
                f_val = (params or {}).get("file", "")
                resp.text = f"Displaying content of file: {f_val}"
            else:
                resp.text = '{"status": "fetched", "simulated_internal_response": "SSH-2.0-OpenSSH_8.9p1 Ubuntu"}'
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_ssrf_request):
            scanner.run()
            output = scanner.parse_output()
            findings = output.get("findings", [])

            view_findings = [f for f in findings if "/view" in f.get("endpoint", "")]
            fetch_findings = [f for f in findings if "/fetch" in f.get("endpoint", "")]

            self.assertEqual(len(view_findings), 0, "No SSRF finding should be reported on /view")
            self.assertEqual(len(fetch_findings), 1, "SSRF must be reported on /fetch")

    def test_aud49_login_sqli_form_encoded_bypass(self):
        """AUD-49: SQLi scanner submits form-encoded POST bodies to login endpoint."""
        scanner = SQLiScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/login", "param": "username", "method": "POST"},
            {"path": "/login", "param": "password", "method": "POST"},
        ]

        requests_sent = []

        def fake_login_request(method, url, params=None, json_data=None, data=None, **kwargs):
            requests_sent.append({"method": method, "url": url, "json_data": json_data, "data": data})
            resp = MagicMock(spec=requests.Response)
            if data and isinstance(data, dict) and ("' or '1'='1" in data.get("username", "").lower() or "' or 1=1" in data.get("username", "").lower()):
                resp.status_code = 302
                resp.headers = {"Location": "/dashboard", "Set-Cookie": "session_id=admin_token"}
                resp.cookies = {"session_id": "admin_token"}
                resp.text = "Redirecting to /dashboard"
                resp.history = []
                return resp
            resp.status_code = 401
            resp.headers = {}
            resp.cookies = {}
            resp.text = "<p>Invalid credentials</p>"
            resp.history = []
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_login_request):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                findings = [f for f in output.get("findings", []) if f.get("endpoint") == "/login"]

                form_posts = [r for r in requests_sent if r.get("data") is not None]
                self.assertGreater(len(form_posts), 0, "Scanner must submit form-encoded POST requests")
                self.assertGreaterEqual(len(findings), 1, "/login SQL injection bypass must be reported")

    def test_aud49_login_constant_redirect_with_cookie_yields_no_finding(self):
        """AUD-49: A server that always answers 302 to /login?error=1 and sets cookie on every response yields 0 login findings."""
        scanner = SQLiScanner(mock_mode=False)
        scanner.configure("http://test.local")
        scanner.discovered_endpoints = [
            {"path": "/login", "param": "username", "method": "POST"},
            {"path": "/login", "param": "password", "method": "POST"},
        ]

        def fake_constant_redirect(method, url, params=None, json_data=None, data=None, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 302
            resp.headers = {"Location": "/login?error=1", "Set-Cookie": "tracker_id=abc"}
            resp.cookies = {"tracker_id": "abc"}
            resp.text = "Redirecting to /login?error=1"
            return resp

        with patch.object(scanner, "_safe_request", side_effect=fake_constant_redirect):
            with patch.object(scanner, "_verify_timing", return_value=(False, "low", {})):
                scanner.run()
                output = scanner.parse_output()
                login_findings = [f for f in output.get("findings", []) if f.get("endpoint") == "/login"]
                self.assertEqual(len(login_findings), 0, "Constant redirect server must yield 0 login bypass findings")

    def test_aud49_testbed_content_type_and_login(self):
        """AUD-49: Against real testbed app, no XSS on /fetch, no SSRF on /view, and SQLi on /login reported."""
        req_handler = make_flask_safe_request(app.test_client())

        # 1. XSS on /fetch
        xss = XSSScanner(mock_mode=False)
        xss.configure("http://127.0.0.1:8080")
        xss.discovered_endpoints = [{"path": "/fetch", "param": "url", "method": "GET"}]
        with patch.object(xss, "_safe_request", side_effect=req_handler):
            xss.run()
            xss_findings = [f for f in xss.parse_output().get("findings", []) if f.get("vuln_type") == "xss"]
            self.assertEqual(len(xss_findings), 0, "Real testbed /fetch must produce 0 XSS findings")

        # 2. SSRF on /view
        ssrf = SSRFScanner(mock_mode=False)
        ssrf.configure("http://127.0.0.1:8080")
        ssrf.discovered_endpoints = [{"path": "/view", "param": "file", "method": "GET"}]
        with patch.object(ssrf, "_safe_request", side_effect=req_handler):
            ssrf.run()
            ssrf_findings = ssrf.parse_output().get("findings", [])
            self.assertEqual(len(ssrf_findings), 0, "Real testbed /view must produce 0 SSRF findings")

        # 3. SQLi on /login
        sqli = SQLiScanner(mock_mode=False)
        sqli.configure("http://127.0.0.1:8080")
        sqli.discovered_endpoints = [
            {"path": "/login", "param": "username", "method": "POST"},
            {"path": "/login", "param": "password", "method": "POST"},
        ]
        with patch.object(sqli, "_safe_request", side_effect=req_handler):
            with patch.object(sqli, "_verify_timing", return_value=(False, "low", {})):
                sqli.run()
                sqli_findings = [f for f in sqli.parse_output().get("findings", []) if f.get("endpoint") == "/login"]
                self.assertGreaterEqual(len(sqli_findings), 1, "Real testbed /login SQLi bypass must be reported")

    # -------------------------------------------------------------------------
    # AUD-50: Cross-tool finding deduplication & canonical key
    # -------------------------------------------------------------------------

    def test_aud50_canonical_key_normalizes_numeric_path_segments(self):
        """AUD-50: Canonical key normalizes numeric path segments to {id}."""
        key1 = compute_canonical_key(vuln_type="idor", method="GET", endpoint="/api/users/1", param="id")
        key2 = compute_canonical_key(vuln_type="idor", method="GET", endpoint="/api/users/2", param="id")
        self.assertEqual(key1, key2)
        self.assertEqual(key1, "idor|GET|/api/users/{id}|id")

    def test_aud50_cross_tool_merging(self):
        """AUD-50: Cross-tool merging keeps highest confidence, lists reporting tools, unifies severity."""
        correlator = Correlator()

        f_xss = Finding(
            id="XSS-003",
            title="Missing Security Header: Content-Security-Policy",
            severity="Medium",
            host="localhost",
            port=80,
            description="XSS scanner CSP missing",
            raw_output="raw csp",
            tool_name="xss_scanner",
            confidence="high",
            vuln_type="misconfig",
            endpoint="/",
            param="Content-Security-Policy",
            method="GET",
            evidence="Evidence from XSS scanner (high confidence)",
        )

        f_misc = Finding(
            id="MISCONF-HDR-002",
            title="Missing security header: Content-Security-Policy",
            severity="Low",
            host="localhost",
            port=80,
            description="Misconfig scanner CSP missing",
            raw_output="raw csp",
            tool_name="misconfig_scanner",
            confidence="medium",
            vuln_type="misconfig",
            endpoint="/",
            param="Content-Security-Policy",
            method="GET",
            evidence="Evidence from Misconfig scanner (medium confidence)",
        )

        merged = correlator.merge_canonical([f_xss, f_misc])
        self.assertEqual(len(merged), 1, "Duplicate security header from 2 tools must be merged into 1 finding")

        res = merged[0]
        self.assertEqual(res.confidence, "high")
        self.assertEqual(res.evidence, "Evidence from XSS scanner (high confidence)")
        self.assertIn("misconfig_scanner", res.tool_name)
        self.assertIn("xss_scanner", res.tool_name)
        self.assertEqual(getattr(res, "reporting_tools", []), ["misconfig_scanner", "xss_scanner"])
        self.assertEqual(res.severity, "Low")

    def test_aud50_merge_canonical_preserves_sqli_on_admin(self):
        """AUD-50: merge_canonical([admin_panel_exposure, sqli_on_/admin?id]) returns 2 findings and SQLi keeps vuln_type=sqli and param=id."""
        correlator = Correlator()

        admin_panel_exposure = Finding(
            id="DIR-001",
            title="Exposed Admin Panel: /admin",
            severity="High",
            host="localhost",
            port=80,
            description="Exposed admin panel",
            raw_output="",
            tool_name="dir_brute",
            confidence="high",
            vuln_type="dir_brute",
            endpoint="/admin",
            param="",
            method="GET",
        )

        sqli_on_admin = Finding(
            id="SQLI-001",
            title="SQL Injection – Error-Based (/admin?id=<payload>)",
            severity="High",
            host="localhost",
            port=80,
            description="SQL injection on admin endpoint",
            raw_output="",
            tool_name="sqli_scanner",
            confidence="high",
            vuln_type="sqli",
            endpoint="/admin",
            param="id",
            method="GET",
        )

        merged = correlator.merge_canonical([admin_panel_exposure, sqli_on_admin])
        self.assertEqual(len(merged), 2, "admin panel exposure and SQLi on admin must remain distinct findings")

        sqli_finding = next((f for f in merged if f.vuln_type == "sqli"), None)
        self.assertIsNotNone(sqli_finding)
        self.assertEqual(sqli_finding.param, "id")
        self.assertEqual(sqli_finding.endpoint, "/admin")

    def test_aud50_multiple_issue_deduplication(self):
        """AUD-50: .env (3x), /admin (2x), /api/exec (2x), and IDOR (2x) merged to exactly 1 each."""
        correlator = Correlator()

        findings = [
            # /.env reported by 3 plugins
            Finding(id="SECR-001", title="Exposed Sensitive File: /.env", severity="Critical", host="localhost", port=80,
                    description="Secret leak", raw_output="", tool_name="secret_exposure_scanner", confidence="high",
                    vuln_type="secret_exposure", endpoint="/.env", param="", method="GET", evidence="SECRET=123"),
            Finding(id="DIR-001", title="Exposed Secrets File: /.env", severity="Critical", host="localhost", port=80,
                    description="Dir brute", raw_output="", tool_name="dir_brute", confidence="medium",
                    vuln_type="dir_brute", endpoint="/.env", param="", method="GET", evidence="SECRET=123"),
            Finding(id="MISCONF-001", title="Exposed sensitive file: .env configuration file", severity="Critical", host="localhost", port=80,
                    description="Misconfig file", raw_output="", tool_name="misconfig_scanner", confidence="medium",
                    vuln_type="misconfig", endpoint="/.env", param="/.env", method="GET", evidence="SECRET=123"),

            # /admin reported by 2 plugins
            Finding(id="AUTH-001", title="Exposed admin panel at /admin", severity="High", host="localhost", port=80,
                    description="Auth admin", raw_output="", tool_name="auth_scanner", confidence="high",
                    vuln_type="auth", endpoint="/admin", param="", method="GET", evidence="Admin panel"),
            Finding(id="DIR-002", title="Exposed Admin Panel: /admin", severity="High", host="localhost", port=80,
                    description="Dir admin", raw_output="", tool_name="dir_brute", confidence="medium",
                    vuln_type="dir_brute", endpoint="/admin", param="", method="GET", evidence="Admin panel"),

            # /api/exec reported 2x by command_injection_scanner
            Finding(id="CMDI-001", title="OS Command Injection (/api/exec?command=<payload>)", severity="Critical", host="localhost", port=80,
                    description="Param cmdi", raw_output="", tool_name="command_injection_scanner", confidence="high",
                    vuln_type="command_injection", endpoint="/api/exec", param="command", method="POST", evidence="output: AUTOSEC_RCE_TEST"),
            Finding(id="CMDI-002", title="OS Command Injection (/api/exec JSON body)", severity="Critical", host="localhost", port=80,
                    description="Body cmdi", raw_output="", tool_name="command_injection_scanner", confidence="high",
                    vuln_type="command_injection", endpoint="/api/exec", param="command", method="POST", evidence="output: AUTOSEC_RCE_TEST"),

            # IDOR reported for 2 sequential IDs
            Finding(id="IDOR-001", title="IDOR on /api/users/1", severity="High", host="localhost", port=80,
                    description="IDOR user 1", raw_output="", tool_name="BOLAIdorScanner", confidence="high",
                    vuln_type="idor", endpoint="/api/users/1", param="id", method="GET", evidence="user 1 profile"),
            Finding(id="IDOR-002", title="IDOR on /api/users/2", severity="High", host="localhost", port=80,
                    description="IDOR user 2", raw_output="", tool_name="BOLAIdorScanner", confidence="high",
                    vuln_type="idor", endpoint="/api/users/2", param="id", method="GET", evidence="user 2 profile"),
        ]

        merged = correlator.merge_canonical(findings)

        env_findings = [f for f in merged if f.endpoint == "/.env"]
        admin_findings = [f for f in merged if f.endpoint == "/admin"]
        exec_findings = [f for f in merged if f.endpoint == "/api/exec"]
        idor_findings = [f for f in merged if f.endpoint == "/api/users/{id}"]

        self.assertEqual(len(env_findings), 1, "/.env must be reported exactly once")
        self.assertEqual(len(admin_findings), 1, "/admin must be reported exactly once")
        self.assertEqual(len(exec_findings), 1, "/api/exec must be reported exactly once")
        self.assertEqual(len(idor_findings), 1, "IDOR must be reported exactly once")

    def test_aud50_testbed_full_scan_canonical_merge(self):
        """AUD-50: Full real plugin set against testbed merges /.env, /admin, /api/exec, idor, and each header to 1."""
        from core.engine import Engine
        from plugins.base_plugin import BaseScanner

        eng = Engine(mock_mode=False)
        eng.load_plugins()
        eng.target = "http://127.0.0.1:8080"

        endpoints = [
            {"path": "/search", "param": "q", "method": "GET"},
            {"path": "/fetch", "param": "url", "method": "GET"},
            {"path": "/template", "param": "name", "method": "GET"},
            {"path": "/view", "param": "file", "method": "GET"},
            {"path": "/api/exec", "param": "command", "method": "POST"},
            {"path": "/api/users/1", "param": "id", "method": "GET"},
            {"path": "/api/users/2", "param": "id", "method": "GET"},
            {"path": "/login", "param": "username", "method": "POST"},
            {"path": "/.env", "param": "", "method": "GET"},
            {"path": "/admin", "param": "", "method": "GET"},
        ]

        handler = make_flask_safe_request(app.test_client())
        with patch.object(BaseScanner, "_safe_request", side_effect=handler), \
             patch.object(BaseScanner, "_verify_timing", return_value=(False, "low", {})):
            raw_findings = []
            for p in eng.plugins:
                p.configure("http://127.0.0.1:8080")
                p.set_discovered_endpoints(endpoints)
                p.run()
                out = p.parse_output()
                raw_findings.extend(out.get("findings", []))

        all_findings = eng._dict_to_findings(raw_findings)
        self.assertGreater(len(all_findings), 0, "Scan must produce findings")

        # Verify identity function fails: raw findings contain duplicate .env and admin findings
        env_raw = [f for f in all_findings if f.endpoint and "/.env" in f.endpoint]
        self.assertGreater(len(env_raw), 1, "Expected duplicate .env findings before merge")

        # Apply merge_canonical
        corr = Correlator()
        merged = corr.merge_canonical(all_findings)

        # Assert exactly 1 for /.env
        env_findings = [f for f in merged if f.endpoint and "/.env" in f.endpoint]
        self.assertEqual(len(env_findings), 1, f"Expected 1 /.env finding, got: {env_findings}")

        # Assert exactly 1 for /admin auth
        admin_findings = [f for f in merged if f.endpoint and "/admin" in f.endpoint and f.vuln_type == "auth"]
        self.assertEqual(len(admin_findings), 1, f"Expected 1 /admin auth finding, got: {admin_findings}")

        # Assert exactly 1 for /api/exec command_injection
        exec_findings = [f for f in merged if f.endpoint and "/api/exec" in f.endpoint and f.vuln_type == "command_injection"]
        self.assertEqual(len(exec_findings), 1, f"Expected 1 /api/exec command injection finding, got: {exec_findings}")

        # Assert exactly 1 for idor on /api/users/{id}
        idor_findings = [f for f in merged if f.vuln_type == "idor" and f.endpoint and "/api/users" in f.endpoint]
        self.assertEqual(len(idor_findings), 1, f"Expected 1 IDOR finding on /api/users, got: {idor_findings}")

        # Assert exactly 1 for each missing-header param (case-insensitive) reported by any plugin
        header_params = set()
        for f in all_findings:
            if f.vuln_type == "misconfig" and f.param and not f.param.startswith("/") and not f.param.startswith("."):
                header_params.add(f.param.lower())

        self.assertGreater(len(header_params), 0, "Expected at least one security header finding")
        for hp in sorted(header_params):
            hp_findings = [f for f in merged if f.vuln_type == "misconfig" and (f.param or "").lower() == hp]
            self.assertEqual(len(hp_findings), 1, f"Expected exactly 1 finding for header '{hp}', got: {hp_findings}")


if __name__ == "__main__":
    unittest.main()
