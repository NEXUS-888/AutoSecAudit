"""Fixes from the end-to-end retest of the audited build.

RT-01 Nmap scans only the target's port unless a full scan is opted into.
RT-02 Session cookies issued without HttpOnly / SameSite / Secure are reported.
RT-03 Logging out revokes the session; replaying the old cookie no longer works.
RT-04 Delta analysis only compares findings from scanners that ran in both scans.
RT-05 Delta analysis compares merged findings with merged findings (identical scans -> empty delta).
RT-06 External-testbed false positives: same-site redirects are not open redirects, URL fragments are
      never probed as admin paths, and CSRF cookies are not "insecure session cookies".
"""

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, ".")

import config
import core.auth as auth
from core.models import Finding, Report, ScanResult
from intelligence.delta import DeltaAnalyzer
from plugins.nmap_plugin import NmapPlugin


class TestNmapScope(unittest.TestCase):
    """RT-01"""

    def _cmd(self, target):
        plugin = NmapPlugin(mock_mode=False)
        plugin.configure(target)
        return plugin._build_command()

    def test_explicit_port_is_scanned_alone(self):
        cmd = self._cmd("http://127.0.0.1:8099")
        self.assertEqual(cmd[cmd.index("-p") + 1], "8099")
        self.assertEqual(cmd[-1], "127.0.0.1")

    def test_default_ports_follow_the_scheme(self):
        cmd = self._cmd("http://localhost/app")
        self.assertEqual(cmd[cmd.index("-p") + 1], "80")
        cmd = self._cmd("https://localhost/app")
        self.assertEqual(cmd[cmd.index("-p") + 1], "443")

    def test_full_scan_is_opt_in(self):
        with patch.object(config, "NMAP_FULL_SCAN", True, create=True):
            cmd = self._cmd("http://127.0.0.1:8099")
        self.assertNotIn("-p", cmd)
        self.assertEqual(cmd[-1], "127.0.0.1")

    def test_ipv6_literal_target_keeps_its_port(self):
        cmd = self._cmd("http://[::1]:9000/x")
        self.assertEqual(cmd[cmd.index("-p") + 1], "9000")
        self.assertIn("::1", cmd[-1])


class TestCookieFlags(unittest.TestCase):
    """RT-02"""

    def test_helper_flags_session_cookie_without_httponly_and_samesite(self):
        from core.cookies import insecure_cookie_flags
        issues = insecure_cookie_flags(["session_id=abc123; Path=/"], https=False)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["cookie"], "session_id")
        self.assertEqual(set(issues[0]["missing"]), {"HttpOnly", "SameSite"})

    def test_helper_requires_secure_only_over_https(self):
        from core.cookies import insecure_cookie_flags
        header = "sid=abc; HttpOnly; SameSite=Lax"
        self.assertEqual(insecure_cookie_flags([header], https=False), [])
        issues = insecure_cookie_flags([header], https=True)
        self.assertEqual(issues[0]["missing"], ["Secure"])

    def test_helper_ignores_non_session_cookies_and_hardened_ones(self):
        from core.cookies import insecure_cookie_flags
        self.assertEqual(insecure_cookie_flags(["theme=dark; Path=/"], https=False), [])
        self.assertEqual(
            insecure_cookie_flags(["session=x; HttpOnly; Secure; SameSite=Strict"], https=True), [])

    def test_sqli_plugin_reports_cookie_issued_on_login_bypass(self):
        from plugins.sqli_plugin import SQLiScanner
        plugin = SQLiScanner(mock_mode=False)
        plugin.configure("http://127.0.0.1:8099")
        plugin.results = [{
            "endpoint": "/login", "param": "username", "payload": "' OR 1=1--",
            "matched_signature": "authentication_bypass_differential_success",
            "status_code": 302, "evidence": "HTTP 302", "type": "login_bypass",
            "verified": True, "confidence": "high",
            "set_cookie_headers": ["session_id=tok; Path=/"],
        }]
        findings = plugin.parse_output()["findings"]
        cookie = [f for f in findings if f.get("vuln_type") == "insecure_cookie"]
        self.assertEqual(len(cookie), 1)
        self.assertIn("session_id", cookie[0]["title"])
        self.assertIn("HttpOnly", cookie[0]["description"])
        self.assertEqual(cookie[0]["severity"], "Medium")

    def test_misconfig_plugin_reports_cookie_on_main_page(self):
        from plugins.misconfig_plugin import MisconfigScanner
        plugin = MisconfigScanner(mock_mode=False)
        plugin.configure("http://127.0.0.1:8099")
        plugin.results = []
        plugin._record_cookie_issues(["sessionid=abc; Path=/"], "http://127.0.0.1:8099/")
        out = plugin.parse_output()["findings"]
        cookie = [f for f in out if f.get("vuln_type") == "insecure_cookie"]
        self.assertEqual(len(cookie), 1)
        self.assertIn("sessionid", cookie[0]["title"])

    def test_scanner_finds_the_testbed_session_cookie_end_to_end(self):
        from werkzeug.serving import make_server
        from testbed.app import app as testbed_app
        from plugins.sqli_plugin import SQLiScanner

        server = make_server("127.0.0.1", 0, testbed_app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            plugin = SQLiScanner(mock_mode=False)
            plugin.configure(f"http://127.0.0.1:{server.server_port}")
            plugin.run()
            findings = plugin.parse_output()["findings"]
        finally:
            server.shutdown()
            thread.join(timeout=5)
        self.assertTrue(any(f.get("vuln_type") == "insecure_cookie" and "session_id" in f["title"]
                            for f in findings), [f["title"] for f in findings])


class TestSessionRevocation(unittest.TestCase):
    """RT-03"""

    def setUp(self):
        from ui.app import app
        self.app = app
        self.tmp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(auth, "DB_PATH", Path(self.tmp.name) / "users.db")
        self.db_patch.start()
        auth._initialized_dbs.clear()
        self.env_patch = patch.dict(os.environ, {"AUTOSEC_ADMIN_PASSWORD": "Retest-Only-9x!pass"})
        self.env_patch.start()
        app.config["WTF_CSRF_ENABLED"] = False

    def tearDown(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.env_patch.stop()
        self.db_patch.stop()
        auth._initialized_dbs.clear()
        self.tmp.cleanup()

    def _login(self, client):
        resp = client.post("/login", data={"identifier": "admin", "password": "Retest-Only-9x!pass"})
        self.assertEqual(resp.status_code, 302)

    def test_old_cookie_is_rejected_after_logout(self):
        client = self.app.test_client()
        self._login(client)
        old_cookie = client.get_cookie("session").value
        self.assertEqual(client.get("/dashboard").status_code, 200)

        client.post("/logout")

        replay = self.app.test_client()
        replay.set_cookie("session", old_cookie)
        resp = replay.get("/dashboard")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])
        self.assertEqual(replay.get("/api/auth/status").get_json().get("authenticated"), False)

    def test_logout_only_revokes_that_session(self):
        first, second = self.app.test_client(), self.app.test_client()
        self._login(first)
        self._login(second)
        first.post("/logout")
        self.assertEqual(second.get("/dashboard").status_code, 200)

    def test_revocation_survives_a_restart(self):
        client = self.app.test_client()
        self._login(client)
        old_cookie = client.get_cookie("session").value
        client.post("/logout")
        auth._initialized_dbs.clear()  # simulate a fresh process reading the same DB
        replay = self.app.test_client()
        replay.set_cookie("session", old_cookie)
        self.assertEqual(replay.get("/dashboard").status_code, 302)

    def test_revoked_session_rows_are_pruned(self):
        auth.revoke_session("old-sid", now=1.0)
        auth.revoke_session("new-sid")
        self.assertFalse(auth.is_session_revoked("old-sid"))
        self.assertTrue(auth.is_session_revoked("new-sid"))


def _finding(fid, tool, endpoint, vuln="x"):
    return Finding(id=fid, title=f"{vuln} at {endpoint}", severity="High", host="h", port=1,
                   description="d", raw_output="r", tool_name=tool, vuln_type=vuln,
                   endpoint=endpoint, param="p", method="GET")


def _report(tools, findings):
    return Report(
        target="http://t", timestamp="now",
        scan_results=[ScanResult(tool_name=t, target="http://t", timestamp="now",
                                 status="success") for t in tools],
        all_findings=findings)


class TestDeltaScope(unittest.TestCase):
    """RT-04"""

    def test_scanners_that_did_not_run_now_are_not_reported_as_fixed(self):
        previous = _report(["sqli_scanner", "nmap"],
                           [_finding("1", "sqli_scanner", "/a", "sqli"), _finding("2", "nmap", "80/tcp", "port_scan")])
        current = _report(["sqli_scanner"], [_finding("1", "sqli_scanner", "/a", "sqli")])
        delta = DeltaAnalyzer().compare(current, previous)
        self.assertEqual(delta["summary"]["fixed_count"], 0)
        self.assertEqual(delta["summary"]["unchanged_count"], 1)
        self.assertEqual(delta["scope"]["excluded_tools"], ["nmap"])
        self.assertEqual(delta["scope"]["compared_tools"], ["sqli_scanner"])

    def test_scanners_missing_from_the_previous_scan_are_not_reported_as_new(self):
        previous = _report(["sqli_scanner"], [_finding("1", "sqli_scanner", "/a", "sqli")])
        current = _report(["sqli_scanner", "xss_scanner"],
                          [_finding("1", "sqli_scanner", "/a", "sqli"), _finding("2", "xss_scanner", "/b", "xss")])
        delta = DeltaAnalyzer().compare(current, previous)
        self.assertEqual(delta["summary"]["new_count"], 0)
        self.assertEqual(delta["scope"]["excluded_tools"], ["xss_scanner"])

    def test_a_real_fix_is_still_reported_when_the_scanner_ran_in_both(self):
        previous = _report(["sqli_scanner"], [_finding("1", "sqli_scanner", "/a", "sqli")])
        current = _report(["sqli_scanner"], [])
        delta = DeltaAnalyzer().compare(current, previous)
        self.assertEqual(delta["summary"]["fixed_count"], 1)
        self.assertEqual(delta["scope"]["excluded_tools"], [])

    def test_merged_finding_counts_if_any_reporting_tool_ran_in_both(self):
        merged = _finding("1", "DirBrute, SecretExposureScanner", "/.env", "exposed_file")
        merged.reporting_tools = ["DirBrute", "SecretExposureScanner"]
        previous = _report(["DirBrute", "SecretExposureScanner"], [merged])
        current = _report(["SecretExposureScanner"], [])
        delta = DeltaAnalyzer().compare(current, previous)
        self.assertEqual(delta["summary"]["fixed_count"], 1)

    def test_reports_without_scan_results_fall_back_to_comparing_everything(self):
        previous = Report(target="t", timestamp="n", all_findings=[_finding("1", "a", "/a")])
        current = Report(target="t", timestamp="n", all_findings=[])
        delta = DeltaAnalyzer().compare(current, previous)
        self.assertEqual(delta["summary"]["fixed_count"], 1)


class TestDeltaAfterCorrelation(unittest.TestCase):
    """RT-05"""

    def _scan(self, previous=None):
        from core.pipeline import PipelinePaths, ScanRequest, run_scan_pipeline
        request = ScanRequest(target="http://127.0.0.1:8080", mock_mode=True, profile="full",
                              skip_reachability=True, previous_report=previous)
        report, paths = run_scan_pipeline(request)
        for path in (paths.json, paths.html):
            if path and os.path.exists(path):
                os.remove(path)
        return report

    def test_two_identical_scans_produce_an_empty_delta(self):
        first = self._scan()
        second = self._scan(previous=first.to_dict())
        summary = second.delta["summary"]
        self.assertEqual((summary["new_count"], summary["fixed_count"]), (0, 0), second.delta["new_issues"][:3])
        self.assertEqual(summary["unchanged_count"], len(second.all_findings))


class _FakeResponse:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.cookies = {}


class TestExternalTestbedFalsePositives(unittest.TestCase):
    """RT-06 (found by scanning pygoat and vulpy)"""

    def _redirect_findings(self, location, status=302):
        from plugins.open_redirect_plugin import OpenRedirectScanner
        plugin = OpenRedirectScanner(mock_mode=False)
        plugin.configure("http://127.0.0.1:5103")
        with patch.object(plugin, "_safe_request", return_value=_FakeResponse(status, {"Location": location})):
            plugin.run()
        return plugin.results

    def test_same_site_redirect_that_only_echoes_the_payload_is_not_an_open_redirect(self):
        # Django's APPEND_SLASH: /login?next=https://example.com -> /login/?next=https%3A%2F%2Fexample.com
        self.assertEqual(self._redirect_findings("/login/?next=https%3A%2F%2Fexample.com", status=301), [])
        self.assertEqual(self._redirect_findings("http://127.0.0.1:5103/login/?next=https://example.com", 301), [])

    def test_redirect_to_the_external_host_is_still_reported(self):
        self.assertTrue(self._redirect_findings("https://example.com"))
        self.assertTrue(self._redirect_findings("//example.com/landing"))
        self.assertTrue(self._redirect_findings("https://attacker.example.com/x"))

    def test_lookalike_host_is_not_reported(self):
        self.assertEqual(self._redirect_findings("https://notexample.com/"), [])

    def test_admin_probe_never_requests_a_url_fragment(self):
        from plugins.auth_plugin import AuthScanner
        plugin = AuthScanner(mock_mode=False)
        plugin.configure("http://127.0.0.1:5102")
        plugin.results = []
        seen = []

        def fake(method, url, **kwargs):
            seen.append(url)
            return _FakeResponse(200, {}, "<html>settings and admin links</html>")

        with patch.object(plugin, "_safe_request", side_effect=fake):
            plugin._test_exposed_admin_panels("http://127.0.0.1:5102")
        self.assertTrue(seen)
        self.assertFalse([u for u in seen if "#" in u], seen)
        self.assertFalse([r for r in plugin.results if "#" in str(r.get("path", r.get("title", "")))])

    def test_csrf_cookies_are_not_flagged_for_missing_httponly(self):
        from core.cookies import insecure_cookie_flags
        self.assertEqual(insecure_cookie_flags(["csrftoken=abc; Path=/; SameSite=Lax"], https=False), [])
        self.assertEqual(insecure_cookie_flags(["XSRF-TOKEN=abc; Path=/"], https=False), [])
        self.assertEqual(insecure_cookie_flags(["_csrf=abc; Path=/"], https=False), [])

    def test_a_real_session_cookie_with_token_in_its_name_is_still_flagged(self):
        from core.cookies import insecure_cookie_flags
        issues = insecure_cookie_flags(["auth_token=abc; Path=/"], https=False)
        self.assertEqual(issues[0]["cookie"], "auth_token")


if __name__ == "__main__":
    unittest.main()
