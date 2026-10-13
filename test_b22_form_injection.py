"""Tests for Batch 22: Form-aware injection testing (AUD-51, AUD-52, AUD-53)."""

from __future__ import annotations

import html
import secrets
import threading
import unittest
from typing import Any, Dict, List
from unittest.mock import patch

from flask import Flask, Response, abort, make_response, render_template_string, request

import config
from core.crawler import WebCrawler
from plugins.command_injection_plugin import CommandInjectionScanner
from plugins.path_traversal_plugin import PathTraversalScanner
from plugins.sqli_plugin import SQLiScanner
from plugins.ssrf_plugin import SSRFScanner
from plugins.ssti_plugin import SSTIScanner
from plugins.xss_plugin import XSSScanner
from testsupport import run_fixture_server


def _build_aud51_app() -> tuple[Flask, Dict[str, Any]]:
    """Build local fixture app for AUD-51 with rotating one-time CSRF token."""
    app = Flask(__name__)
    state: Dict[str, Any] = {
        "latest_csrf": "initial_token",
        "submissions": [],
        "delete_hits": 0,
        "denied_field_hits": 0,
    }

    @app.route("/")
    def index() -> str:
        return """
        <html><body>
            <a href="/feedback">Feedback Form</a>
            <a href="/upload">Multipart Form</a>
            <a href="/danger">Danger Forms</a>
        </body></html>
        """

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback() -> Response:
        if request.method == "GET":
            token = secrets.token_hex(8)
            state["latest_csrf"] = token
            body = f"""
            <html><body>
                <form action="/feedback" method="POST">
                    <input type="hidden" name="csrfmiddlewaretoken" value="{token}" />
                    <select name="category">
                        <option value="bug_report">Bug Report</option>
                        <option value="feature">Feature Request</option>
                    </select>
                    <input type="text" name="comment" value="default_comment" />
                    <input type="submit" value="Send" />
                </form>
            </body></html>
            """
            return make_response(body, 200)

        # POST: require the fresh token from the most recent GET /feedback
        submitted_token = request.form.get("csrfmiddlewaretoken", "")
        if not submitted_token or submitted_token != state["latest_csrf"]:
            return make_response("CSRF token invalid or stale", 403)
        # Rotate token on every POST so a static token from initial crawl would fail on 2nd probe
        state["latest_csrf"] = secrets.token_hex(8)
        cat = request.form.get("category", "")
        if cat != "bug_report":
            return make_response("Missing select default", 400)
        comment = request.form.get("comment", "")
        state["submissions"].append({"category": cat, "comment": comment})
        return make_response(f"Accepted: {html.escape(comment)}", 200)

    @app.route("/upload", methods=["GET", "POST"])
    def upload() -> Response:
        if request.method == "GET":
            return make_response(
                """
                <html><body>
                    <form action="/upload" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="_csrf" value="mp_token" />
                        <input type="text" name="title" value="doc" />
                    </form>
                </body></html>
                """,
                200,
            )
        ctype = request.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype.lower():
            return make_response("Expected multipart/form-data", 400)
        return make_response(f"Uploaded title={html.escape(request.form.get('title', ''))}", 200)

    @app.route("/danger", methods=["GET"])
    def danger() -> str:
        return """
        <html><body>
            <form action="http://other.example/steal" method="POST">
                <input type="text" name="q" value="1" />
            </form>
            <form action="/account/delete" method="POST">
                <input type="text" name="reason" value="bye" />
            </form>
            <form action="/profile/update" method="POST">
                <input type="text" name="bio" value="hello" />
                <input type="text" name="delete_account" value="no" />
            </form>
        </body></html>
        """

    @app.route("/account/delete", methods=["POST"])
    def account_delete() -> Response:
        state["delete_hits"] += 1
        return make_response("Deleted", 200)

    @app.route("/profile/update", methods=["POST"])
    def profile_update() -> Response:
        state["denied_field_hits"] += 1
        return make_response("Updated", 200)

    return app, state


class TestAUD51FormDiscoveryAndSubmitProbe(unittest.TestCase):
    """AUD-51: Crawler preserves form metadata and BaseScanner.submit_form_probe works safely."""

    def test_crawler_extracts_fields_enctype_form_page_and_source(self) -> None:
        app, _ = _build_aud51_app()
        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=3)
            crawl_res = crawler.crawl(srv.base_url)
            injectables = crawl_res.get_injectable_endpoints()

            feedback_eps = [
                ep for ep in injectables
                if ep["path"] == "/feedback" and ep["param"] == "comment"
            ]
            self.assertEqual(len(feedback_eps), 1, f"Expected /feedback comment in {injectables}")
            fb_ep = feedback_eps[0]
            self.assertEqual(fb_ep["method"], "POST")
            self.assertEqual(fb_ep["source"], "form")
            self.assertIn("fields", fb_ep)
            self.assertIn("csrfmiddlewaretoken", fb_ep["fields"])
            self.assertTrue(fb_ep["fields"]["csrfmiddlewaretoken"])
            self.assertEqual(fb_ep["fields"].get("category"), "bug_report")
            self.assertEqual(fb_ep["fields"].get("comment"), "default_comment")
            self.assertEqual(fb_ep["enctype"], "application/x-www-form-urlencoded")
            self.assertTrue(fb_ep["form_page"].endswith("/feedback"))

    def test_submit_form_probe_refetches_csrf_token_and_succeeds(self) -> None:
        app, state = _build_aud51_app()
        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=3)
            crawl_res = crawler.crawl(srv.base_url)
            injectables = crawl_res.get_injectable_endpoints()
            fb_ep = next(
                ep for ep in injectables
                if ep["path"] == "/feedback" and ep["param"] == "comment"
            )

            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)

            # Mutate server's expected CSRF token so the crawled token is now stale;
            # submit_form_probe MUST re-fetch form_page first to obtain the fresh token.
            state["latest_csrf"] = "rotated_before_probe"

            resp1 = scanner.submit_form_probe(fb_ep, "comment", "benign_probe_1")
            self.assertIsNotNone(resp1)
            self.assertEqual(resp1.status_code, 200, f"Expected 200, got {resp1.status_code}: {resp1.text}")
            self.assertIn("Accepted: benign_probe_1", resp1.text)

            # Second probe also succeeds because submit_form_probe re-fetches form_page again
            resp2 = scanner.submit_form_probe(fb_ep, "comment", "benign_probe_2")
            self.assertIsNotNone(resp2)
            self.assertEqual(resp2.status_code, 200)

            # Multipart form probe encodes as multipart/form-data
            mp_ep = next(
                ep for ep in injectables
                if ep["path"] == "/upload" and ep["param"] == "title"
            )
            resp_mp = scanner.submit_form_probe(mp_ep, "title", "my_report")
            self.assertIsNotNone(resp_mp)
            self.assertEqual(resp_mp.status_code, 200)
            self.assertIn("Uploaded title=my_report", resp_mp.text)

    def test_submit_form_probe_refuses_cross_origin_and_denied_forms(self) -> None:
        app, state = _build_aud51_app()
        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)

            with patch.object(scanner, "_safe_request", wraps=scanner._safe_request) as spy_req:
                # (3) Cross-origin form action -> None, no request sent
                cross_ep = {
                    "path": "http://other.example/steal",
                    "param": "q",
                    "method": "POST",
                    "fields": {"q": "1"},
                    "enctype": "application/x-www-form-urlencoded",
                    "form_page": f"{srv.base_url}/danger",
                    "source": "form",
                }
                self.assertIsNone(scanner.submit_form_probe(cross_ep, "q", "test"))

                # (4a) Form at /account/delete -> None, no request sent
                delete_ep = {
                    "path": "/account/delete",
                    "param": "reason",
                    "method": "POST",
                    "fields": {"reason": "bye"},
                    "enctype": "application/x-www-form-urlencoded",
                    "form_page": f"{srv.base_url}/danger",
                    "source": "form",
                }
                self.assertIsNone(scanner.submit_form_probe(delete_ep, "reason", "test"))

                # (4b) Form whose field is named in the deny list -> None, no request sent
                denied_field_ep = {
                    "path": "/profile/update",
                    "param": "bio",
                    "method": "POST",
                    "fields": {"bio": "hello", "delete_account": "no"},
                    "enctype": "application/x-www-form-urlencoded",
                    "form_page": f"{srv.base_url}/danger",
                    "source": "form",
                }
                self.assertIsNone(scanner.submit_form_probe(denied_field_ep, "bio", "test"))

                self.assertEqual(spy_req.call_count, 0, "No HTTP requests should be sent for refused forms")
                self.assertEqual(state["delete_hits"], 0)
                self.assertEqual(state["denied_field_hits"], 0)


class TestAUD52SQLiAndXSSFormScanning(unittest.TestCase):
    """AUD-52: SQLi and XSS scanners test POST forms accurately and obey request caps."""

    def test_sqli_and_xss_detect_vulnerable_post_forms_and_ignore_safe_forms(self) -> None:
        app = Flask(__name__)

        @app.route("/")
        def index() -> str:
            return """
            <html><body>
                <form method="POST" action="/sql_lab">
                    <input type="text" name="name" value="alice" />
                    <input type="text" name="pass" value="secret" />
                </form>
                <form method="POST" action="/xss_lab">
                    <input type="text" name="comment" value="hello" />
                </form>
                <form method="POST" action="/xss_escaped">
                    <input type="text" name="comment" value="hello" />
                </form>
                <form method="POST" action="/sql_safe">
                    <input type="text" name="name" value="alice" />
                </form>
            </body></html>
            """

        @app.route("/sql_lab", methods=["POST"])
        def sql_lab() -> Response:
            name = request.form.get("name", "")
            if "'" in name:
                return make_response("sqlite3.OperationalError: near \"'\": syntax error at or near input", 500)
            return make_response(f"User lookup for {html.escape(name)}", 200)

        @app.route("/xss_lab", methods=["POST"])
        def xss_lab() -> Response:
            comment = request.form.get("comment", "")
            return Response(f"<html><body><div>You said: {comment}</div></body></html>", mimetype="text/html")

        @app.route("/xss_escaped", methods=["POST"])
        def xss_escaped() -> Response:
            comment = request.form.get("comment", "")
            return Response(f"<html><body><div>You said: {html.escape(comment)}</div></body></html>", mimetype="text/html")

        @app.route("/sql_safe", methods=["POST"])
        def sql_safe() -> Response:
            name = request.form.get("name", "")
            return make_response(f"Safe lookup for {html.escape(name)}", 200)

        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=2)
            injectables = crawler.crawl(srv.base_url).get_injectable_endpoints()

            sqli = SQLiScanner(mock_mode=False)
            sqli.configure(srv.base_url)
            sqli.set_discovered_endpoints(injectables)
            with (
                patch.object(sqli, "_test_login_endpoints"),
                patch.object(sqli, "_test_url_path_injection"),
                patch.object(sqli, "_test_json_body_sqli"),
            ):
                sqli.run()
            sqli_findings = [f for f in sqli.parse_output()["findings"] if f.get("vuln_type") == "sqli"]

            sql_lab_findings = [f for f in sqli_findings if f.get("endpoint") == "/sql_lab"]
            sql_safe_findings = [f for f in sqli_findings if f.get("endpoint") == "/sql_safe"]
            self.assertEqual(len(sql_lab_findings), 1, f"Expected 1 SQLi finding on /sql_lab, got {sqli_findings}")
            self.assertEqual(sql_lab_findings[0]["param"], "name")
            self.assertEqual(sql_lab_findings[0]["method"], "POST")
            self.assertEqual(len(sql_safe_findings), 0, f"Expected 0 SQLi findings on /sql_safe, got {sql_safe_findings}")

            xss = XSSScanner(mock_mode=False)
            xss.configure(srv.base_url)
            xss.set_discovered_endpoints(injectables)
            with (
                patch.object(xss, "_test_hash_fragment_endpoints"),
                patch.object(xss, "_test_dom_xss_indicators"),
                patch.object(xss, "_test_security_headers"),
            ):
                xss.run()
            xss_findings = [f for f in xss.parse_output()["findings"] if f.get("vuln_type") == "xss" and f.get("param") != "dom_xss"]

            xss_lab_findings = [f for f in xss_findings if f.get("endpoint") == "/xss_lab"]
            xss_esc_findings = [f for f in xss_findings if f.get("endpoint") == "/xss_escaped"]
            self.assertEqual(len(xss_lab_findings), 1, f"Expected 1 XSS finding on /xss_lab, got {xss_findings}")
            self.assertEqual(xss_lab_findings[0]["param"], "comment")
            self.assertEqual(xss_lab_findings[0]["method"], "POST")
            self.assertEqual(len(xss_esc_findings), 0, f"Expected 0 XSS findings on /xss_escaped, got {xss_esc_findings}")

    def test_twenty_forms_fixture_obeys_form_and_field_caps(self) -> None:
        """A fixture with 20 forms (each with 8 fields) receives no more form probes than caps allow."""
        app = Flask(__name__)
        lock = threading.Lock()
        form_post_counts: Dict[str, int] = {}
        fields_probed_per_form: Dict[str, set[str]] = {}

        @app.route("/")
        def index() -> str:
            forms_html = []
            for i in range(1, 21):
                fields = [
                    f'<input type="text" name="field_{j}" value="default_{j}" />'
                    for j in range(1, 8)
                ]
                if i == 15:
                    fields.append('<input type="text" name="query" value="default_8" />')
                else:
                    fields.append('<input type="text" name="field_8" value="default_8" />')
                inputs_html = "\n".join(fields)
                forms_html.append(f'<form method="POST" action="/form_{i}">{inputs_html}</form>')
            return "<html><body>" + "\n".join(forms_html) + "</body></html>"

        @app.route("/form_<int:form_idx>", methods=["POST"])
        def handle_form(form_idx: int) -> Response:
            key = f"/form_{form_idx}"
            with lock:
                form_post_counts[key] = form_post_counts.get(key, 0) + 1
                for k, v in request.form.items():
                    if not v.startswith("default_") and v != "safe123":
                        fields_probed_per_form.setdefault(key, set()).add(k)
            return make_response("OK", 200)

        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)
            injectables = crawler.crawl(srv.base_url).get_injectable_endpoints()

            max_forms = getattr(config, "MAX_FORMS_PER_PLUGIN", 8)
            max_fields = getattr(config, "MAX_FIELDS_PER_FORM", 6)

            for scanner_cls in (XSSScanner, SQLiScanner):
                with lock:
                    form_post_counts.clear()
                    fields_probed_per_form.clear()

                scanner = scanner_cls(mock_mode=False)
                scanner.configure(srv.base_url)
                scanner.set_discovered_endpoints(injectables)
                if scanner_cls is SQLiScanner:
                    with (
                        patch.object(scanner, "_test_login_endpoints"),
                        patch.object(scanner, "_test_url_path_injection"),
                        patch.object(scanner, "_test_json_body_sqli"),
                    ):
                        scanner.run()
                else:
                    with (
                        patch.object(scanner, "_test_hash_fragment_endpoints"),
                        patch.object(scanner, "_test_dom_xss_indicators"),
                        patch.object(scanner, "_test_security_headers"),
                    ):
                        scanner.run()

                self.assertGreater(len(form_post_counts), 0, f"Expected form probes from {scanner_cls.__name__}")
                self.assertLessEqual(
                    len(form_post_counts),
                    max_forms,
                    f"{scanner_cls.__name__}: Expected at most {max_forms} forms probed, got {len(form_post_counts)}",
                )
                self.assertIn(
                    "/form_15",
                    form_post_counts,
                    f"{scanner_cls.__name__}: Promising form /form_15 (with 'query' field) must be selected ahead of generic forms",
                )
                self.assertIn(
                    "query",
                    fields_probed_per_form.get("/form_15", set()),
                    f"{scanner_cls.__name__}: Promising field 'query' (8th field) must be prioritized into the {max_fields}-field cap",
                )
                for form_path, probed_fields in fields_probed_per_form.items():
                    self.assertGreater(len(probed_fields), 0)
                    self.assertLessEqual(
                        len(probed_fields),
                        max_fields,
                        f"{scanner_cls.__name__}: Form {form_path} had {len(probed_fields)} fields probed (cap {max_fields}): {probed_fields}",
                    )


class TestAUD53CmdiSstiSsrfLfiFormScanning(unittest.TestCase):
    """AUD-53: Command injection, SSTI, SSRF, and path traversal test POST forms and ignore echo decoys."""

    def test_four_plugins_detect_simulated_post_forms_and_ignore_echo_form(self) -> None:
        app = Flask(__name__)

        @app.route("/")
        def index() -> str:
            return """
            <html><body>
                <form method="POST" action="/cmd_lab">
                    <input type="text" name="domain" value="example.com" />
                </form>
                <form method="POST" action="/ssti_lab">
                    <input type="text" name="name" value="guest" />
                </form>
                <form method="POST" action="/ssrf_lab">
                    <input type="text" name="url" value="http://example.com" />
                </form>
                <form method="POST" action="/lfi_lab">
                    <input type="text" name="file" value="readme.txt" />
                </form>
                <form method="POST" action="/echo_decoy">
                    <input type="text" name="domain" value="" />
                    <input type="text" name="name" value="" />
                    <input type="text" name="url" value="" />
                    <input type="text" name="file" value="" />
                </form>
            </body></html>
            """

        @app.route("/cmd_lab", methods=["POST"])
        def cmd_lab() -> Response:
            domain = request.form.get("domain", "")
            if "echo AUTOSEC_RCE_TEST" in domain or "AUTOSEC_$((6*7))_RCE" in domain:
                return make_response("PING 127.0.0.1\nAUTOSEC_42_RCE\ncommand output: AUTOSEC_RCE_TEST\n", 200)
            return make_response(f"Pinging {html.escape(domain)}: 0% packet loss", 200)

        @app.route("/ssti_lab", methods=["POST"])
        def ssti_lab() -> Response:
            name = request.form.get("name", "guest")
            return make_response(render_template_string(f"Hello {name}"), 200)

        @app.route("/ssrf_lab", methods=["POST"])
        def ssrf_lab() -> Response:
            url = request.form.get("url", "")
            if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
                return make_response("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\n", 200)
            return make_response("External fetch disabled in lab", 200)

        @app.route("/lfi_lab", methods=["POST"])
        def lfi_lab() -> Response:
            filename = request.form.get("file", "")
            if ".." in filename:
                return make_response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", 200)
            return make_response(f"Contents of {html.escape(filename)}: Hello World", 200)

        @app.route("/echo_decoy", methods=["POST"])
        def echo_decoy() -> Response:
            parts = [f"{k}={v}" for k, v in request.form.items()]
            return make_response("Echo: " + " | ".join(parts), 200)

        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=2)
            injectables = crawler.crawl(srv.base_url).get_injectable_endpoints()

            # (a) CommandInjectionScanner
            cmdi = CommandInjectionScanner(mock_mode=False)
            cmdi.configure(srv.base_url)
            cmdi.set_discovered_endpoints(injectables)
            with patch.object(cmdi, "_verify_timing", return_value=(False, "low", {})):
                cmdi.run()
            cmdi_findings = cmdi.parse_output()["findings"]
            self.assertEqual(len(cmdi_findings), 1, f"Expected 1 CMDI finding, got {cmdi_findings}")
            self.assertEqual(cmdi_findings[0]["endpoint"], "/cmd_lab")
            self.assertEqual(cmdi_findings[0]["param"], "domain")
            self.assertEqual(cmdi_findings[0]["method"], "POST")

            # (b) SSTIScanner
            ssti = SSTIScanner(mock_mode=False)
            ssti.configure(srv.base_url)
            ssti.set_discovered_endpoints(injectables)
            ssti.run()
            ssti_findings = ssti.parse_output()["findings"]
            self.assertEqual(len(ssti_findings), 1, f"Expected 1 SSTI finding, got {ssti_findings}")
            self.assertEqual(ssti_findings[0]["endpoint"], "/ssti_lab")
            self.assertEqual(ssti_findings[0]["param"], "name")
            self.assertEqual(ssti_findings[0]["method"], "POST")

            # (c) SSRFScanner
            ssrf = SSRFScanner(mock_mode=False)
            ssrf.configure(srv.base_url)
            ssrf.set_discovered_endpoints(injectables)
            ssrf.run()
            ssrf_findings = ssrf.parse_output()["findings"]
            self.assertEqual(len(ssrf_findings), 1, f"Expected 1 SSRF finding, got {ssrf_findings}")
            self.assertEqual(ssrf_findings[0]["endpoint"], "/ssrf_lab")
            self.assertEqual(ssrf_findings[0]["param"], "url")
            self.assertEqual(ssrf_findings[0]["method"], "POST")

            # (d) PathTraversalScanner
            lfi = PathTraversalScanner(mock_mode=False)
            lfi.configure(srv.base_url)
            lfi.set_discovered_endpoints(injectables)
            lfi.run()
            lfi_findings = lfi.parse_output()["findings"]
            self.assertEqual(len(lfi_findings), 1, f"Expected 1 LFI finding, got {lfi_findings}")
            self.assertEqual(lfi_findings[0]["endpoint"], "/lfi_lab")
            self.assertEqual(lfi_findings[0]["param"], "file")
            self.assertEqual(lfi_findings[0]["method"], "POST")

    def test_crawler_excludes_logout_and_delete_form_actions_from_injectables(self) -> None:
        """AUD-51: Forms with action=/logout or /account/delete on a neutral page never appear in forms or get_injectable_endpoints."""
        app = Flask(__name__)

        @app.route("/")
        def index() -> str:
            return """
            <html><body>
                <form action="/logout" method="POST">
                    <input type="text" name="confirm" value="1" />
                </form>
                <form action="/account/delete" method="POST">
                    <input type="text" name="reason" value="bye" />
                </form>
                <form action="/feedback" method="POST">
                    <input type="text" name="comment" value="hi" />
                </form>
            </body></html>
            """

        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)
            res = crawler.crawl(srv.base_url)
            form_paths = [f.path for f in res.forms]
            injectable_paths = [ep["path"] for ep in res.get_injectable_endpoints()]

            self.assertNotIn("/logout", form_paths)
            self.assertNotIn("/account/delete", form_paths)
            self.assertNotIn("/logout", injectable_paths)
            self.assertNotIn("/account/delete", injectable_paths)
            self.assertIn("/feedback", form_paths)
            self.assertIn("/feedback", injectable_paths)

    def test_submit_form_probe_literal_deny_pattern_blocks_dropdown_and_preset_reset(self) -> None:
        """AUD-51: Literal FORM_DENY_PATTERN refuses field named dropdown_choice and action /preset/reset."""
        app, _ = _build_aud51_app()
        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)

            with patch.object(scanner, "_safe_request", wraps=scanner._safe_request) as spy_req:
                ep_dropdown = {
                    "path": "/feedback",
                    "param": "comment",
                    "method": "POST",
                    "fields": {"comment": "hi", "dropdown_choice": "a"},
                    "enctype": "application/x-www-form-urlencoded",
                    "form_page": f"{srv.base_url}/feedback",
                    "source": "form",
                }
                self.assertIsNone(scanner.submit_form_probe(ep_dropdown, "comment", "test"))

                ep_preset = {
                    "path": "/preset/reset",
                    "param": "comment",
                    "method": "POST",
                    "fields": {"comment": "hi"},
                    "enctype": "application/x-www-form-urlencoded",
                    "form_page": f"{srv.base_url}/feedback",
                    "source": "form",
                }
                self.assertIsNone(scanner.submit_form_probe(ep_preset, "comment", "test"))
                self.assertEqual(spy_req.call_count, 0)

    def test_json_only_post_api_endpoints_detected_across_all_four_plugins(self) -> None:
        """AUD-53: Non-form POST API endpoints (no source='form' or fields) still send JSON bodies and detect vulnerabilities."""
        app = Flask(__name__)

        @app.route("/api/cmd", methods=["POST"])
        def api_cmd() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            cmd = str(data.get("command", ""))
            if "AUTOSEC_$((6*7))_RCE" in cmd or "echo AUTOSEC_RCE_TEST" in cmd:
                return make_response('{"output": "AUTOSEC_42_RCE"}', 200)
            return make_response('{"output": "ok"}', 200)

        @app.route("/api/ssti", methods=["POST"])
        def api_ssti() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            tpl = str(data.get("template", ""))
            return make_response(render_template_string(f"Result: {tpl}"), 200)

        @app.route("/api/ssrf", methods=["POST"])
        def api_ssrf() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            u = str(data.get("url", ""))
            if "127.0.0.1" in u or "localhost" in u:
                return make_response("SSH-2.0-OpenSSH_8.9p1 Ubuntu\n", 200)
            return make_response("ok", 200)

        @app.route("/api/lfi", methods=["POST"])
        def api_lfi() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            f = str(data.get("file", ""))
            if ".." in f:
                return make_response("root:x:0:0:root:/root:/bin/bash\n", 200)
            return make_response("ok", 200)

        with run_fixture_server(app) as srv:
            # 1. CommandInjectionScanner
            cmdi = CommandInjectionScanner(mock_mode=False)
            cmdi.configure(srv.base_url)
            cmdi.set_discovered_endpoints([{"path": "/api/cmd", "param": "command", "method": "POST"}])
            with patch.object(cmdi, "_verify_timing", return_value=(False, "low", {})):
                cmdi.run()
            cmdi_f = [f for f in cmdi.parse_output()["findings"] if f["endpoint"] == "/api/cmd"]
            self.assertEqual(len(cmdi_f), 1)

            # 2. SSTIScanner
            ssti = SSTIScanner(mock_mode=False)
            ssti.configure(srv.base_url)
            ssti.set_discovered_endpoints([{"path": "/api/ssti", "param": "template", "method": "POST"}])
            ssti.run()
            ssti_f = [f for f in ssti.parse_output()["findings"] if f["endpoint"] == "/api/ssti"]
            self.assertEqual(len(ssti_f), 1)

            # 3. SSRFScanner
            ssrf = SSRFScanner(mock_mode=False)
            ssrf.configure(srv.base_url)
            ssrf.set_discovered_endpoints([{"path": "/api/ssrf", "param": "url", "method": "POST"}])
            ssrf.run()
            ssrf_f = [f for f in ssrf.parse_output()["findings"] if f["endpoint"] == "/api/ssrf"]
            self.assertEqual(len(ssrf_f), 1)

            # 4. PathTraversalScanner
            lfi = PathTraversalScanner(mock_mode=False)
            lfi.configure(srv.base_url)
            lfi.set_discovered_endpoints([{"path": "/api/lfi", "param": "file", "method": "POST"}])
            lfi.run()
            lfi_f = [f for f in lfi.parse_output()["findings"] if f["endpoint"] == "/api/lfi"]
            self.assertEqual(len(lfi_f), 1)

    def test_ssrf_form_always_returning_502_yields_no_finding(self) -> None:
        """AUD-53: A form path that returns HTTP 502 for every input (including control) produces 0 SSRF findings."""
        app = Flask(__name__)

        @app.route("/")
        def index() -> str:
            return """
            <html><body>
                <form method="POST" action="/broken_gateway">
                    <input type="text" name="url" value="http://example.com" />
                </form>
            </body></html>
            """

        @app.route("/broken_gateway", methods=["POST"])
        def broken_gateway() -> Response:
            return make_response("Bad Gateway", 502)

        with run_fixture_server(app) as srv:
            crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)
            injectables = crawler.crawl(srv.base_url).get_injectable_endpoints()

            ssrf = SSRFScanner(mock_mode=False)
            ssrf.configure(srv.base_url)
            ssrf.set_discovered_endpoints(injectables)
            ssrf.run()
            self.assertEqual(len(ssrf.parse_output()["findings"]), 0)

    def test_json_only_put_api_endpoints_detected_across_plugins(self) -> None:
        """AUD-53: Non-GET JSON-only API endpoints with method='PUT' are detected across SSTI, SSRF, and LFI."""
        app = Flask(__name__)

        @app.route("/api/ssti", methods=["PUT"])
        def api_ssti_put() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            tpl = str(data.get("template", ""))
            return make_response(render_template_string(f"Result: {tpl}"), 200)

        @app.route("/api/ssrf", methods=["PUT"])
        def api_ssrf_put() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            u = str(data.get("url", ""))
            if "127.0.0.1" in u or "localhost" in u:
                return make_response("SSH-2.0-OpenSSH_8.9p1 Ubuntu\n", 200)
            return make_response("ok", 200)

        @app.route("/api/lfi", methods=["PUT"])
        def api_lfi_put() -> Response:
            if not request.is_json:
                return make_response("Expected JSON", 415)
            data = request.get_json(silent=True) or {}
            f = str(data.get("file", ""))
            if ".." in f:
                return make_response("root:x:0:0:root:/root:/bin/bash\n", 200)
            return make_response("ok", 200)

        with run_fixture_server(app) as srv:
            # 1. SSTIScanner with PUT
            ssti = SSTIScanner(mock_mode=False)
            ssti.configure(srv.base_url)
            ssti.set_discovered_endpoints([{"path": "/api/ssti", "param": "template", "method": "PUT"}])
            ssti.run()
            ssti_f = [f for f in ssti.parse_output()["findings"] if f["endpoint"] == "/api/ssti"]
            self.assertEqual(len(ssti_f), 1)
            self.assertEqual(ssti_f[0]["method"], "PUT")

            # 2. SSRFScanner with PUT
            ssrf = SSRFScanner(mock_mode=False)
            ssrf.configure(srv.base_url)
            ssrf.set_discovered_endpoints([{"path": "/api/ssrf", "param": "url", "method": "PUT"}])
            ssrf.run()
            ssrf_findings = ssrf.parse_output()["findings"]
            ssrf_f = [f for f in ssrf_findings if f["endpoint"] == "/api/ssrf"]
            self.assertEqual(len(ssrf_f), 1)
            self.assertEqual(ssrf_f[0]["method"], "PUT")

            # 3. PathTraversalScanner with PUT
            lfi = PathTraversalScanner(mock_mode=False)
            lfi.configure(srv.base_url)
            lfi.set_discovered_endpoints([{"path": "/api/lfi", "param": "file", "method": "PUT"}])
            lfi.run()
            lfi_f = [f for f in lfi.parse_output()["findings"] if f["endpoint"] == "/api/lfi"]
            self.assertEqual(len(lfi_f), 1)
            self.assertEqual(lfi_f[0]["method"], "PUT")


if __name__ == "__main__":
    unittest.main()


