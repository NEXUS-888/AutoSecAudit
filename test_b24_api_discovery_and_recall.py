"""
Tests for Batch 24: API discovery and detection recall (AUD-57, AUD-58, AUD-59).
"""

import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

from flask import Flask, request, jsonify, make_response, Response

import config
from core.engine import Engine
from core.http_client import ScanHttpClient
from core.models import Report, ScanResult, Finding
from core.openapi import OpenAPIImporter
from plugins.base_plugin import BaseScanner
from plugins.sqli_plugin import SQLiScanner
from reports.generator import ReportGenerator
from testsupport import run_fixture_server


class TestAUD57OpenAPIAutoProbeAndImport(unittest.TestCase):
    """AUD-57: Auto-probe OpenAPI/Swagger specs, import endpoints, avoid off-origin requests."""

    def test_auto_probe_openapi_discovers_and_injects_endpoints(self) -> None:
        """Fixture serving /openapi.json with 3 paths -> injection plugins receive those 3 endpoints."""
        app = Flask(__name__)

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/api/users": {
                    "get": {
                        "parameters": [{"name": "id", "in": "query", "schema": {"type": "string"}}]
                    }
                },
                "/api/products": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]
                    }
                },
                "/api/orders": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"item": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    }
                },
            },
        }

        @app.route("/")
        def index() -> str:
            return "<html><body><h1>Root</h1></body></html>"

        @app.route("/openapi.json")
        def openapi_json():
            return jsonify(spec)

        with run_fixture_server(app) as srv:
            engine = Engine(mock_mode=False)
            engine.plugins = [SQLiScanner(mock_mode=False)]
            engine.set_target(srv.base_url, check_reachable=False)

            # run_plugins should auto-probe /openapi.json since no spec was provided
            with patch.object(engine, "calibrate_spa_detector"), patch.object(SQLiScanner, "run"):
                engine.run_plugins()

            # The plugin's discovered endpoints must include the 3 openapi endpoints
            sqli_plugin = engine.plugins[0]
            discovered = sqli_plugin.discovered_endpoints or []
            discovered_paths = {ep.get("path") for ep in discovered if isinstance(ep, dict)}

            self.assertIn("/api/users", discovered_paths)
            self.assertIn("/api/products", discovered_paths)
            self.assertIn("/api/orders", discovered_paths)

    def test_openapi_servers_pointing_off_origin_ignored(self) -> None:
        """A spec whose servers lists http://evil.example -> every request still goes to fixture origin."""
        import urllib.parse
        app = Flask(__name__)
        fixture_received_paths = []

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Off-Origin Test API", "version": "1.0"},
            "servers": [{"url": "http://evil.example/v1"}],
            "paths": {
                "/items": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]
                    }
                }
            },
        }

        @app.before_request
        def before_req():
            fixture_received_paths.append(request.path)

        @app.route("/")
        def index() -> str:
            return "<html><body>OK</body></html>"

        @app.route("/openapi.json")
        def openapi_json():
            return jsonify(spec)

        @app.route("/v1/items")
        @app.route("/items")
        def items():
            return jsonify({"items": []})

        with run_fixture_server(app) as srv:
            fixture_netloc = urllib.parse.urlparse(srv.base_url).netloc

            engine = Engine(mock_mode=False)
            sqli_plugin = SQLiScanner(mock_mode=False)
            engine.plugins = [sqli_plugin]
            engine.set_target(srv.base_url, check_reachable=False)

            # Spy on ScanHttpClient.request to record every requested URL
            recorded_urls = []
            orig_request = ScanHttpClient.request

            def spy_request(self_client, method, url, *args, **kwargs):
                recorded_urls.append(url)
                return orig_request(self_client, method, url, *args, **kwargs)

            with patch.object(ScanHttpClient, "request", new=spy_request), \
                 patch.object(engine, "calibrate_spa_detector"), \
                 patch.object(sqli_plugin, "_test_login_endpoints"), \
                 patch.object(sqli_plugin, "_test_url_path_injection"), \
                 patch.object(sqli_plugin, "_test_json_body_sqli"):
                engine.run_plugins()

            # Confirm every requested URL went strictly to the fixture netloc
            self.assertGreater(len(recorded_urls), 0, "Expected HTTP requests to be recorded by spy")
            for u in recorded_urls:
                parsed = urllib.parse.urlparse(u)
                self.assertEqual(
                    parsed.netloc,
                    fixture_netloc,
                    f"Request URL {u} targeted {parsed.netloc}, expected fixture netloc {fixture_netloc}",
                )

            # Also assert the fixture received a request to the imported path
            self.assertTrue(any("items" in p for p in fixture_received_paths), f"Expected items path in {fixture_received_paths}")

    def test_invalid_json_spec_ignored_without_error(self) -> None:
        """Invalid JSON at /openapi.json is ignored without error."""
        app = Flask(__name__)

        @app.route("/")
        def index() -> str:
            return "<html><body>OK</body></html>"

        @app.route("/openapi.json")
        def openapi_json() -> Response:
            return make_response("not-json {broken: yes", 200, {"Content-Type": "application/json"})

        with run_fixture_server(app) as srv:
            engine = Engine(mock_mode=False)
            engine.plugins = [SQLiScanner(mock_mode=False)]
            engine.set_target(srv.base_url, check_reachable=False)

            with patch.object(engine, "calibrate_spa_detector"), patch.object(SQLiScanner, "run"):
                engine.run_plugins()

            # Engine should finish without raising an error
            self.assertIsNotNone(engine.scan_results)

    def test_explicit_openapi_spec_skips_auto_probe(self) -> None:
        """When an explicit spec was supplied, auto-probe makes no spec probe requests."""
        app = Flask(__name__)
        probe_requests = []

        @app.route("/openapi.json")
        @app.route("/swagger.json")
        @app.route("/v2/api-docs")
        @app.route("/v3/api-docs")
        @app.route("/api-docs")
        @app.route("/openapi.yaml")
        def spec_probe() -> Response:
            probe_requests.append(request.path)
            return make_response("{}", 200)

        @app.route("/")
        def index() -> str:
            return "<html><body>Root</body></html>"

        with run_fixture_server(app) as srv:
            engine = Engine(mock_mode=False)
            engine.plugins = [SQLiScanner(mock_mode=False)]
            engine.set_target(srv.base_url, check_reachable=False)

            # Explicit spec supplied via add_endpoints without manually setting engine.explicit_openapi
            explicit_eps = [{"path": "/explicit", "param": "id", "method": "GET"}]
            engine.add_endpoints(explicit_eps)

            with patch.object(engine, "calibrate_spa_detector"), patch.object(SQLiScanner, "run"):
                engine.run_plugins()

            self.assertEqual(
                probe_requests,
                [],
                f"Expected no auto-probe requests when explicit spec is supplied, got: {probe_requests}",
            )

    def test_explicit_openapi_spec_that_fails_still_skips_probe(self) -> None:
        """Running run_scan_pipeline with an openapi_spec that fails/has 0 paths makes no probe requests."""
        from core.pipeline import run_scan_pipeline, ScanRequest

        app = Flask(__name__)
        probe_paths = [
            "/openapi.json",
            "/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api-docs",
            "/openapi.yaml",
        ]
        probe_requests = []

        @app.before_request
        def before_req():
            if request.path in probe_paths:
                probe_requests.append(request.path)

        @app.route("/")
        def index() -> str:
            return "<html><body>Root</body></html>"

        for p in probe_paths:
            app.add_url_rule(p, p, lambda: jsonify({}))

        class TestEngine(Engine):
            def load_plugins(self, *args, **kwargs):
                self.plugins = [SQLiScanner(mock_mode=False)]
                return 1

        with run_fixture_server(app) as srv:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                f.write("not-valid-json")
                bad_spec_file = f.name

            try:
                # Positive control: openapi_spec=None hits >=1 probe path with non-empty plugin list
                req_control = ScanRequest(
                    target=srv.base_url,
                    openapi_spec=None,
                    mock_mode=False,
                    skip_reachability=True,
                )
                with patch.object(TestEngine, "calibrate_spa_detector"), patch.object(SQLiScanner, "run"):
                    run_scan_pipeline(req_control, engine_cls=TestEngine, generator_cls=ReportGenerator)

                self.assertGreaterEqual(
                    len(probe_requests),
                    1,
                    f"Expected positive control (openapi_spec=None) to probe at least 1 OpenAPI path, got: {probe_requests}",
                )

                # Negative case: explicit bad spec with non-empty plugin list hits none
                probe_requests.clear()
                req_negative = ScanRequest(
                    target=srv.base_url,
                    openapi_spec=bad_spec_file,
                    mock_mode=False,
                    skip_reachability=True,
                )
                with patch.object(TestEngine, "calibrate_spa_detector"), patch.object(SQLiScanner, "run"):
                    run_scan_pipeline(req_negative, engine_cls=TestEngine, generator_cls=ReportGenerator)

                self.assertEqual(
                    probe_requests,
                    [],
                    f"Expected no probe requests when explicit openapi_spec is supplied, got: {probe_requests}",
                )
            finally:
                if os.path.exists(bad_spec_file):
                    os.remove(bad_spec_file)


class TestAUD58SQLiErrorStatusDifferential(unittest.TestCase):
    """AUD-58: SQL injection detection on bare 500 status differential."""

    def test_error_status_differential_reported_at_medium_confidence(self) -> None:
        """Endpoint returning 500 on ' and 200 on '' is reported as SQLi with medium confidence."""
        app = Flask(__name__)

        @app.route("/search")
        def search() -> Response:
            q = request.args.get("q", "")
            if q == "'":
                # Bare 500 with generic error page
                return make_response("Internal Server Error", 500)
            # Normal response for control and doubled quote
            return make_response(f"Results for: {q}", 200)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([{"path": "/search", "param": "q", "method": "GET"}])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
                patch.object(scanner, "_test_json_body_sqli"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = output.get("findings", [])
            sqli_findings = [f for f in findings if f.get("vuln_type") == "sqli"]

            self.assertGreaterEqual(len(sqli_findings), 1, "Expected differential SQLi finding")
            found = sqli_findings[0]
            self.assertEqual(found.get("confidence"), "medium")
            self.assertIn("error status differential", (found.get("title", "") + " " + found.get("description", "")).lower())

    def test_always_500_not_reported(self) -> None:
        """Endpoint that always returns 500 is not reported as SQLi."""
        app = Flask(__name__)

        @app.route("/broken")
        def broken() -> Response:
            return make_response("Always down", 500)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([{"path": "/broken", "param": "id", "method": "GET"}])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
                patch.object(scanner, "_test_json_body_sqli"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertEqual(len(findings), 0, f"Must not report SQLi when endpoint always returns 500: {findings}")

    def test_500_on_any_special_char_not_reported(self) -> None:
        """Endpoint returning 500 on any special character including '' is not reported."""
        app = Flask(__name__)

        @app.route("/strict")
        def strict() -> Response:
            val = request.args.get("val", "")
            # Fails on any quote
            if "'" in val:
                return make_response("Invalid input", 500)
            return make_response("OK", 200)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([{"path": "/strict", "param": "val", "method": "GET"}])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
                patch.object(scanner, "_test_json_body_sqli"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertEqual(len(findings), 0, f"Must not report SQLi when '' also gives 500: {findings}")

    def test_signature_based_sqli_still_detected(self) -> None:
        """Existing signature-based detection still functions alongside differential check."""
        app = Flask(__name__)

        @app.route("/sqli_leak")
        def sqli_leak() -> Response:
            q = request.args.get("q", "")
            if "'" in q:
                return make_response("syntax error at or near 'SELECT'", 500)
            return make_response("Normal", 200)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([{"path": "/sqli_leak", "param": "q", "method": "GET"}])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
                patch.object(scanner, "_test_json_body_sqli"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertGreaterEqual(len(findings), 1, "Expected signature-based SQLi finding")

    def test_json_post_differential_sqli_reported_at_medium_confidence(self) -> None:
        """JSON POST endpoint returning 500 on ' and 200 on '' is reported with medium confidence."""
        app = Flask(__name__)

        @app.route("/api/user_json", methods=["POST"])
        def user_json():
            data = request.get_json(silent=True) or {}
            val = str(data.get("username", ""))
            if val == "'":
                return make_response("Database syntax error", 500)
            return jsonify({"status": "ok", "user": val})

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {"path": "/api/user_json", "param": "username", "method": "POST"}
            ])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertGreaterEqual(len(findings), 1, "Expected differential SQLi finding for JSON POST")
            found = findings[0]
            self.assertEqual(found.get("confidence"), "medium")
            self.assertIn("error status differential", (found.get("title", "") + " " + found.get("description", "")).lower())

    def test_json_post_differential_sqli_500_on_doubled_quote_not_reported(self) -> None:
        """JSON POST endpoint returning 500 on '' too is not reported."""
        app = Flask(__name__)

        @app.route("/api/user_strict_json", methods=["POST"])
        def user_strict_json():
            data = request.get_json(silent=True) or {}
            val = str(data.get("username", ""))
            if "'" in val:
                return make_response("Server Error", 500)
            return jsonify({"status": "ok"})

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {"path": "/api/user_strict_json", "param": "username", "method": "POST"}
            ])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertEqual(len(findings), 0, f"Must not report SQLi when '' gives 500: {findings}")

    def test_form_differential_sqli_reported_at_medium_confidence(self) -> None:
        """Form endpoint via submit_form_probe returning 500 on ' and 200 on '' is reported at medium confidence."""
        app = Flask(__name__)

        @app.route("/form_post", methods=["GET", "POST"])
        def form_post():
            if request.method == "GET":
                return '<form action="/form_post" method="POST"><input name="user"><input type="submit"></form>'
            val = request.form.get("user", "")
            if val == "'":
                return make_response("Error", 500)
            return make_response("Welcome", 200)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {
                    "path": "/form_post",
                    "param": "user",
                    "method": "POST",
                    "source": "form",
                    "form_page": "/form_post",
                    "form_action": "/form_post",
                    "fields": {"user": "test"},
                }
            ])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
                patch.object(scanner, "_test_json_body_sqli"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertGreaterEqual(len(findings), 1, "Expected differential SQLi finding on form")
            found = findings[0]
            self.assertEqual(found.get("confidence"), "medium")
            self.assertIn("error status differential", (found.get("title", "") + " " + found.get("description", "")).lower())

    def test_form_differential_sqli_500_on_doubled_quote_not_reported(self) -> None:
        """Form endpoint via submit_form_probe returning 500 on '' too is not reported."""
        app = Flask(__name__)

        @app.route("/form_strict", methods=["GET", "POST"])
        def form_strict():
            if request.method == "GET":
                return '<form action="/form_strict" method="POST"><input name="user"><input type="submit"></form>'
            val = request.form.get("user", "")
            if "'" in val:
                return make_response("Error", 500)
            return make_response("Welcome", 200)

        with run_fixture_server(app) as srv:
            scanner = SQLiScanner(mock_mode=False)
            scanner.configure(srv.base_url)
            scanner.set_discovered_endpoints([
                {
                    "path": "/form_strict",
                    "param": "user",
                    "method": "POST",
                    "source": "form",
                    "form_page": "/form_strict",
                    "form_action": "/form_strict",
                    "fields": {"user": "test"},
                }
            ])
            with (
                patch.object(scanner, "_test_login_endpoints"),
                patch.object(scanner, "_test_url_path_injection"),
                patch.object(scanner, "_test_json_body_sqli"),
            ):
                scanner.run()

            output = scanner.parse_output()
            findings = [f for f in output.get("findings", []) if f.get("vuln_type") == "sqli"]
            self.assertEqual(len(findings), 0, f"Must not report SQLi when '' gives 500: {findings}")


class TestAUD59CoverageReportingAndDegradedStatus(unittest.TestCase):
    """AUD-59: Report.coverage tracking, degraded status, CLI warning, HTML banner, config bounds."""

    def test_http_client_counters_thread_safe_under_100_threads(self) -> None:
        """Counters stay exact under 100 concurrent threads."""
        client = ScanHttpClient(target="http://127.0.0.1:8080")
        threads = []

        def worker():
            for _ in range(50):
                client.increment_requests_total()
                client.increment_requests_failed()
                client.increment_requests_skipped_deadline()

        for _ in range(100):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(client.requests_total, 5000)
        self.assertEqual(client.requests_failed, 5000)
        self.assertEqual(client.requests_skipped_deadline, 5000)

    def test_report_round_trips_with_and_without_coverage(self) -> None:
        """Report round-trips with and without coverage."""
        cov_data = {
            "requests_total": 100,
            "requests_failed": 2,
            "requests_skipped_deadline": 0,
            "plugins_timed_out": 0,
            "plugins_skipped": 0,
            "crawl": {"pages_visited": 10, "forms": 2, "fetch_failures": 0, "start_ok": True},
            "duration_seconds": 12.345,
            "per_plugin_seconds": {"SQLiScanner": 5.12},
            "degraded": False,
        }

        # 1. With coverage
        rep = Report(
            target="http://localhost:3000",
            timestamp="2026-10-13 12:00:00",
            coverage=cov_data,
        )
        d = rep.to_dict()
        self.assertEqual(d["coverage"], cov_data)

        reconstructed = Report.from_dict(d)
        self.assertEqual(reconstructed.coverage, cov_data)

        # 2. Without coverage (old report compatibility)
        old_dict = {
            "target": "http://localhost:3000",
            "timestamp": "2026-10-13 12:00:00",
            "scan_results": [],
            "all_findings": [],
            "summary": {},
        }
        old_rep = Report.from_dict(old_dict)
        self.assertIsNone(old_rep.coverage)
        self.assertIsNone(old_rep.to_dict().get("coverage"))

    def test_clean_mock_scan_degraded_false(self) -> None:
        """A clean mock scan yields degraded=False in report.coverage."""
        engine = Engine(mock_mode=True)
        engine.load_plugins()
        engine.set_target("http://localhost:3000", check_reachable=False)
        engine.run_plugins()
        report = engine.generate_report()

        self.assertIsNotNone(report.coverage)
        self.assertFalse(report.coverage["degraded"])
        self.assertEqual(report.coverage["plugins_timed_out"], 0)

    def test_http_client_concurrent_requests_against_fixture(self) -> None:
        """Concurrent request() calls against a live fixture server maintain accurate counters."""
        app = Flask(__name__)
        @app.route("/ping")
        def ping():
            return "pong"

        with run_fixture_server(app) as srv:
            client = ScanHttpClient(target=srv.base_url)
            threads = []
            success_count = [0]
            lock = threading.Lock()

            def worker():
                for _ in range(10):
                    resp = client.request("GET", f"{srv.base_url}/ping")
                    if resp is not None and resp.status_code == 200:
                        with lock:
                            success_count[0] += 1

            for _ in range(10):
                t = threading.Thread(target=worker)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            self.assertEqual(client.requests_total, 100)
            self.assertEqual(client.requests_failed + success_count[0], 100)

    def test_fake_slow_plugin_exceeds_deadline_degraded_true_and_cli_warning(self) -> None:
        """A fake slow plugin that exceeds a tiny deadline yields degraded=True and CLI warning."""
        class SlowPlugin(BaseScanner):
            def _get_tool_name(self) -> str:
                return "python-requests"
            def _get_mock_output(self):
                return {}
            def configure(self, target: str) -> None:
                pass
            def run(self):
                time.sleep(1.0)
            def parse_output(self):
                return {"tool_name": "python-requests", "findings": []}

        engine = Engine(mock_mode=False)
        engine.plugins = [SlowPlugin(mock_mode=False)]
        engine.set_target("http://127.0.0.1:8080", check_reachable=False)
        engine.scan_timeout = 0.1

        with patch.object(engine, "calibrate_spa_detector"):
            engine.run_plugins()

        report = engine.generate_report()
        self.assertIsNotNone(report.coverage)
        self.assertTrue(report.coverage["degraded"])
        self.assertGreaterEqual(report.coverage["plugins_timed_out"], 1)

        # Verify CLI warning is printed via main.run_scan
        import main
        captured_stdout = io.StringIO()
        with patch.object(Engine, "generate_report", return_value=report), \
             patch("sys.stdout", captured_stdout), \
             patch("main.run_scan_pipeline") as mock_pipeline:
            mock_pipeline.return_value = (report, MagicMock(json="r.json", html="r.html"))
            main.run_scan("http://127.0.0.1:8080", skip_reachability=True)

        stdout_text = captured_stdout.getvalue()
        self.assertIn("degraded", stdout_text.lower())

    def test_html_report_shows_banner_only_when_degraded(self) -> None:
        """The HTML report contains the banner text only when degraded."""
        generator = ReportGenerator()
        default_summary = {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "throttled_requests": 0
        }

        # 1. Degraded report
        degraded_rep = Report(
            target="http://localhost:3000",
            timestamp="2026-10-13 12:00:00",
            summary=default_summary,
            coverage={"degraded": True, "requests_total": 10, "requests_failed": 5},
        )
        html_degraded = generator.generate_html(degraded_rep)
        self.assertIn("Scan Coverage Degraded", html_degraded)

        # 2. Non-degraded report
        clean_rep = Report(
            target="http://localhost:3000",
            timestamp="2026-10-13 12:00:00",
            summary=default_summary,
            coverage={"degraded": False, "requests_total": 10, "requests_failed": 0},
        )
        html_clean = generator.generate_html(clean_rep)
        self.assertNotIn("Scan Coverage Degraded", html_clean)

    def test_engine_deadline_uses_scan_deadline_seconds(self) -> None:
        """Patched config.SCAN_DEADLINE_SECONDS = 45 with scan_timeout=None sets http_client.deadline to ~45s."""
        class DummyPlugin(BaseScanner):
            def _get_tool_name(self): return "python-requests"
            def _get_mock_output(self): return {}
            def configure(self, target): pass
            def run(self): pass
            def parse_output(self): return {}

        engine = Engine(mock_mode=False)
        engine.plugins = [DummyPlugin(mock_mode=False)]
        engine.set_target("http://127.0.0.1:8080", check_reachable=False)
        engine.scan_timeout = None

        with patch("config.SCAN_DEADLINE_SECONDS", 45), \
             patch("core.engine.WebCrawler.crawl", return_value=MagicMock(get_injectable_endpoints=lambda: [], get_login_endpoints=lambda: [])):
            start = time.monotonic()
            engine.run_plugins()
            self.assertIsNotNone(engine.http_client.deadline)
            diff = engine.http_client.deadline - start
            self.assertAlmostEqual(diff, 45.0, delta=1.5)

    def test_config_scan_deadline_seconds_env_bounds_and_warning(self) -> None:
        """config.SCAN_DEADLINE_SECONDS (default 300, range 30-3600), invalid -> default with warning."""
        import importlib

        try:
            # 1. Default when unset
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUTOSEC_SCAN_DEADLINE_SECONDS", None)
                importlib.reload(config)
                self.assertEqual(config.SCAN_DEADLINE_SECONDS, 300)

            # 2. Valid override
            with patch.dict(os.environ, {"AUTOSEC_SCAN_DEADLINE_SECONDS": "600"}):
                importlib.reload(config)
                self.assertEqual(config.SCAN_DEADLINE_SECONDS, 600)

            # 3. Out of range (20 and 5000) and invalid non-integer ('abc')
            for bad_val in ("20", "5000", "abc"):
                with patch.dict(os.environ, {"AUTOSEC_SCAN_DEADLINE_SECONDS": bad_val}):
                    with self.assertLogs("config", level="WARNING") as cm:
                        importlib.reload(config)
                    self.assertEqual(config.SCAN_DEADLINE_SECONDS, 300)
                    self.assertGreaterEqual(len(cm.output), 1)
        finally:
            # Restore defaults
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUTOSEC_SCAN_DEADLINE_SECONDS", None)
                importlib.reload(config)


if __name__ == "__main__":
    unittest.main()
