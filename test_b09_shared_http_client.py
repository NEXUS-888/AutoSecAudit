import unittest
from unittest.mock import MagicMock, patch, call
import requests

from core.http_client import ScanHttpClient
from core.politeness import PolitenessEngine
from plugins.base_plugin import BaseScanner
from core.engine import Engine


class DummyTestScanner(BaseScanner):
    """Concrete test scanner for testing BaseScanner delegates."""
    def _get_tool_name(self) -> str:
        return "dummy"

    def _get_mock_output(self):
        return {"findings": []}

    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        pass

    def parse_output(self):
        return {"findings": []}


class TestB09SharedHttpClient(unittest.TestCase):
    # -----------------------------------------------------------------------
    # AUD-25: Shared, scope-aware HTTP client
    # -----------------------------------------------------------------------
    def test_aud25_redirect_to_out_of_scope_host_not_followed(self):
        """AUD-25: A redirect to an out-of-scope host is not followed."""
        client = ScanHttpClient(target="http://localhost:3000")

        # Mock session.send or session.get
        resp_302 = MagicMock(spec=requests.Response)
        resp_302.status_code = 302
        resp_302.url = "http://localhost:3000/redirect"
        resp_302.headers = {"Location": "http://evil.com/exfiltrate"}
        resp_302.history = []

        client.session.send = MagicMock(return_value=resp_302)

        # Execute request that triggers 302 to evil.com
        resp = client.request("GET", "http://localhost:3000/redirect", allow_redirects=True)

        # Verify evil.com was never requested
        self.assertEqual(resp.status_code, 302)
        for send_call in client.session.send.call_args_list:
            req = send_call[0][0]
            self.assertNotIn("evil.com", req.url, f"Out-of-scope host evil.com was requested: {req.url}")

    def test_aud25_redirect_to_same_origin_is_followed(self):
        """AUD-25: A redirect to same origin is followed."""
        client = ScanHttpClient(target="http://localhost:3000")

        resp_302 = MagicMock(spec=requests.Response)
        resp_302.status_code = 302
        resp_302.url = "http://localhost:3000/old"
        resp_302.headers = {"Location": "/dashboard"}
        resp_302.history = []

        resp_200 = MagicMock(spec=requests.Response)
        resp_200.status_code = 200
        resp_200.url = "http://localhost:3000/dashboard"
        resp_200.headers = {"Content-Type": "text/html"}
        resp_200.text = "Dashboard Content"
        resp_200.history = [resp_302]

        def mock_send(prepared_req, *args, **kwargs):
            if "dashboard" in prepared_req.url:
                return resp_200
            return resp_302

        client.session.send = MagicMock(side_effect=mock_send)

        resp = client.request("GET", "http://localhost:3000/old", allow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.url, "http://localhost:3000/dashboard")

    def test_aud25_user_agent_is_constant_across_requests(self):
        """AUD-25: The User-Agent is constant across requests (no rotation)."""
        client = ScanHttpClient(target="http://localhost:3000")

        sent_uas = []
        resp_200 = MagicMock(spec=requests.Response)
        resp_200.status_code = 200
        resp_200.headers = {}
        resp_200.history = []

        def mock_send(prep_req, *args, **kwargs):
            sent_uas.append(prep_req.headers.get("User-Agent"))
            return resp_200

        client.session.send = MagicMock(side_effect=mock_send)

        for _ in range(5):
            client.request("GET", "http://localhost:3000/page")

        self.assertEqual(len(sent_uas), 5)
        self.assertTrue(all(ua == "AutoSecAudit/2.0" for ua in sent_uas), f"User-Agent varied: {sent_uas}")

    def test_aud25_base_scanner_safe_request_signature_and_delegation(self):
        """AUD-25: BaseScanner._safe_request signature is unchanged and delegates to shared client."""
        scanner = DummyTestScanner(mock_mode=False)
        shared_client = ScanHttpClient(target="http://localhost:3000")
        scanner.set_http_client(shared_client)

        resp_mock = MagicMock(spec=requests.Response)
        resp_mock.status_code = 200
        resp_mock.headers = {}
        resp_mock.history = []

        shared_client.session.send = MagicMock(return_value=resp_mock)

        resp = scanner._safe_request(
            method="POST",
            url="http://localhost:3000/api/test",
            params={"q": "search"},
            json_data={"data": 123},
            headers={"X-Custom": "value"},
            timeout=(2.0, 5.0),
            allow_redirects=True
        )

        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)

    def test_aud25_engine_injects_http_client_into_plugins(self):
        """AUD-25: Engine owns ScanHttpClient and injects it with auth headers into plugins."""
        engine = Engine(mock_mode=False)
        engine.set_target("http://localhost:3000")
        engine.set_custom_headers({"X-Custom-Auth": "SecretToken123"})

        scanner = DummyTestScanner(mock_mode=False)
        engine.plugins = [scanner]

        # Simulate engine run_plugins preparation
        engine.setup_shared_http_client()

        self.assertIsNotNone(scanner.http)
        self.assertIs(scanner.http, engine.http_client)
        self.assertEqual(scanner.http.session.headers.get("X-Custom-Auth"), "SecretToken123")

    # -----------------------------------------------------------------------
    # AUD-26: 429/503 retry and politeness handling
    # -----------------------------------------------------------------------
    def test_aud26_server_returning_429_once_then_200_returns_200(self):
        """AUD-26: A server returning 429 once then 200 -> _safe_request returns the 200."""
        scanner = DummyTestScanner(mock_mode=False)
        client = ScanHttpClient(target="http://localhost:3000", max_retries_on_429=2)
        scanner.set_http_client(client)

        resp_429 = MagicMock(spec=requests.Response)
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "0.01"}
        resp_429.history = []

        resp_200 = MagicMock(spec=requests.Response)
        resp_200.status_code = 200
        resp_200.headers = {}
        resp_200.history = []

        responses = [resp_429, resp_200]
        client.session.send = MagicMock(side_effect=lambda req, *a, **kw: responses.pop(0))

        resp = scanner._safe_request("GET", "http://localhost:3000/rate-limited")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)

    def test_aud26_always_429_server_returns_none_and_counts_throttled(self):
        """AUD-26: An always-429 server -> None, never fed to plugin detection logic."""
        scanner = DummyTestScanner(mock_mode=False)
        client = ScanHttpClient(target="http://localhost:3000", max_retries_on_429=2)
        scanner.set_http_client(client)

        resp_429 = MagicMock(spec=requests.Response)
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "0.01"}
        resp_429.history = []

        client.session.send = MagicMock(return_value=resp_429)

        resp = scanner._safe_request("GET", "http://localhost:3000/blocked")
        self.assertIsNone(resp, "Always-429 server must return None to plugin logic")
        self.assertGreater(client.throttled_count, 0)

    @patch("time.sleep")
    def test_aud26_always_503_server_returns_none(self, mock_sleep):
        """AUD-26: An always-503 server -> None, session.send mocked, retries counted, throttled_count incremented."""
        client = ScanHttpClient(target="http://localhost:3000", max_retries_on_429=2)

        resp_503 = MagicMock(spec=requests.Response)
        resp_503.status_code = 503
        resp_503.headers = {"Retry-After": "0.01"}
        resp_503.history = []

        client.session.send = MagicMock(return_value=resp_503)

        initial_throttled = client.throttled_count
        resp = client.request("GET", "http://localhost:3000/service-unavailable")

        self.assertIsNone(resp, "Always-503 server must return None to caller")
        self.assertEqual(client.session.send.call_count, client.max_retries_on_429 + 1)
        self.assertEqual(client.throttled_count, initial_throttled + 1)

    @patch("time.sleep")
    def test_aud26_single_source_of_truth_max_retries(self, mock_sleep):
        """AUD-26: ScanHttpClient uses PolitenessEngine.max_retries_on_429 as default."""
        politeness = PolitenessEngine(max_retries_on_429=1)
        client = ScanHttpClient(target="http://localhost:3000", politeness=politeness)

        resp_429 = MagicMock(spec=requests.Response)
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "0.01"}
        resp_429.history = []

        client.session.send = MagicMock(return_value=resp_429)

        resp = client.request("GET", "http://localhost:3000/test")
        self.assertIsNone(resp)
        self.assertEqual(client.session.send.call_count, 2)

    @patch("time.sleep")
    def test_aud26_engine_exposes_throttled_requests_in_report(self, mock_sleep):
        """AUD-26: Engine exposes throttled_requests count in Report summary and report dict."""
        engine = Engine(mock_mode=False)
        engine.set_target("http://localhost:3000", check_reachable=False)

        resp_429 = MagicMock(spec=requests.Response)
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "0.01"}
        resp_429.history = []

        engine.http_client.session.send = MagicMock(return_value=resp_429)

        scanner = DummyTestScanner(mock_mode=False)
        engine.plugins = [scanner]
        engine.setup_shared_http_client()

        # Scanner makes a request that gets throttled
        resp = scanner._safe_request("GET", "http://localhost:3000/api")
        self.assertIsNone(resp)

        report = engine.generate_report()
        report_dict = report.to_dict()

        self.assertGreater(report.throttled_requests, 0)
        self.assertIn("throttled_requests", report_dict)
        self.assertEqual(report_dict["throttled_requests"], report.throttled_requests)
        self.assertIn("throttled_requests", report.summary)
        self.assertEqual(report.summary["throttled_requests"], report.throttled_requests)

    def test_aud25_live_local_server_redirect_to_out_of_scope_not_followed(self):
        """AUD-25: Live local HTTP server redirect to out-of-scope host is not followed."""
        import http.server
        import threading

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect-out":
                    self.send_response(302)
                    self.send_header("Location", "http://example.com/out-of-scope")
                    self.end_headers()
                elif self.path == "/redirect-in":
                    self.send_response(302)
                    self.send_header("Location", "/in-scope-target")
                    self.end_headers()
                elif self.path == "/in-scope-target":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"in-scope ok")
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"
            client = ScanHttpClient(target=base_url)

            # 1. Out of scope redirect: should NOT follow to example.com
            resp = client.request("GET", f"{base_url}/redirect-out", allow_redirects=True)
            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("example.com", resp.headers.get("Location", ""))
            self.assertEqual(len(resp.history), 0)

            # 2. In scope redirect: SHOULD follow
            resp_in = client.request("GET", f"{base_url}/redirect-in", allow_redirects=True)
            self.assertIsNotNone(resp_in)
            self.assertEqual(resp_in.status_code, 200)
            self.assertEqual(resp_in.text, "in-scope ok")
            self.assertEqual(len(resp_in.history), 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_aud25_malformed_redirect_port_out_of_range_does_not_raise(self):
        """AUD-25: A redirect with malformed port (99999) returns 302 without raising ValueError."""
        import http.server
        import threading

        class BadPortRedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:99999/overflow")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), BadPortRedirectHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"
            client = ScanHttpClient(target=base_url)

            # Must not raise ValueError or crash plugin
            resp = client.request("GET", f"{base_url}/redirect-bad-port", allow_redirects=True)
            if resp is not None:
                self.assertEqual(resp.status_code, 302)
                self.assertIn("99999", resp.headers.get("Location", ""))
        finally:
            server.shutdown()
            server.server_close()

    def test_aud25_concurrent_requests_global_rate_limiting(self):
        """AUD-25: 10 concurrent requests from ThreadPoolExecutor are spaced by >= ~90ms."""
        import http.server
        import socketserver
        import threading
        import time
        from concurrent.futures import ThreadPoolExecutor

        arrivals = []
        arrivals_lock = threading.Lock()

        class PacingHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                with arrivals_lock:
                    arrivals.append(time.monotonic())
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format, *args):
                pass

        class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            request_queue_size = 32

        server = ThreadedServer(("127.0.0.1", 0), PacingHandler)
        port = server.server_port
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"
            politeness = PolitenessEngine(request_interval_ms=100)
            client = ScanHttpClient(target=base_url, politeness=politeness)

            # Warm up connection pool
            client.request("GET", f"{base_url}/warmup")
            with arrivals_lock:
                arrivals.clear()

            def make_request(idx):
                return client.request("GET", f"{base_url}/test-{idx}")

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request, i) for i in range(10)]
                for f in futures:
                    resp = f.result()
                    self.assertIsNotNone(resp)
                    self.assertEqual(resp.status_code, 200)

            self.assertEqual(len(arrivals), 10)
            sorted_arrivals = sorted(arrivals)
            gaps = [sorted_arrivals[i + 1] - sorted_arrivals[i] for i in range(len(sorted_arrivals) - 1)]
            for idx, gap in enumerate(gaps):
                self.assertGreaterEqual(
                    gap,
                    0.070,
                    f"Gap between request {idx} and {idx+1} was too small: {gap*1000:.1f}ms < 70ms",
                )
            mean_gap = sum(gaps) / len(gaps)
            self.assertGreaterEqual(
                mean_gap,
                0.090,
                f"Mean gap across requests was too small: {mean_gap*1000:.1f}ms < 90ms",
            )
        finally:
            server.shutdown()
            server.server_close()

    def test_aud25_engine_default_request_interval_is_positive(self):
        """AUD-25: Engine(mock_mode=False).http_client.politeness.request_interval_ms > 0."""
        engine = Engine(mock_mode=False)
        self.assertGreater(
            engine.http_client.politeness.request_interval_ms,
            0,
            "Engine http_client politeness request_interval_ms must be > 0 by default",
        )

    def test_aud25_engine_http_client_concurrent_requests_paced_by_default_interval(self):
        """AUD-25: Concurrent requests through Engine().http_client at a local server space by about default interval."""
        import http.server
        import socketserver
        import threading
        import time
        from concurrent.futures import ThreadPoolExecutor

        arrivals = []
        arrivals_lock = threading.Lock()

        class EnginePacingHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                with arrivals_lock:
                    arrivals.append(time.monotonic())
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format, *args):
                pass

        class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            request_queue_size = 32

        server = ThreadedServer(("127.0.0.1", 0), EnginePacingHandler)
        port = server.server_port
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"
            engine = Engine(mock_mode=False)
            engine.set_target(base_url)

            # Warm up
            engine.http_client.request("GET", f"{base_url}/warmup")
            with arrivals_lock:
                arrivals.clear()

            def make_request(idx):
                return engine.http_client.request("GET", f"{base_url}/test-{idx}")

            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = [executor.submit(make_request, i) for i in range(6)]
                for f in futures:
                    resp = f.result()
                    self.assertIsNotNone(resp)
                    self.assertEqual(resp.status_code, 200)

            self.assertEqual(len(arrivals), 6)
            sorted_arrivals = sorted(arrivals)
            gaps = [sorted_arrivals[i + 1] - sorted_arrivals[i] for i in range(len(sorted_arrivals) - 1)]
            interval = engine.http_client.politeness.request_interval_ms / 1000.0
            min_allowed_gap = interval * 0.5
            mean_allowed_gap = interval * 0.75
            for idx, gap in enumerate(gaps):
                self.assertGreaterEqual(
                    gap,
                    min_allowed_gap,
                    f"Gap between request {idx} and {idx+1} was too small: {gap*1000:.1f}ms < {min_allowed_gap*1000:.1f}ms",
                )
            mean_gap = sum(gaps) / len(gaps)
            self.assertGreaterEqual(
                mean_gap,
                mean_allowed_gap,
                f"Mean gap across requests was too small: {mean_gap*1000:.1f}ms < {mean_allowed_gap*1000:.1f}ms",
            )
        finally:
            server.shutdown()
            server.server_close()

    def test_aud25_jitter_fallback_runs_when_max_jitter_positive(self):
        """AUD-25: Jitter fallback runs when request_interval_ms=0 and max_jitter_ms > 0."""
        politeness = PolitenessEngine(request_interval_ms=0, min_jitter_ms=0, max_jitter_ms=25)
        with patch("time.sleep") as mock_sleep:
            politeness.pace_request()
            self.assertTrue(mock_sleep.called)
            sleep_arg = mock_sleep.call_args[0][0]
            self.assertGreaterEqual(sleep_arg, 0.0)
            self.assertLessEqual(sleep_arg, 0.030)

    def test_b09_scope_enricher_transient_failure_not_cached_across_instances(self):
        """Review item: _fetch_from_nvd raises once, new Enricher() returns data, not None."""
        from intelligence.enricher import Enricher

        call_count = 0
        def mock_fetch(cve_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise requests.RequestException("Transient network failure")
            return {"cvss_score": 7.5, "references": ["https://example.com/cve"]}

        with patch.object(Enricher, "_fetch_from_nvd", side_effect=mock_fetch), \
             patch.object(Enricher, "_fetch_from_circl", return_value=None):
            # First instance encounters transient network error
            e1 = Enricher(mock_mode=False, cache_path=None)
            res1 = e1._fetch_cve_data("CVE-2021-99999")
            self.assertIsNone(res1)

            # Second instance (e.g. subsequent scan) must retry and return data, NOT cached None
            e2 = Enricher(mock_mode=False, cache_path=None)
            res2 = e2._fetch_cve_data("CVE-2021-99999")
            self.assertIsNotNone(res2)
            self.assertEqual(res2.get("cvss_score"), 7.5)


if __name__ == "__main__":
    unittest.main()

