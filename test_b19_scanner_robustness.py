import importlib
import os
import socket
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from flask import Flask, Response
from werkzeug.serving import make_server

import config
from core.http_client import ScanHttpClient
from core.politeness import PolitenessEngine
from plugins.nmap_plugin import NmapPlugin
from plugins.open_redirect_plugin import OpenRedirectScanner


class TestAud62OpenRedirectEvasion(unittest.TestCase):
    """AUD-62: Open-redirect normalization catches browser-resolvable evasion forms."""

    def test_aud62_open_redirect_evasion_and_non_evasion_rows(self):
        request_url = "http://127.0.0.1:5103/redirect?next=PAYLOAD"

        flagged_locations = [
            "https://example.com",
            "//example.com/x",
            "/\\example.com",
            "\\\\example.com",
            "///example.com",
            "HTTPS://EXAMPLE.COM",
            "https:example.com",
            "https:/example.com",
            "http://127.0.0.1@example.com/",
            "https://attacker.example.com/",
        ]
        for loc in flagged_locations:
            with self.subTest(location=loc, expected=True):
                self.assertTrue(
                    OpenRedirectScanner._redirects_to_external_host(request_url, loc),
                    f"Expected Location={loc!r} to be flagged as external redirect",
                )

        unflagged_locations = [
            "/login/?next=https%3A%2F%2Fexample.com",
            "https://example.com.evil.net/",
            "https://notexample.com/",
            "",
        ]
        for loc in unflagged_locations:
            with self.subTest(location=loc, expected=False):
                self.assertFalse(
                    OpenRedirectScanner._redirects_to_external_host(request_url, loc),
                    f"Expected Location={loc!r} NOT to be flagged as external redirect",
                )


class TestAud63NmapIPv6AndSafeArgs(unittest.TestCase):
    """AUD-63: Nmap IPv6 -6 support, -- option terminator, and option-like/empty host rejection."""

    def test_aud63_ipv6_build_command_includes_dash6_port_dashdash_and_host(self):
        plugin = NmapPlugin(mock_mode=False)
        plugin.configure("http://[::1]:9000/x")
        cmd = plugin._build_command()

        self.assertIn("-6", cmd)
        self.assertIn("-p", cmd)
        p_idx = cmd.index("-p")
        self.assertEqual(cmd[p_idx + 1], "9000")
        self.assertIn("--", cmd)
        self.assertEqual(cmd[-2:], ["--", "::1"])
        self.assertEqual(cmd[-1], "::1")

    def test_aud63_option_like_host_and_empty_target_skip_subprocess_and_warn(self):
        for bad_target in ("http://--script=evil", "--version", ""):
            with self.subTest(target=bad_target):
                plugin = NmapPlugin(mock_mode=False)
                plugin.configure(bad_target)
                with patch.object(plugin, "check_tool_available", return_value=True), \
                     patch("plugins.nmap_plugin.subprocess.run") as mock_subproc, \
                     self.assertLogs("plugins.nmap_plugin", level="WARNING") as cm:
                    plugin.run()
                mock_subproc.assert_not_called()
                self.assertTrue(len(cm.output) > 0)

    def test_aud63_ipv4_and_hostname_targets_have_dashdash_before_host(self):
        plugin = NmapPlugin(mock_mode=False)
        plugin.configure("http://127.0.0.1:8080")
        cmd_v4 = plugin._build_command()
        self.assertNotIn("-6", cmd_v4)
        self.assertEqual(
            cmd_v4,
            [config.NMAP_PATH, "-sV", "-oX", "-", "-T4", "-p", "8080", "--", "127.0.0.1"],
        )

        plugin = NmapPlugin(mock_mode=False)
        plugin.configure("http://localhost:8080")
        cmd_host = plugin._build_command()
        self.assertNotIn("-6", cmd_host)
        self.assertEqual(
            cmd_host,
            [config.NMAP_PATH, "-sV", "-oX", "-", "-T4", "-p", "8080", "--", "localhost"],
        )


class TestAud64ResponseSizeAndTimeLimits(unittest.TestCase):
    """AUD-64: Response-size and total wall-time limits on ScanHttpClient requests."""

    @classmethod
    def setUpClass(cls):
        app = Flask(__name__)

        @app.route("/small")
        def small():
            return Response(b'{"status": "ok", "count": 3}', content_type="application/json")

        @app.route("/stream50mb")
        def stream50mb():
            chunk = b"A" * (64 * 1024)  # 64 KiB

            def generate():
                # 800 * 64 KiB = 50 MiB
                for _ in range(800):
                    yield chunk

            return Response(
                generate(),
                headers={"Content-Length": str(50 * 1024 * 1024)},
                content_type="text/plain; charset=utf-8",
            )

        @app.route("/drip60s")
        def drip60s():
            def generate():
                for _ in range(60):
                    yield b"0123456789"
                    time.sleep(1.0)

            return Response(
                generate(),
                headers={"Content-Length": "600"},
                content_type="text/plain; charset=utf-8",
            )

        @app.route("/drip_json")
        def drip_json():
            def generate():
                yield b'{"truncated_ok": true}'
                for _ in range(30):
                    time.sleep(0.5)
                    yield b" "

            return Response(generate(), content_type="application/json")

        @app.route("/fast_oversized")
        def fast_oversized():
            chunk = b"X" * (128 * 1024)

            def generate():
                for _ in range(3):  # 384 KiB
                    yield chunk

            return Response(generate(), content_type="text/plain")

        @app.route("/fast_drip")
        def fast_drip():
            def generate():
                yield b"part1"
                time.sleep(8.0)  # always longer than the time cap used with this endpoint
                yield b"part2"

            return Response(generate(), content_type="text/plain")

        # Server-side concurrency tracking: how many /slow_header_2s requests were in flight at once.
        cls.slow_state = {"inflight": 0, "max": 0}
        cls.slow_lock = threading.Lock()

        @app.route("/slow_header_2s")
        def slow_header_2s():
            with cls.slow_lock:
                cls.slow_state["inflight"] += 1
                cls.slow_state["max"] = max(cls.slow_state["max"], cls.slow_state["inflight"])
            try:
                time.sleep(2.0)
            finally:
                with cls.slow_lock:
                    cls.slow_state["inflight"] -= 1
            return Response(b"done", content_type="text/plain")

        cls.server = make_server("127.0.0.1", 0, app, threaded=True)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_aud64_config_defaults_and_env_validation(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOSEC_MAX_RESPONSE_BYTES", None)
            os.environ.pop("AUTOSEC_MAX_REQUEST_SECONDS", None)
            importlib.reload(config)
            self.assertEqual(config.MAX_RESPONSE_BYTES, 5 * 1024 * 1024)
            self.assertEqual(config.MAX_REQUEST_SECONDS, 30)

        with patch.dict(
            os.environ,
            {"AUTOSEC_MAX_RESPONSE_BYTES": "131072", "AUTOSEC_MAX_REQUEST_SECONDS": "15"},
        ):
            importlib.reload(config)
            self.assertEqual(config.MAX_RESPONSE_BYTES, 131072)
            self.assertEqual(config.MAX_REQUEST_SECONDS, 15)

        for bad_bytes, bad_secs in [
            ("100", "0"),
            (str(200 * 1024 * 1024), "500"),
            ("not-an-int", "bad-sec"),
        ]:
            with patch.dict(
                os.environ,
                {"AUTOSEC_MAX_RESPONSE_BYTES": bad_bytes, "AUTOSEC_MAX_REQUEST_SECONDS": bad_secs},
            ):
                with self.assertLogs("config", level="WARNING") as cm:
                    importlib.reload(config)
                self.assertEqual(config.MAX_RESPONSE_BYTES, 5 * 1024 * 1024)
                self.assertEqual(config.MAX_REQUEST_SECONDS, 30)
                self.assertGreaterEqual(len(cm.output), 2)

        # Restore defaults
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOSEC_MAX_RESPONSE_BYTES", None)
            os.environ.pop("AUTOSEC_MAX_REQUEST_SECONDS", None)
            importlib.reload(config)

    def test_aud64_streaming_50mb_response_capped_and_truncated(self):
        cap = 512 * 1024  # 512 KiB
        client = ScanHttpClient(
            target=self.base_url,
            politeness=PolitenessEngine(request_interval_ms=0, max_jitter_ms=0),
        )
        with patch.object(config, "MAX_RESPONSE_BYTES", cap):
            t0 = time.monotonic()
            resp = client.get(f"{self.base_url}/stream50mb")
            elapsed = time.monotonic() - t0

        self.assertIsNotNone(resp)
        self.assertTrue(getattr(resp, "truncated", False))
        self.assertLessEqual(len(resp.content), cap)
        self.assertEqual(len(resp.content), cap)
        self.assertEqual(len(resp.text), cap)
        self.assertLess(elapsed, 5.0)
        self.assertEqual(client.responses_truncated, 1)
        self.assertEqual(client.requests_timed_out, 0)

    def test_aud64_dripping_response_stopped_at_max_request_seconds(self):
        client = ScanHttpClient(
            target=self.base_url,
            politeness=PolitenessEngine(request_interval_ms=0, max_jitter_ms=0),
        )
        with patch.object(config, "MAX_REQUEST_SECONDS", 3):
            t0 = time.monotonic()
            resp = client.get(f"{self.base_url}/drip60s", timeout=(3.0, 10.0))
            elapsed = time.monotonic() - t0

        self.assertIsNotNone(resp)
        self.assertTrue(getattr(resp, "truncated", False))
        self.assertLessEqual(elapsed, 4.5, f"Drip request took too long: {elapsed:.2f}s")
        self.assertGreaterEqual(elapsed, 2.5)
        self.assertGreater(len(resp.content), 0)
        self.assertTrue(resp.text.startswith("0123456789"))
        self.assertEqual(client.requests_timed_out, 1)

    def test_aud64_dripping_headers_stopped_at_max_request_seconds(self):
        """A raw-socket server dripping HTTP headers at 10 B/s is cut off at MAX_REQUEST_SECONDS=3."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        raw_port = srv.getsockname()[1]

        def drip_headers():
            try:
                conn, _ = srv.accept()
            except Exception:
                return
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nX-Pad: ")
                for _ in range(300):
                    conn.sendall(b"a")
                    time.sleep(0.1)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        t = threading.Thread(target=drip_headers, daemon=True)
        t.start()

        try:
            raw_target = f"http://127.0.0.1:{raw_port}"
            client = ScanHttpClient(
                target=raw_target,
                politeness=PolitenessEngine(request_interval_ms=0, max_jitter_ms=0),
            )
            with patch.object(config, "MAX_REQUEST_SECONDS", 3):
                t0 = time.monotonic()
                resp = client.get(f"{raw_target}/", timeout=(3.0, 10.0))
                elapsed = time.monotonic() - t0

            self.assertIsNone(resp)
            self.assertLessEqual(elapsed, 4.5, f"Dripping header request took too long: {elapsed:.2f}s")
            self.assertGreaterEqual(elapsed, 2.5)
            self.assertEqual(client.requests_timed_out, 1)
        finally:
            try:
                srv.close()
            except Exception:
                pass

    def test_aud64_concurrent_requests_not_serialized_with_positive_pacing(self):
        """With PolitenessEngine(request_interval_ms=50), 5 concurrent GETs to a 2s endpoint overlap.

        Measured on the server (requests in flight at the same time), not with a tight wall-clock bound
        that a busy machine can exceed. Serialized requests would never overlap and would take >= 10 s.
        """
        client = ScanHttpClient(
            target=self.base_url,
            politeness=PolitenessEngine(request_interval_ms=50, max_jitter_ms=0),
        )
        with self.slow_lock:
            self.slow_state["max"] = 0
        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: client.get(f"{self.base_url}/slow_header_2s"), range(5)))
        elapsed = time.monotonic() - t0

        self.assertTrue(all(r is not None and r.status_code == 200 for r in results))
        self.assertGreaterEqual(self.slow_state["max"], 3,
                                f"Concurrent requests were serialized: at most {self.slow_state['max']} in flight")
        self.assertLess(elapsed, 9.0, f"Concurrent requests were serialized: took {elapsed:.2f}s (serial >= 10s)")

    def test_aud64_normal_small_response_unchanged_and_not_truncated(self):
        client = ScanHttpClient(
            target=self.base_url,
            politeness=PolitenessEngine(request_interval_ms=0, max_jitter_ms=0),
        )
        resp = client.get(f"{self.base_url}/small")
        self.assertIsNotNone(resp)
        self.assertFalse(getattr(resp, "truncated", True))
        self.assertEqual(resp.content, b'{"status": "ok", "count": 3}')
        self.assertEqual(resp.text, '{"status": "ok", "count": 3}')
        self.assertEqual(resp.json(), {"status": "ok", "count": 3})
        self.assertEqual(client.responses_truncated, 0)
        self.assertEqual(client.requests_timed_out, 0)

    def test_aud64_json_works_on_truncated_body(self):
        client = ScanHttpClient(
            target=self.base_url,
            politeness=PolitenessEngine(request_interval_ms=0, max_jitter_ms=0),
        )
        with patch.object(config, "MAX_REQUEST_SECONDS", 1):
            resp = client.get(f"{self.base_url}/drip_json")
        self.assertIsNotNone(resp)
        self.assertTrue(resp.truncated)
        self.assertEqual(resp.json(), {"truncated_ok": True})

    def test_aud64_counters_exact_under_50_concurrent_calls(self):
        client = ScanHttpClient(
            target=self.base_url,
            politeness=PolitenessEngine(request_interval_ms=0, max_jitter_ms=0),
        )
        # The time cap (4 s) is well above what a size-limited response needs even on a busy machine and
        # well below /fast_drip's 8 s, so each response is cut by exactly one of the two limits.
        with patch.object(config, "MAX_RESPONSE_BYTES", 64 * 1024), \
             patch.object(config, "MAX_REQUEST_SECONDS", 4.0):

            def call_one(idx: int):
                if idx < 25:
                    return client.get(f"{self.base_url}/fast_oversized")
                else:
                    return client.get(f"{self.base_url}/fast_drip")

            with ThreadPoolExecutor(max_workers=50) as pool:
                results = list(pool.map(call_one, range(50)))

        self.assertEqual(len(results), 50)
        self.assertTrue(all(r is not None and r.truncated for r in results))
        self.assertEqual(client.responses_truncated, 25)
        self.assertEqual(client.requests_timed_out, 25)


if __name__ == "__main__":
    unittest.main()

