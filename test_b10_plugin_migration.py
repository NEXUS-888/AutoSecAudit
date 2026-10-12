"""Tests for Batch 10: Plugin migration (AUD-27, AUD-28)."""
import os
import re
import unittest
from pathlib import Path

from core.engine import Engine
from plugins.base_plugin import BaseScanner
from plugins.auth_plugin import AuthScanner
from plugins.command_injection_plugin import CommandInjectionScanner
from plugins.sqli_plugin import SQLiScanner
from plugins.xss_plugin import XSSScanner


class TestB10PluginMigration(unittest.TestCase):
    def setUp(self):
        self.plugins_dir = Path(__file__).resolve().parent / "plugins"

    def test_aud27_no_direct_requests_calls_in_plugins(self):
        """AUD-27: grep for direct requests calls matches nothing outside base_plugin.py."""
        pattern = re.compile(r"requests\.(get|post|put|delete|head|options|request|Session)\(")
        violations = []

        for py_file in self.plugins_dir.glob("*.py"):
            if py_file.name == "base_plugin.py":
                continue
            content = py_file.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    violations.append(f"{py_file.name}:{lineno}: {line.strip()}")

        self.assertEqual(
            violations,
            [],
            "Found direct requests calls outside base_plugin.py:\n" + "\n".join(violations),
        )

    def test_aud27_plugin_request_carries_authorization_header(self):
        """AUD-27: A plugin request carries the Authorization header passed via set_auth."""
        import http.server
        import socketserver
        import threading

        received_headers = {}

        class AuthHeaderHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal received_headers
                received_headers = dict(self.headers)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format, *args):
                pass

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), AuthHeaderHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            target = f"http://127.0.0.1:{port}"
            scanner = CommandInjectionScanner()
            scanner.configure(target)
            scanner.set_auth(headers={"Authorization": "Bearer autosec-token-xyz"})

            # Send a request via the scanner's safe_request
            resp = scanner._safe_request("GET", f"{target}/api/test")
            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 200)

            auth_hdr = received_headers.get("Authorization")
            self.assertEqual(
                auth_hdr,
                "Bearer autosec-token-xyz",
                f"Expected 'Bearer autosec-token-xyz', got {auth_hdr!r}",
            )
        finally:
            server.shutdown()
            server.server_close()

    def test_aud28_only_base_plugin_defines_parse_target_or_parse_url(self):
        """AUD-28: Only base_plugin.py defines _parse_target or _parse_url."""
        pattern = re.compile(r"def\s+(_parse_target|_parse_url)\s*\(")
        definitions = []

        for py_file in self.plugins_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    definitions.append(f"{py_file.name}:{lineno}: {line.strip()}")

        # Ensure base_plugin.py has the definition
        base_defs = [d for d in definitions if d.startswith("base_plugin.py:")]
        self.assertTrue(len(base_defs) >= 1, "base_plugin.py must define _parse_target")

        # Ensure no other plugin defines them
        other_defs = [d for d in definitions if not d.startswith("base_plugin.py:")]
        self.assertEqual(
            other_defs,
            [],
            "Duplicated helper definitions found outside base_plugin.py:\n" + "\n".join(other_defs),
        )

    def test_aud27_public_target_rejected_by_is_in_scope_and_request(self):
        """AUD-27: ScanHttpClient rejects public target in is_in_scope and request() never calls send()."""
        from unittest.mock import MagicMock
        from core.http_client import ScanHttpClient

        client = ScanHttpClient(target="http://example.com")
        self.assertFalse(
            client.is_in_scope("http://example.com/x"),
            "ScanHttpClient must reject public IP/hostname example.com in is_in_scope",
        )

        client.session.send = MagicMock()
        resp = client.request("GET", "http://example.com/x")
        self.assertIsNone(resp, "request() must return None for out-of-scope / public target")
        client.session.send.assert_not_called()

    def test_aud27_http_client_has_no_mock_seams(self):
        """AUD-27: core/http_client.py has no mock_calls or assert_called test seams."""
        client_py = Path(__file__).resolve().parent / "core" / "http_client.py"
        content = client_py.read_text(encoding="utf-8")
        self.assertNotRegex(content, r"mock_calls|assert_called")

    def test_aud28_no_parse_url_anywhere_in_plugins(self):
        """AUD-28: No occurrences of _parse_url exist anywhere in plugins/."""
        pattern = re.compile(r"\b_parse_url\b")
        matches = []
        for py_file in self.plugins_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    matches.append(f"{py_file.name}:{lineno}: {line.strip()}")
        self.assertEqual(matches, [], f"Found _parse_url in plugins/:\n" + "\n".join(matches))

    def test_aud28_xss_scanner_run_does_not_raise(self):
        """AUD-28: XSSScanner run() executes without raising AttributeError for _parse_url."""
        scanner_mock = XSSScanner(mock_mode=True)
        scanner_mock.configure("http://127.0.0.1:9")
        scanner_mock._safe_request = lambda *a, **kw: None
        scanner_mock.run()  # Must not raise

        scanner_real = XSSScanner(mock_mode=False)
        scanner_real.configure("http://127.0.0.1:9")
        scanner_real.discovered_endpoints = [{"path": "/test", "param": "param", "method": "GET"}]
        scanner_real._test_security_headers = lambda base_url: None
        scanner_real._test_dom_xss_indicators = lambda base_url: None
        scanner_real._test_hash_fragment_endpoints = lambda base_url: None
        scanner_real.run()  # Must not raise


if __name__ == "__main__":
    unittest.main()

