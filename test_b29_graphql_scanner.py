"""Unit and integration tests for AUD-75: GraphQL Scanner Plugin.

Covers:
1. GraphQL endpoint discovery across standard paths and crawler-discovered endpoints.
2. Introspection check:
   - Enabled: reports introspection enabled, parses queryType fields with String/ID args.
   - Disabled: reports a single 'GraphQL endpoint found' informational finding and stops.
3. Injection probing:
   - SQLi error-signature leak reported exactly once on vulnerable field.
   - XSS unescaped reflection reported exactly once on vulnerable field.
   - Safe field produces no findings.
4. Safety guarantees:
   - No requests contain 'mutation' or 'subscription' operations.
   - All requests stay on fixture target origin.
   - Cap of 20 arguments and 6 payloads per argument.
   - Target without GraphQL produces no findings and at most 6 requests.
5. Stated plugin count:
   - README.md, CLAUDE.md, and ui/app.py match the Engine loaded plugin count.
"""

import os
import re
import sys
import json
import logging
import threading
import unittest
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from core.engine import Engine
import config


class FixtureGraphQLServer(BaseHTTPRequestHandler):
    """Loopback GraphQL test fixture implemented in plain Python with no GraphQL library."""

    introspection_enabled = True
    request_log = []
    lock = threading.Lock()

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def finish(self):
        try:
            super().finish()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def log_message(self, format, *args):
        # Silence default server logging
        return

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8", errors="replace")

        with self.lock:
            self.request_log.append({
                "path": parsed.path,
                "host": self.headers.get("Host", ""),
                "body": raw_body,
            })

        if parsed.path not in ("/graphql", "/api/graphql"):
            self.send_response(404)
            self.end_headers()
            return

        try:
            data = json.loads(raw_body) if raw_body else {}
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        query = data.get("query", "")
        variables = data.get("variables", {}) or {}

        # 1. Type name probe: {"query": "{__typename}"}
        if "__typename" in query and "__schema" not in query:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": {"__typename": "Query"}}).encode("utf-8"))
            return

        # 2. Introspection query
        if "__schema" in query:
            if not self.introspection_enabled:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "errors": [{"message": "GraphQL introspection is not allowed in production."}]
                }).encode("utf-8"))
                return

            # Canned introspection schema with 3 query fields:
            # - sql_query(id: String)
            # - xss_query(comment: String)
            # - safe_query(tag: String)
            canned_schema = {
                "data": {
                    "__schema": {
                        "queryType": {
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "sql_query",
                                    "args": [
                                        {"name": "id", "type": {"name": "String", "kind": "SCALAR"}}
                                    ]
                                },
                                {
                                    "name": "xss_query",
                                    "args": [
                                        {"name": "comment", "type": {"name": "String", "kind": "SCALAR"}}
                                    ]
                                },
                                {
                                    "name": "safe_query",
                                    "args": [
                                        {"name": "tag", "type": {"name": "String", "kind": "SCALAR"}}
                                    ]
                                },
                                {
                                    "name": "a } mutation M { b",
                                    "args": [
                                        {"name": "bad_arg", "type": {"name": "String", "kind": "SCALAR"}}
                                    ]
                                },
                                {
                                    "name": "error_on_any_quote",
                                    "args": [
                                        {"name": "text", "type": {"name": "String", "kind": "SCALAR"}}
                                    ]
                                },
                            ]
                        }
                    }
                }
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(canned_schema).encode("utf-8"))
            return

        # 3. Argument probing on query fields
        response_data = {"data": {}}

        # Check sql_query field
        if "sql_query" in query:
            val = variables.get("id")
            if val is None:
                m = re.search(r'sql_query\s*\(\s*id\s*:\s*(?:"([^"]*)"|([^,\)]*))\)', query)
                val = (m.group(1) or m.group(2) or "") if m else ""

            # Vulnerable to SQLi: leak syntax error on quotation marks
            if "'" in val or '"' in val:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "errors": [{"message": "you have an error in your sql syntax near '" + val + "'"}]
                }).encode("utf-8"))
                return
            else:
                response_data["data"]["sql_query"] = {"result": f"record for {val}"}

        # Check xss_query field
        if "xss_query" in query:
            val = variables.get("comment")
            if val is None:
                m = re.search(r'xss_query\s*\(\s*comment\s*:\s*(?:"([^"]*)"|([^,\)]*))\)', query)
                val = (m.group(1) or m.group(2) or "") if m else ""

            # Vulnerable to XSS: unescaped reflection in HTML string
            response_data["data"]["xss_query"] = f"<div class='comment-output'>{val}</div>"

        # Check safe_query field
        if "safe_query" in query:
            val = variables.get("tag")
            if val is None:
                m = re.search(r'safe_query\s*\(\s*tag\s*:\s*(?:"([^"]*)"|([^,\)]*))\)', query)
                val = (m.group(1) or m.group(2) or "") if m else ""

            # Safely sanitizes / echoes cleanly
            import html
            response_data["data"]["safe_query"] = html.escape(val)

        # Check error_on_any_quote field (returns 500 on any quotation mark, balanced or not)
        if "error_on_any_quote" in query:
            val = variables.get("text")
            if val is None:
                m = re.search(r'error_on_any_quote\s*\(\s*text\s*:\s*(?:"([^"]*)"|([^,\)]*))\)', query)
                val = (m.group(1) or m.group(2) or "") if m else ""

            if "'" in val or '"' in val:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "errors": [{"message": "Internal error: quote not allowed"}]
                }).encode("utf-8"))
                return
            else:
                response_data["data"]["error_on_any_quote"] = f"ok: {val}"

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode("utf-8"))


class TestB29GraphQLScanner(unittest.TestCase):
    """Test suite covering AUD-75 GraphQL security scanner."""

    def test_stated_plugin_count_matches_engine(self):
        """Assert stated plugin count in README, CLAUDE.md, and UI matches Engine.load_plugins()."""
        engine = Engine(mock_mode=True, profile="full")
        count = engine.load_plugins()
        self.assertEqual(count, 20, f"Expected 20 discovered plugins, found {count}")

        # Check README.md
        with open("README.md", "r", encoding="utf-8") as f:
            readme_text = f.read()
        self.assertIn(f"{count} Dynamic Vulnerability Scanner Plugins", readme_text)
        self.assertIn(f"Executes all {count} scanner plugins concurrently", readme_text)
        self.assertIn(f"List Discovered Scanner Plugins ({count} Plugins)", readme_text)

        # Check CLAUDE.md
        with open("CLAUDE.md", "r", encoding="utf-8") as f:
            claude_text = f.read()
        self.assertIn(f"{count} dynamic vulnerability scanners", claude_text)
        self.assertIn(f"{count} dynamic attack scanner plugins", claude_text)

        # Check ui/app.py badge and subtitle
        with open("ui/app.py", "r", encoding="utf-8") as f:
            app_text = f.read()
        self.assertIn(f"{count} PLUGINS", app_text)
        self.assertIn(f"{count} Attack Simulation Scanners", app_text)

    def test_graphql_scanner_mock_output(self):
        """Assert GraphQLScanner mock output conforms to BaseScanner contract."""
        from plugins.graphql_plugin import GraphQLScanner
        scanner = GraphQLScanner(mock_mode=True)
        scanner.configure("http://127.0.0.1:8080")
        output = scanner.get_standardized_output()

        self.assertIn("tool_name", output)
        self.assertIn("findings", output)
        findings = output["findings"]
        self.assertGreater(len(findings), 0)

        for f in findings:
            for req_key in ("id", "title", "severity", "host", "port", "description", "raw_output"):
                self.assertIn(req_key, f)
            self.assertIn(f["severity"], {"Critical", "High", "Medium", "Low", "Info"})

    def test_graphql_scanner_against_vulnerable_fixture(self):
        """Assert GraphQL scanner detects SQLi, XSS, and introspection, verifying safety constraints."""
        from plugins.graphql_plugin import GraphQLScanner

        FixtureGraphQLServer.introspection_enabled = True
        FixtureGraphQLServer.request_log = []

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureGraphQLServer)
        server.daemon_threads = True
        port = server.server_port
        target_url = f"http://127.0.0.1:{port}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            scanner = GraphQLScanner(mock_mode=False)
            scanner.configure(target_url)
            scanner.run()
            findings = scanner.results

            # 1. Finding assertions
            titles = [f.get("title", "") for f in findings]
            types = [f.get("vuln_type", "") for f in findings]

            # Introspection finding exactly once
            intro_findings = [f for f in findings if "Introspection" in f.get("title", "")]
            self.assertEqual(len(intro_findings), 1, "Must report introspection enabled exactly once")

            # SQLi finding on sql_query exactly once
            sqli_findings = [f for f in findings if f.get("vuln_type") == "sqli" or "SQL Injection" in f.get("title", "")]
            self.assertEqual(len(sqli_findings), 1, "Must report SQLi on sql_query exactly once")
            self.assertIn("sql_query", str(sqli_findings[0]))

            # XSS finding on xss_query exactly once
            xss_findings = [f for f in findings if f.get("vuln_type") == "xss" or "Cross-Site Scripting" in f.get("title", "")]
            self.assertEqual(len(xss_findings), 1, "Must report XSS on xss_query exactly once")
            self.assertIn("xss_query", str(xss_findings[0]))

            # Safe field has no findings
            safe_findings = [f for f in findings if "safe_query" in str(f)]
            self.assertEqual(len(safe_findings), 0, "Safe field must not produce any findings")

            # error_on_any_quote field has no SQLi findings (paired status differential rejects it)
            error_quote_findings = [f for f in findings if "error_on_any_quote" in str(f)]
            self.assertEqual(len(error_quote_findings), 0, "error_on_any_quote must produce 0 findings (paired check rejects)")

            # Hostile schema field name was filtered out by regex and produced no findings
            hostile_findings = [f for f in findings if "mutation" in str(f).lower() or "bad_arg" in str(f)]
            self.assertEqual(len(hostile_findings), 0, "Hostile schema field name must produce no findings")

            # 2. Safety rules assertions
            server_logs = list(FixtureGraphQLServer.request_log)
            self.assertGreater(len(server_logs), 0)

            from collections import defaultdict
            payload_counts = defaultdict(int)

            for req in server_logs:
                # Every request went to the fixture origin
                self.assertEqual(req["host"], f"127.0.0.1:{port}")
                # No request contained mutation or subscription
                body_lower = req["body"].lower()
                self.assertNotIn("mutation", body_lower, "Safety violation: mutation operation found in request")
                self.assertNotIn("subscription", body_lower, "Safety violation: subscription operation found in request")

                # Count payload-bearing requests (excluding introspection and baseline/control)
                if "__schema" not in body_lower and "__typename" not in body_lower:
                    if "safe123" not in body_lower and "ctrl_abc" not in body_lower:
                        for fld in ("sql_query", "xss_query", "safe_query", "error_on_any_quote"):
                            if fld in body_lower:
                                payload_counts[fld] += 1

            for fld, cnt in payload_counts.items():
                self.assertLessEqual(cnt, 6, f"Field '{fld}' exceeded 6 payloads: {cnt} requests sent")

        finally:
            server.shutdown()
            server.server_close()

    def test_target_without_graphql_produces_no_findings_and_at_most_6_requests(self):
        """Assert target with no GraphQL endpoint produces zero findings and <= 6 discovery requests."""
        from plugins.graphql_plugin import GraphQLScanner

        class NonGraphQLHandler(BaseHTTPRequestHandler):
            request_count = 0
            lock = threading.Lock()

            def log_message(self, format, *args):
                return

            def do_POST(self):
                with self.lock:
                    NonGraphQLHandler.request_count += 1
                self.send_response(404)
                self.end_headers()

        NonGraphQLHandler.request_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), NonGraphQLHandler)
        server.daemon_threads = True
        port = server.server_port
        target_url = f"http://127.0.0.1:{port}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            scanner = GraphQLScanner(mock_mode=False)
            scanner.configure(target_url)
            scanner.run()

            self.assertEqual(len(scanner.results), 0, "Non-GraphQL target must produce 0 findings")
            self.assertLessEqual(NonGraphQLHandler.request_count, 6, "Must make at most 6 discovery requests")
            self.assertGreater(NonGraphQLHandler.request_count, 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_introspection_disabled_produces_single_info_finding_no_argument_probing(self):
        """Assert disabled introspection reports a single 'GraphQL endpoint found' info finding and does no arg probing."""
        from plugins.graphql_plugin import GraphQLScanner

        FixtureGraphQLServer.introspection_enabled = False
        FixtureGraphQLServer.request_log = []

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureGraphQLServer)
        server.daemon_threads = True
        port = server.server_port
        target_url = f"http://127.0.0.1:{port}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            scanner = GraphQLScanner(mock_mode=False)
            scanner.configure(target_url)
            scanner.run()

            findings = scanner.results
            self.assertEqual(len(findings), 1, "Must produce exactly one finding when introspection is disabled")

            info_finding = findings[0]
            self.assertEqual(info_finding.get("severity"), "Info")
            title = info_finding.get("title", "").lower()
            self.assertTrue("graphql endpoint" in title or "found" in title)

            # Confirm no argument probing occurred
            logs = list(FixtureGraphQLServer.request_log)
            for req in logs:
                body = req["body"]
                self.assertNotIn("sql_query", body)
                self.assertNotIn("xss_query", body)
                self.assertNotIn("safe_query", body)

        finally:
            server.shutdown()
            server.server_close()

    def test_discovered_endpoint_custom_graphql(self):
        """Assert scanner given discovered endpoint /custom/graphql finds GraphQL and produces introspection finding."""
        from plugins.graphql_plugin import GraphQLScanner

        class CustomGraphQLEndpointHandler(BaseHTTPRequestHandler):
            request_log = []
            lock = threading.Lock()

            def log_message(self, format, *args):
                return

            def do_POST(self):
                parsed = urlparse(self.path)
                content_len = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_len).decode("utf-8", errors="replace")

                with self.lock:
                    CustomGraphQLEndpointHandler.request_log.append({
                        "path": parsed.path,
                        "body": raw_body,
                    })

                # Only /custom/graphql responds with GraphQL; standard paths return 404
                if parsed.path != "/custom/graphql":
                    self.send_response(404)
                    self.end_headers()
                    return

                try:
                    data = json.loads(raw_body) if raw_body else {}
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    return

                query = data.get("query", "")
                if "__typename" in query and "__schema" not in query:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"data": {"__typename": "Query"}}).encode("utf-8"))
                    return

                if "__schema" in query:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "data": {
                            "__schema": {
                                "queryType": {
                                    "name": "Query",
                                    "fields": []
                                }
                            }
                        }
                    }).encode("utf-8"))
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data": {}}')

        CustomGraphQLEndpointHandler.request_log = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), CustomGraphQLEndpointHandler)
        server.daemon_threads = True
        port = server.server_port
        target_url = f"http://127.0.0.1:{port}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            scanner = GraphQLScanner(mock_mode=False)
            scanner.configure(target_url)
            scanner.set_discovered_endpoints([{"path": "/custom/graphql"}])
            scanner.run()

            findings = scanner.results
            intro_findings = [f for f in findings if "Introspection" in f.get("title", "")]
            self.assertEqual(len(intro_findings), 1, "Must produce introspection finding for /custom/graphql")
            self.assertIn("/custom/graphql", intro_findings[0].get("endpoint", ""))
        finally:
            server.shutdown()
            server.server_close()

    def test_argument_cap_at_most_20_distinct_args_probed(self):
        """Assert that a schema with 25 String arguments probes at most 20 distinct arguments."""
        from plugins.graphql_plugin import GraphQLScanner

        class BigSchemaHandler(BaseHTTPRequestHandler):
            probed_fields = set()
            lock = threading.Lock()

            def log_message(self, format, *args):
                return

            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_len).decode("utf-8", errors="replace")

                try:
                    data = json.loads(raw_body) if raw_body else {}
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    return

                query = data.get("query", "")
                if "__typename" in query and "__schema" not in query:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"data": {"__typename": "Query"}}')
                    return

                if "__schema" in query:
                    # Canned schema with 25 query fields, each having a String argument
                    fields = []
                    for i in range(1, 26):
                        fields.append({
                            "name": f"item_{i}",
                            "args": [
                                {"name": f"param_{i}", "type": {"name": "String", "kind": "SCALAR"}}
                            ]
                        })
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "data": {
                            "__schema": {
                                "queryType": {
                                    "name": "Query",
                                    "fields": fields
                                }
                            }
                        }
                    }).encode("utf-8"))
                    return

                # Record probed item
                m = re.search(r'\bitem_(\d+)\b', query)
                if m:
                    with self.lock:
                        BigSchemaHandler.probed_fields.add(f"item_{m.group(1)}.param_{m.group(1)}")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data": {"result": "ok"}}')

        BigSchemaHandler.probed_fields = set()
        server = ThreadingHTTPServer(("127.0.0.1", 0), BigSchemaHandler)
        server.daemon_threads = True
        port = server.server_port
        target_url = f"http://127.0.0.1:{port}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            scanner = GraphQLScanner(mock_mode=False)
            scanner.configure(target_url)
            scanner.run()

            probed_count = len(BigSchemaHandler.probed_fields)
            self.assertEqual(probed_count, 20, f"Expected exactly 20 distinct arguments probed (cap), but got {probed_count}")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

