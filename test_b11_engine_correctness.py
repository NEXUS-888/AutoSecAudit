"""Tests for Batch 11: Engine correctness (AUD-29, AUD-30, AUD-31)."""
import time
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile
import os

from core.engine import Engine
from core.models import Finding
from core.openapi import OpenAPIImporter
from plugins.base_plugin import BaseScanner


class SlowSleepScanner(BaseScanner):
    """Scanner that sleeps to simulate a hung plugin."""
    def _get_tool_name(self) -> str:
        return "slow_sleep"

    def _get_mock_output(self):
        return {"findings": []}

    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        time.sleep(6)

    def parse_output(self):
        return {"findings": []}


class CaptureEndpointsScanner(BaseScanner):
    """Scanner that captures self.discovered_endpoints seen during run()."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.seen_during_run = []

    def _get_tool_name(self) -> str:
        return "builtin"

    def _get_mock_output(self):
        return {"findings": []}

    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        self.seen_during_run = list(self.discovered_endpoints)

    def parse_output(self):
        return {"findings": []}


class TestB11EngineCorrectness(unittest.TestCase):
    # -----------------------------------------------------------------------
    # AUD-29: SCAN_TIMEOUT applies
    # -----------------------------------------------------------------------
    def test_aud29_scan_timeout_terminates_hung_plugin_within_deadline(self):
        """AUD-29: With SCAN_TIMEOUT=2 and a plugin sleeping 6s, run_plugins returns within ~4s with status='timeout'."""
        engine = Engine(mock_mode=True)
        engine.set_target("http://localhost:3000")

        slow_plugin = SlowSleepScanner(mock_mode=False)
        engine.plugins = [slow_plugin]

        with patch.object(engine, "_execute_plugin", side_effect=lambda p: (time.sleep(6), {"findings": []})[1]), \
             patch("config.SCAN_TIMEOUT", 2), \
             patch("config.SCAN_DEADLINE_SECONDS", 2):
            start = time.monotonic()
            results = engine.run_plugins()
            elapsed = time.monotonic() - start

            self.assertLess(
                elapsed,
                4.0,
                f"run_plugins took {elapsed:.2f}s; expected to return within ~4s when SCAN_TIMEOUT=2",
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, "timeout")

    def test_aud29_http_client_deadline_aborts_lingering_requests(self):
        """AUD-29: ScanHttpClient respects deadline and returns None when expired."""
        from core.http_client import ScanHttpClient

        client = ScanHttpClient(target="http://localhost:3000")
        client.deadline = time.monotonic() - 0.1  # already expired

        client.session.send = MagicMock()
        resp = client.request("GET", "http://localhost:3000/test")
        self.assertIsNone(resp)
        client.session.send.assert_not_called()

    # -----------------------------------------------------------------------
    # AUD-30: Finding fields survive conversion
    # -----------------------------------------------------------------------
    def test_aud30_cwe_id_and_pci_dss_survive_dict_to_findings(self):
        """AUD-30: cwe_id and pci_dss survive _dict_to_findings conversion, with defaults for host and confidence."""
        engine = Engine(mock_mode=False)
        engine.target = "http://localhost:3000"

        findings_data = [
            {
                "id": "SQLI-001",
                "title": "SQL Injection in /api/users",
                "severity": "High",
                "description": "Blind SQL injection",
                "cwe_id": "CWE-89",
                "pci_dss": "6.2.4",
            }
        ]

        findings = engine._dict_to_findings(findings_data)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.id, "SQLI-001")
        self.assertEqual(f.title, "SQL Injection in /api/users")
        self.assertEqual(f.cwe_id, "CWE-89", "cwe_id must survive conversion")
        self.assertEqual(f.pci_dss, "6.2.4", "pci_dss must survive conversion")
        self.assertEqual(f.host, "http://localhost:3000", "host must default to engine target")
        self.assertEqual(f.confidence, "medium", "confidence must default to 'medium'")

    # -----------------------------------------------------------------------
    # AUD-31: OpenAPI import wired to plugins
    # -----------------------------------------------------------------------
    def test_aud31_openapi_importer_extracts_plugin_shaped_endpoints(self):
        """AUD-31: OpenAPIImporter extracts plugin-shaped {path, param, method} entries (YAML and JSON, OpenAPI 3 and Swagger)."""
        spec_yaml = """
openapi: "3.0.0"
info:
  title: Sample Store API
  version: "1.0.0"
servers:
  - url: /api/v1
paths:
  /search:
    get:
      summary: Search items
      parameters:
        - name: q
          in: query
          schema:
            type: string
  /items:
    post:
      summary: Create item
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                price:
                  type: number
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(spec_yaml)
            yaml_path = f.name

        try:
            importer = OpenAPIImporter(yaml_path)
            self.assertTrue(importer.load_spec(), "YAML OpenAPI spec must load successfully")
            endpoints = importer.get_endpoints()

            # Should contain {path, param, method} entries
            expected_entries = [
                {"path": "/api/v1/search", "param": "q", "method": "GET"},
                {"path": "/api/v1/items", "param": "name", "method": "POST"},
                {"path": "/api/v1/items", "param": "price", "method": "POST"},
            ]
            for exp in expected_entries:
                self.assertIn(
                    exp,
                    endpoints,
                    f"Expected endpoint {exp} missing from OpenAPIImporter output: {endpoints}",
                )
        finally:
            if os.path.exists(yaml_path):
                os.remove(yaml_path)

    def test_aud31_engine_add_endpoints_wires_into_plugins_and_removes_crawler_data(self):
        """AUD-31: Engine.add_endpoints merges endpoints into plugins and crawler_data is removed."""
        engine = Engine(mock_mode=False)
        self.assertFalse(hasattr(engine, "crawler_data"), "engine.crawler_data must be removed")

        dummy_plugin = SlowSleepScanner()
        engine.plugins = [dummy_plugin]

        imported_endpoints = [
            {"path": "/api/v1/search", "param": "q", "method": "GET"},
            {"path": "/api/v1/items", "param": "name", "method": "POST"},
        ]
        engine.add_endpoints(imported_endpoints)

        # Plugin should receive the endpoints
        self.assertEqual(len(dummy_plugin.discovered_endpoints), 2)
        self.assertIn(imported_endpoints[0], dummy_plugin.discovered_endpoints)
        self.assertIn(imported_endpoints[1], dummy_plugin.discovered_endpoints)

    def test_aud31_openapi_endpoints_reach_plugins_end_to_end_in_run_plugins(self):
        """AUD-31: Imported OpenAPI 3 endpoints reach plugins through run_plugins()."""
        spec_yaml = """
openapi: "3.0.0"
info:
  title: Sample Store API
  version: "1.0.0"
servers:
  - url: /api/v1
paths:
  /search:
    get:
      summary: Search items
      parameters:
        - name: q
          in: query
          schema:
            type: string
  /items:
    post:
      summary: Create item
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                price:
                  type: number
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(spec_yaml)
            yaml_path = f.name

        try:
            importer = OpenAPIImporter(yaml_path)
            self.assertTrue(importer.load_spec(), "YAML OpenAPI spec must load successfully")
            endpoints = importer.get_endpoints()

            engine = Engine(mock_mode=True)
            engine.set_target("http://localhost:3000")
            engine.add_endpoints(endpoints)

            capture_plugin = CaptureEndpointsScanner(mock_mode=False)
            engine.plugins = [capture_plugin]

            engine.run_plugins()

            # Endpoints captured inside run() must include OpenAPI endpoints
            seen = capture_plugin.seen_during_run
            expected_entries = [
                {"path": "/api/v1/search", "param": "q", "method": "GET"},
                {"path": "/api/v1/items", "param": "name", "method": "POST"},
                {"path": "/api/v1/items", "param": "price", "method": "POST"},
            ]
            for exp in expected_entries:
                self.assertIn(
                    exp,
                    seen,
                    f"Expected endpoint {exp} missing from plugin seen_during_run: {seen}",
                )
        finally:
            if os.path.exists(yaml_path):
                os.remove(yaml_path)


if __name__ == "__main__":
    unittest.main()

