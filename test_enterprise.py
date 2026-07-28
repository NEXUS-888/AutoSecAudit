import unittest
import json
import os
from unittest.mock import MagicMock, patch

from core.openapi import OpenAPIImporter
from core.notifications import WebhookNotifier
from intelligence.compliance import ComplianceMapper
from core.models import Finding
import main


class TestEnterpriseFeatures(unittest.TestCase):
    """Test suite for enterprise features: OpenAPI, Notifications, CWE/PCI-DSS, and CI/CD Gating."""

    def test_openapi_importer(self):
        sample_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/v1/users": {
                    "get": {
                        "summary": "Get users",
                        "parameters": [{"name": "role", "in": "query", "type": "string"}]
                    }
                }
            }
        }
        spec_path = "test_spec.json"
        with open(spec_path, "w") as f:
            json.dump(sample_spec, f)

        try:
            importer = OpenAPIImporter(spec_path)
            self.assertTrue(importer.load_spec())
            endpoints = importer.get_endpoints()
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0]["path"], "/api/v1/users")
            self.assertEqual(endpoints[0]["method"], "GET")
        finally:
            if os.path.exists(spec_path):
                os.remove(spec_path)

    def test_webhook_notifier(self):
        with patch("requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            notifier = WebhookNotifier("https://discord.com/api/webhooks/test")
            summary = {"total": 5, "critical": 1, "high": 2, "medium": 2, "low": 0}
            success = notifier.send_notification(summary, "http://example.com")
            self.assertTrue(success)
            mock_post.assert_called_once()

    def test_compliance_cwe_pci(self):
        finding = Finding(
            id="TEST-001",
            title="SQL Injection in search endpoint",
            severity="High",
            host="example.com",
            port=80,
            description="Parameter vulnerable to SQLi",
            raw_output="",
            tool_name="sqli_scanner"
        )
        mapper = ComplianceMapper()
        mapped = mapper.map_findings([finding])
        self.assertEqual(mapped[0].cwe_id, "CWE-89")
        self.assertEqual(mapped[0].pci_dss, "PCI-DSS 6.2.4")

    def test_cicd_gating_fail(self):
        with patch("main.validate_target", return_value=True), \
             patch("main.is_target_allowed", return_value=(True, "")), \
             patch("main.Engine") as mock_engine_cls:
            
            mock_engine = MagicMock()
            mock_engine.load_plugins.return_value = 1
            mock_engine.set_target.return_value = True
            
            mock_report = MagicMock()
            mock_report.summary = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
            mock_report.all_findings = []
            mock_report.target = "example.com"
            mock_report.timestamp = "2026-07-28 20:00:00"
            mock_report.delta = None
            mock_report.to_dict.return_value = {
                "target": "example.com",
                "timestamp": "2026-07-28 20:00:00",
                "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
                "all_findings": [],
                "delta": None
            }
            
            mock_engine.generate_report.return_value = mock_report
            mock_engine._generate_summary.return_value = mock_report.summary
            mock_engine_cls.return_value = mock_engine
            
            exit_code = main.run_scan("example.com", fail_on="critical")
            self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
