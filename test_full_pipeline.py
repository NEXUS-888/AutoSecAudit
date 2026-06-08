"""End-to-end pipeline test.

Validates the full scan pipeline:
  Engine -> load_plugins -> run_plugins -> intelligence -> report
"""
import os
import sys
import json
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
os.environ["AUTOSEC_MOCK_MODE"] = "true"

import config
from core.engine import Engine
from core.models import Report
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper


class TestFullPipeline(unittest.TestCase):
    """Test the complete scan-to-report pipeline in mock mode."""

    TARGET = "http://testsite.example.com:3000"

    def setUp(self):
        self.engine = Engine(mock_mode=True)

    # ------------------------------------------------------------------
    # 1. Plugin loading
    # ------------------------------------------------------------------
    def test_load_all_plugins(self):
        count = self.engine.load_plugins()
        # We expect at least the 5 new + 2 original plugins
        self.assertGreaterEqual(count, 7,
                                f"Expected >=7 plugins, got {count}")

    # ------------------------------------------------------------------
    # 2. Run plugins and collect results
    # ------------------------------------------------------------------
    def test_run_plugins_produces_results(self):
        self.engine.load_plugins()
        self.engine.set_target(self.TARGET)
        results = self.engine.run_plugins()
        self.assertGreater(len(results), 0, "No scan results produced")

    # ------------------------------------------------------------------
    # 3. Report generation
    # ------------------------------------------------------------------
    def test_generate_report(self):
        self.engine.load_plugins()
        self.engine.set_target(self.TARGET)
        self.engine.run_plugins()
        report = self.engine.generate_report()

        self.assertIsInstance(report, Report)
        self.assertEqual(report.target, f"http://testsite.example.com:3000")
        self.assertGreater(len(report.all_findings), 0)
        self.assertIn("total", report.summary)
        self.assertEqual(report.summary["total"], len(report.all_findings))

    # ------------------------------------------------------------------
    # 4. Intelligence pipeline
    # ------------------------------------------------------------------
    def test_intelligence_pipeline(self):
        self.engine.load_plugins()
        self.engine.set_target(self.TARGET)
        self.engine.run_plugins()
        report = self.engine.generate_report()

        # Correlator
        correlator = Correlator()
        correlated = correlator.correlate(report.all_findings)
        self.assertIsInstance(correlated, list)

        # Enricher (mock mode – should not crash even without network)
        enricher = Enricher()
        enriched = enricher.enrich(report.all_findings)
        self.assertIsInstance(enriched, list)

        # Compliance mapper
        mapper = ComplianceMapper()
        mapped = mapper.map_findings(report.all_findings)
        self.assertIsInstance(mapped, list)

    # ------------------------------------------------------------------
    # 5. Save and reload report
    # ------------------------------------------------------------------
    def test_save_and_reload_report(self):
        self.engine.load_plugins()
        self.engine.set_target(self.TARGET)
        self.engine.run_plugins()
        report = self.engine.generate_report()

        # Save to a temp file
        tmp_dir = os.path.join(os.path.dirname(__file__), "data", "reports")
        os.makedirs(tmp_dir, exist_ok=True)
        path = os.path.join(tmp_dir, "test_pipeline_report.json")
        saved_path = self.engine.save_report(report, path)

        self.assertTrue(os.path.exists(saved_path))

        with open(saved_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["target"], report.target)
        self.assertEqual(len(data["all_findings"]), len(report.all_findings))

        # Cleanup
        os.remove(saved_path)

    # ------------------------------------------------------------------
    # 6. Severity summary math
    # ------------------------------------------------------------------
    def test_severity_counts_match(self):
        self.engine.load_plugins()
        self.engine.set_target(self.TARGET)
        self.engine.run_plugins()
        report = self.engine.generate_report()

        expected_total = sum(
            report.summary.get(s, 0)
            for s in ("critical", "high", "medium", "low", "info")
        )
        self.assertEqual(report.summary["total"], expected_total,
                         "Severity counts don't add up to total")


if __name__ == "__main__":
    unittest.main(verbosity=2)
