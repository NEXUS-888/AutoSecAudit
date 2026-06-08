"""Tests for all new vulnerability scanner plugins.

Runs every plugin in MOCK_MODE to verify:
1. Plugin instantiation
2. configure() + get_standardized_output() return well-formed data
3. Mock findings have all required fields
4. Severity values are valid
5. OWASP tags are present
"""
import os
import sys
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(__file__))

# Force mock mode
os.environ["AUTOSEC_MOCK_MODE"] = "true"


class PluginTestBase:
    """Mixin with shared assertion helpers for plugin tests."""

    PLUGIN_CLASS = None
    EXPECTED_TOOL_NAME = None
    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
    TARGET = "http://testsite.example.com:3000"

    def _get_output(self):
        plugin = self.PLUGIN_CLASS(mock_mode=True)
        plugin.configure(self.TARGET)
        return plugin.get_standardized_output()

    def test_instantiation(self):
        plugin = self.PLUGIN_CLASS(mock_mode=True)
        self.assertIsNotNone(plugin)

    def test_configure_sets_target(self):
        plugin = self.PLUGIN_CLASS(mock_mode=True)
        plugin.configure(self.TARGET)
        self.assertEqual(plugin.target, self.TARGET)

    def test_output_structure(self):
        output = self._get_output()
        self.assertIn("tool_name", output)
        self.assertIn("findings", output)
        self.assertEqual(output["tool_name"], self.EXPECTED_TOOL_NAME)
        self.assertIsInstance(output["findings"], list)

    def test_findings_not_empty(self):
        output = self._get_output()
        self.assertGreater(len(output["findings"]), 0,
                           f"{self.PLUGIN_CLASS.__name__} mock output returned no findings")

    def test_finding_required_fields(self):
        output = self._get_output()
        required_keys = {"id", "title", "severity", "host", "port",
                         "description", "raw_output"}
        for finding in output["findings"]:
            for key in required_keys:
                self.assertIn(key, finding,
                              f"Missing key '{key}' in finding {finding.get('id', '?')}")

    def test_finding_severities_valid(self):
        output = self._get_output()
        for finding in output["findings"]:
            self.assertIn(finding["severity"], self.VALID_SEVERITIES,
                          f"Invalid severity '{finding['severity']}' in {finding['id']}")

    def test_owasp_tag_present(self):
        output = self._get_output()
        for finding in output["findings"]:
            self.assertIn("owasp_tag", finding,
                          f"Missing OWASP tag in finding {finding['id']}")
            self.assertTrue(finding["owasp_tag"].startswith("A"),
                            f"OWASP tag should start with 'A': {finding['owasp_tag']}")


# -----------------------------------------------------------------------
# Concrete test classes – one per plugin
# -----------------------------------------------------------------------

class TestSQLiPlugin(PluginTestBase, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.sqli_plugin import SQLiScanner
        cls.PLUGIN_CLASS = SQLiScanner
        cls.EXPECTED_TOOL_NAME = "sqli_scanner"


class TestXSSPlugin(PluginTestBase, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.xss_plugin import XSSScanner
        cls.PLUGIN_CLASS = XSSScanner
        cls.EXPECTED_TOOL_NAME = "xss_scanner"


class TestAuthPlugin(PluginTestBase, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.auth_plugin import AuthScanner
        cls.PLUGIN_CLASS = AuthScanner
        cls.EXPECTED_TOOL_NAME = "auth_scanner"


class TestMisconfigPlugin(PluginTestBase, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.misconfig_plugin import MisconfigScanner
        cls.PLUGIN_CLASS = MisconfigScanner
        cls.EXPECTED_TOOL_NAME = "misconfig_scanner"


class TestAPIAbusePlugin(PluginTestBase, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from plugins.api_abuse_plugin import APIAbuseScanner
        cls.PLUGIN_CLASS = APIAbuseScanner
        cls.EXPECTED_TOOL_NAME = "api_abuse_scanner"


if __name__ == "__main__":
    unittest.main(verbosity=2)
