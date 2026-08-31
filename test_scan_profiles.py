"""
Unit tests for Scan Profiles Engine in AutoSecAudit.
"""

import unittest
from core.engine import Engine
import config


class TestScanProfiles(unittest.TestCase):
    """Test suite for Scan Profile loading and filtering."""

    def test_full_profile_loads_all_plugins(self):
        engine = Engine(mock_mode=True, profile="full")
        count = engine.load_plugins()
        self.assertGreaterEqual(count, 19)
        plugin_names = [p.__class__.__name__ for p in engine.plugins]
        self.assertIn("SQLiScanner", plugin_names)
        self.assertIn("CSRFScanner", plugin_names)
        self.assertIn("OpenRedirectScanner", plugin_names)
        self.assertIn("BOLAIdorScanner", plugin_names)
        self.assertIn("SecretExposureScanner", plugin_names)
        self.assertIn("SSLTLSScanner", plugin_names)

    def test_owasp_profile_filtering(self):
        engine = Engine(mock_mode=True, profile="owasp")
        count = engine.load_plugins()
        plugin_names = [p.__class__.__name__ for p in engine.plugins]
        self.assertIn("SQLiScanner", plugin_names)
        self.assertIn("XSSScanner", plugin_names)
        self.assertIn("CSRFScanner", plugin_names)
        self.assertIn("SecretExposureScanner", plugin_names)
        self.assertNotIn("NmapPlugin", plugin_names)  # Nmap is in recon profile

    def test_api_profile_filtering(self):
        engine = Engine(mock_mode=True, profile="api")
        count = engine.load_plugins()
        plugin_names = [p.__class__.__name__ for p in engine.plugins]
        self.assertIn("BOLAIdorScanner", plugin_names)
        self.assertIn("JWTScanner", plugin_names)
        self.assertIn("APIAbuseScanner", plugin_names)
        self.assertIn("CORSScanner", plugin_names)

    def test_recon_profile_filtering(self):
        engine = Engine(mock_mode=True, profile="recon")
        count = engine.load_plugins()
        plugin_names = [p.__class__.__name__ for p in engine.plugins]
        self.assertIn("SSLTLSScanner", plugin_names)
        self.assertIn("DirBruteScanner", plugin_names)
        self.assertNotIn("XSSScanner", plugin_names)


if __name__ == "__main__":
    unittest.main()
