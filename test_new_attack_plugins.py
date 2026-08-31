"""
Unit tests for new Attack Simulation Scanner Plugins:
- CSRFScanner
- OpenRedirectScanner
- BOLAIdorScanner
- SecretExposureScanner
- SSLTLSScanner
"""

import unittest
from plugins.csrf_plugin import CSRFScanner
from plugins.open_redirect_plugin import OpenRedirectScanner
from plugins.bola_idor_plugin import BOLAIdorScanner
from plugins.secret_exposure_plugin import SecretExposureScanner
from plugins.ssl_tls_plugin import SSLTLSScanner


class TestNewAttackPlugins(unittest.TestCase):
    """Test suite for the 5 new attack scanner plugins."""

    def test_csrf_scanner_mock_output(self):
        scanner = CSRFScanner(mock_mode=True)
        scanner.configure("http://localhost:3000")
        output = scanner.get_standardized_output()
        self.assertEqual(output["tool_name"], "CSRFScanner")
        self.assertGreater(len(output["findings"]), 0)
        finding = output["findings"][0]
        self.assertTrue(finding["id"].startswith("CSRF-"))
        self.assertIn("CSRF", finding["title"])
        self.assertIn("SameSite", finding["remediation"])

    def test_open_redirect_scanner_mock_output(self):
        scanner = OpenRedirectScanner(mock_mode=True)
        scanner.configure("http://localhost:3000")
        output = scanner.get_standardized_output()
        self.assertEqual(output["tool_name"], "OpenRedirectScanner")
        self.assertGreater(len(output["findings"]), 0)
        finding = output["findings"][0]
        self.assertTrue(finding["id"].startswith("REDIR-"))
        self.assertIn("Redirect", finding["title"])

    def test_bola_idor_scanner_mock_output(self):
        scanner = BOLAIdorScanner(mock_mode=True)
        scanner.configure("http://localhost:3000")
        output = scanner.get_standardized_output()
        self.assertEqual(output["tool_name"], "BOLAIdorScanner")
        self.assertGreater(len(output["findings"]), 0)
        finding = output["findings"][0]
        self.assertTrue(finding["id"].startswith("BOLA-"))
        self.assertIn("IDOR", finding["title"])

    def test_secret_exposure_scanner_mock_output(self):
        scanner = SecretExposureScanner(mock_mode=True)
        scanner.configure("http://localhost:3000")
        output = scanner.get_standardized_output()
        self.assertEqual(output["tool_name"], "SecretExposureScanner")
        self.assertGreater(len(output["findings"]), 0)
        finding = output["findings"][0]
        self.assertTrue(finding["id"].startswith("SECR-"))
        self.assertIn("Exposed", finding["title"])

    def test_ssl_tls_scanner_mock_output(self):
        scanner = SSLTLSScanner(mock_mode=True)
        scanner.configure("https://localhost:3000")
        output = scanner.get_standardized_output()
        self.assertEqual(output["tool_name"], "SSLTLSScanner")
        self.assertGreater(len(output["findings"]), 0)
        finding = output["findings"][0]
        self.assertTrue(finding["id"].startswith("TLS-"))
        self.assertIn("HSTS", finding["title"])


if __name__ == "__main__":
    unittest.main()
