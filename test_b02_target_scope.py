import unittest
from unittest.mock import patch
import socket
from core.utils import is_target_allowed, validate_target
from core.engine import Engine
import mcp_server


class TestB02TargetScope(unittest.TestCase):
    """Test suite for Batch 02: Target scope enforcement (AUD-04, AUD-05, AUD-06)."""

    def test_aud_04_target_allowlist_enforcement(self):
        """AUD-04: Allowlist matches IP addresses (is_private or is_loopback), not hostname strings."""
        disallowed = [
            "10.example.com",
            "192.168.attacker.net",
            "127.evil.org",
            "8.8.8.8",
            "example.com"
        ]
        for target in disallowed:
            allowed, reason = is_target_allowed(target)
            self.assertFalse(allowed, f"Expected {target} to be rejected, but got allowed=True. Reason: {reason}")

        allowed_targets = [
            "localhost",
            "127.0.0.1",
            "192.168.1.5",
            "10.0.0.2",
            "http://[::1]:8080"
        ]
        for target in allowed_targets:
            allowed, reason = is_target_allowed(target)
            self.assertTrue(allowed, f"Expected {target} to be allowed, but got allowed=False. Reason: {reason}")

    def test_aud_04_dns_mock_resolution(self):
        """AUD-04: Test DNS resolution allowing only private/loopback IPs."""
        # Hostname resolves to public IP
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
            allowed, reason = is_target_allowed("custom-internal.corp")
            self.assertFalse(allowed)

        # Hostname resolves to private IP
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.1.25", 80))]):
            allowed, reason = is_target_allowed("custom-internal.corp")
            self.assertTrue(allowed)

        # Unresolvable hostname
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            allowed, reason = is_target_allowed("nonexistent.invalid")
            self.assertFalse(allowed)

    def test_aud_05_engine_and_mcp_chokepoint(self):
        """AUD-05: Allowlist enforced inside Engine.set_target and MCP handle_scan."""
        engine_mock = Engine(mock_mode=True)
        self.assertFalse(engine_mock.set_target("http://10.example.com"))
        self.assertTrue(engine_mock.set_target("http://127.0.0.1:8080"))

        mcp_result = mcp_server.handle_scan({"target": "http://10.example.com", "mock": True})
        self.assertEqual(mcp_result.get("status"), "error")

    def test_aud_06_validate_target(self):
        """AUD-06: validate_target supports single-label hosts, IPv6, and rejects invalid URLs."""
        valid_targets = [
            "http://juice-shop:3000",
            "dvwa",
            "localhost:8080",
            "10.0.0.2",
            "http://[::1]:80",
        ]
        for target in valid_targets:
            self.assertTrue(validate_target(target), f"Expected {target} to be valid")

        invalid_targets = [
            "",
            "http://",
            "ftp://x",
            "http://host:99999",
            "not a url",
        ]
        for target in invalid_targets:
            self.assertFalse(validate_target(target), f"Expected {target} to be invalid")


if __name__ == "__main__":
    unittest.main()
