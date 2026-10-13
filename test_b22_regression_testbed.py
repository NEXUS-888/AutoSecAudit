"""
Alias / bridge module for test_b25_regression_testbed.py matching backlog AUD-60 filename reference.
Lightweight tests only to prevent running the full pipeline scan twice in discovery.
"""

import unittest


class TestB22RegressionTestbedLightweight(unittest.TestCase):
    """Smoke check for app2 sandbox without repeating the full 66s pipeline scan."""

    def test_app2_importable_and_routes_registered(self):
        from testbed.app2 import app
        self.assertIsNotNone(app)
        rules = [rule.rule for rule in app.url_map.iter_rules()]
        self.assertIn("/api/v1/_debug", rules)
        self.assertIn("/labs/sqli", rules)
        self.assertIn("/login", rules)


if __name__ == "__main__":
    unittest.main()
