"""
Unit tests for JavaScript Route and API Path Extractor in Crawler.
"""

import unittest
from core.crawler import extract_js_endpoints


class TestCrawlerJSExtractor(unittest.TestCase):
    """Test suite for JS API extraction."""

    def test_extract_fetch_calls(self):
        js_code = """
        function loadUsers() {
            fetch('/api/v1/users?page=1&limit=20')
                .then(res => res.json())
                .then(data => console.log(data));
        }
        """
        endpoints = extract_js_endpoints(js_code, source_path="/index.html")
        paths = [e.path for e in endpoints]
        self.assertIn("/api/v1/users", paths)
        user_ep = next(e for e in endpoints if e.path == "/api/v1/users")
        self.assertIn("page", user_ep.params)
        self.assertIn("limit", user_ep.params)

    def test_extract_axios_and_ajax(self):
        js_code = """
        axios.post('/api/orders/checkout?discount=SUMMER');
        $.ajax('/graphql');
        """
        endpoints = extract_js_endpoints(js_code)
        paths = [e.path for e in endpoints]
        self.assertIn("/api/orders/checkout", paths)
        self.assertIn("/graphql", paths)

    def test_extract_rest_literals(self):
        js_code = """
        const API_URL = '/api/auth/token';
        const SEARCH_URL = '/api/search';
        """
        endpoints = extract_js_endpoints(js_code)
        paths = [e.path for e in endpoints]
        self.assertIn("/api/auth/token", paths)
        self.assertIn("/api/search", paths)


if __name__ == "__main__":
    unittest.main()
