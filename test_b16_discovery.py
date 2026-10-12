"""
Unit tests for Batch 16:
- AUD-43: Crawler BFS queue, same-origin checks, JS bundle fetching, and HTTP method detection.
- AUD-44: SPA soft-404 detection with multi-probe calibration, redirect policy, shared engine detector, and tolerance checks.
- AUD-45: Enricher mock mode zero HTTP calls, disk cache with TTL, and NVD_API_KEY support.
"""

import os
import json
import time
import tempfile
import difflib
import hashlib
import unittest
from unittest.mock import patch, MagicMock

import requests
from core.models import Finding
from core.crawler import WebCrawler, DiscoveredEndpoint, extract_js_endpoints
from core.spa_detector import SPADetector
from core.engine import Engine
from plugins.base_plugin import BaseScanner
from intelligence.enricher import Enricher


class TestAUD43Crawler(unittest.TestCase):
    """AUD-43: Crawler is a BFS that reads JS bundles and detects HTTP methods."""

    def test_acceptance_script_src_yields_endpoint_and_param(self):
        """Acceptance: root page with <script src="/app.js"> containing fetch('/api/items?id=1') yields /api/items with param id."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        root_html = """
        <!doctype html>
        <html>
        <head>
            <script src="/app.js"></script>
        </head>
        <body><h1>Welcome</h1></body>
        </html>
        """

        app_js = """
        function getItems() {
            fetch('/api/items?id=1');
        }
        """

        def mock_get(url, *args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.history = []
            if url.endswith("/app.js"):
                resp.url = "http://localhost:3000/app.js"
                resp.headers = {"content-type": "application/javascript"}
                resp.text = app_js
                resp.content = app_js.encode("utf-8")
            else:
                resp.url = "http://localhost:3000/"
                resp.headers = {"content-type": "text/html"}
                resp.text = root_html
                resp.content = root_html.encode("utf-8")
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000")

        paths = {ep.path: ep for ep in result.endpoints}
        self.assertIn("/api/items", paths)
        item_ep = paths["/api/items"]
        self.assertIn("id", item_ep.params)

    def test_crawler_uses_bfs_order(self):
        """Crawler visits links in BFS queue order rather than recursive DFS order."""
        crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=3)

        visited_urls = []

        def mock_get(url, *args, **kwargs):
            visited_urls.append(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.history = []
            if url == "http://localhost:3000" or url == "http://localhost:3000/":
                resp.text = '<a href="/depth1-a">A</a><a href="/depth1-b">B</a>'
            elif "/depth1-a" in url:
                resp.text = '<a href="/depth2-a1">A1</a>'
            elif "/depth1-b" in url:
                resp.text = '<a href="/depth2-b1">B1</a>'
            else:
                resp.text = "Leaf page"
            resp.content = resp.text.encode("utf-8")
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            crawler.crawl("http://localhost:3000")

        # In BFS, depth 1 URLs (/depth1-a, /depth1-b) are visited before depth 2 URLs (/depth2-a1, /depth2-b1)
        depth1_indices = [i for i, u in enumerate(visited_urls) if "depth1" in u]
        depth2_indices = [i for i, u in enumerate(visited_urls) if "depth2" in u]
        self.assertTrue(len(depth1_indices) >= 2)
        self.assertTrue(len(depth2_indices) >= 1)
        self.assertLess(max(depth1_indices), min(depth2_indices))

    def test_crawler_js_http_methods_implied(self):
        """extract_js_endpoints detects HTTP methods implied by .post(, .put(, .delete(."""
        sample_js = """
        axios.post('/api/users?name=test');
        client.put('/api/users/42?role=admin');
        req.delete('/api/items/99');
        fetch('/api/status');
        """
        endpoints = extract_js_endpoints(sample_js, "app.js")
        by_path = {ep.path: ep for ep in endpoints}

        self.assertIn("/api/users", by_path)
        self.assertEqual(by_path["/api/users"].method, "POST")
        self.assertIn("name", by_path["/api/users"].params)

        self.assertIn("/api/users/42", by_path)
        self.assertEqual(by_path["/api/users/42"].method, "PUT")
        self.assertIn("role", by_path["/api/users/42"].params)

        self.assertIn("/api/items/99", by_path)
        self.assertEqual(by_path["/api/items/99"].method, "DELETE")

        self.assertIn("/api/status", by_path)
        self.assertEqual(by_path["/api/status"].method, "GET")

    def test_crawler_same_origin_and_script_limits(self):
        """Crawler ignores off-origin scripts and caps script count to 10 and size to 2 MB."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        scripts_html = """
        <!doctype html>
        <html>
        <head>
            <script src="https://cdn.external.com/lib.js"></script>
        """ + "\n".join([f'<script src="/bundle{i}.js"></script>' for i in range(15)]) + """
        </head>
        <body>Test</body>
        </html>
        """

        fetched_scripts = []

        def mock_get(url, *args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.history = []
            resp.url = url
            if url.endswith(".js"):
                fetched_scripts.append(url)
                resp.headers = {"content-type": "application/javascript"}
                resp.text = "fetch('/api/test');"
                resp.content = b"x" * 100
            else:
                resp.headers = {"content-type": "text/html"}
                resp.text = scripts_html
                resp.content = scripts_html.encode("utf-8")
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            crawler.crawl("http://localhost:3000")

        # External CDN script must NOT be fetched
        self.assertFalse(any("cdn.external.com" in s for s in fetched_scripts))
        # Same-origin scripts capped at 10 files
        self.assertLessEqual(len(fetched_scripts), 10)

    def test_crawler_oversized_script_content_length_yields_no_endpoints(self):
        """Oversized script via Content-Length (>2 MB) yields none of its endpoints."""
        crawler = WebCrawler(mock_mode=False, max_pages=1, max_depth=1)
        html = '<!doctype html><html><head><script src="/oversized.js"></script></head><body>Home</body></html>'

        def mock_get(url, *args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.history = []
            resp.url = url
            if url.endswith(".js"):
                resp.headers = {"Content-Length": "3145728", "content-type": "application/javascript"}
                resp.iter_content.return_value = [b"fetch('/api/secret_cl_endpoint');"]
            else:
                resp.headers = {"content-type": "text/html"}
                resp.text = html
                resp.content = html.encode("utf-8")
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            res = crawler.crawl("http://localhost:3000")

        discovered_paths = [ep.path for ep in res.endpoints]
        self.assertNotIn("/api/secret_cl_endpoint", discovered_paths)

    def test_crawler_oversized_script_streamed_yields_no_endpoints(self):
        """Oversized script streamed (>2 MB) yields none of its endpoints."""
        crawler = WebCrawler(mock_mode=False, max_pages=1, max_depth=1)
        html = '<!doctype html><html><head><script src="/stream_huge.js"></script></head><body>Home</body></html>'

        def mock_get(url, *args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.history = []
            resp.url = url
            if url.endswith(".js"):
                resp.headers = {"content-type": "application/javascript"}
                # Yield >2 MB of chunks then endpoint call
                chunks = [b"var a = 1;\n" * 6000 for _ in range(40)]  # 40 * 72000 = ~2.88 MB
                chunks.append(b"fetch('/api/secret_stream_endpoint');")
                resp.iter_content.return_value = chunks
            else:
                resp.headers = {"content-type": "text/html"}
                resp.text = html
                resp.content = html.encode("utf-8")
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            res = crawler.crawl("http://localhost:3000")

        discovered_paths = [ep.path for ep in res.endpoints]
        self.assertNotIn("/api/secret_stream_endpoint", discovered_paths)

    def test_crawler_script_off_origin_redirect_not_parsed(self):
        """Script redirecting off-origin is discarded and not parsed."""
        crawler = WebCrawler(mock_mode=False, max_pages=1, max_depth=1)
        html = '<!doctype html><html><head><script src="/bundle.js"></script></head><body>Home</body></html>'

        def mock_get(url, *args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.history = []
            if url.endswith(".js"):
                resp.url = "https://evil.external.com/bundle.js"  # Redirected off origin!
                resp.headers = {"content-type": "application/javascript"}
                resp.iter_content.return_value = [b"fetch('/api/off_origin_script_endpoint');"]
            else:
                resp.url = url
                resp.headers = {"content-type": "text/html"}
                resp.text = html
                resp.content = html.encode("utf-8")
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            res = crawler.crawl("http://localhost:3000")

        discovered_paths = [ep.path for ep in res.endpoints]
        self.assertNotIn("/api/off_origin_script_endpoint", discovered_paths)


class TestAUD44SPASoft404(unittest.TestCase):
    """AUD-44: SPA soft-404 detection."""

    def test_acceptance_site_with_shared_title_differing_by_over_30_percent_not_soft_404(self):
        """Acceptance: a site with a shared title whose real page differs by more than 30% in content is not flagged as soft-404."""
        detector = SPADetector(base_url="http://localhost:3000", calibrate=False)
        detector.is_spa_catchall = True
        detector.baseline_status = 200
        detector.baseline_title = "My App"
        baseline_content = "<html><head><title>My App</title></head><body>" + "Short baseline " * 10 + "</body></html>"
        detector.baseline_length = len(baseline_content)
        detector.baseline_text = baseline_content

        # Real finding page with the SAME title "My App", but significantly different body (> 30% length difference)
        real_page_content = "<html><head><title>My App</title></head><body>" + "Extensive product details and vulnerable SQL error output: You have an error in your SQL syntax near select! " * 20 + "</body></html>"
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.text = real_page_content

        # Must NOT be flagged as soft-404!
        self.assertFalse(detector.is_soft_404(resp))

    def test_spa_shared_title_similar_length_different_body_not_soft_404(self):
        """Baseline and real page share <title>, differ in length by <10%, and have different bodies (<0.7 similarity)."""
        detector = SPADetector(base_url="http://localhost:3000", calibrate=False)
        detector.is_spa_catchall = True
        detector.baseline_status = 200
        detector.baseline_title = "Shared Portal"
        baseline_content = "<html><head><title>Shared Portal</title></head><body><h1>404 Not Found</h1><p>The requested route does not exist in this client-side single page application. Please return home.</p></body></html>"
        detector.baseline_length = len(baseline_content)
        detector.baseline_text = baseline_content
        detector.baseline_hash = hashlib.md5(baseline_content.encode("utf-8")).hexdigest()

        # Real finding page with the SAME title "Shared Portal", similar length (<10% diff), different body
        real_page_content = "<html><head><title>Shared Portal</title></head><body><h1>User Settings</h1><p>Configure your account notifications, change security passwords, and manage personal profile details.</p></body></html>"
        
        # Verify test preconditions
        len_diff_ratio = abs(len(real_page_content) - len(baseline_content)) / len(baseline_content)
        self.assertLess(len_diff_ratio, 0.10)
        similarity = difflib.SequenceMatcher(None, baseline_content, real_page_content).ratio()
        self.assertLess(similarity, 0.70)

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.text = real_page_content

        # Must NOT be flagged as soft-404!
        self.assertFalse(detector.is_soft_404(resp))

    def test_spa_near_identical_body_is_soft_404(self):
        """SPA fallback response with identical or near-identical body is correctly flagged as soft-404."""
        detector = SPADetector(base_url="http://localhost:3000", calibrate=False)
        detector.is_spa_catchall = True
        detector.baseline_status = 200
        detector.baseline_title = "SPA App"
        baseline_content = "<html><head><title>SPA App</title></head><body><div id='root'></div><script src='/app.js'></script></body></html>"
        detector.baseline_length = len(baseline_content)
        detector.baseline_text = baseline_content
        detector.baseline_hash = hashlib.md5(baseline_content.encode("utf-8")).hexdigest()

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.text = baseline_content + " "

        self.assertTrue(detector.is_soft_404(resp))

    def test_spa_calibration_probes_and_redirect_policy(self):
        """Calibration sends 2-3 random probes (including one with file extension) following redirects."""
        probes_sent = []

        def mock_get(url, *args, **kwargs):
            probes_sent.append((url, kwargs.get("allow_redirects", False)))
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html><head><title>SPA App</title></head><body><div id='root'></div></body></html>"
            resp.headers = {"Content-Type": "text/html"}
            return resp

        session = MagicMock()
        session.get.side_effect = mock_get

        detector = SPADetector(base_url="http://localhost:3000", session=session)

        # Between 2 and 3 probes sent
        self.assertGreaterEqual(len(probes_sent), 2)
        self.assertLessEqual(len(probes_sent), 3)
        # All probes use allow_redirects=True (same as plugins)
        for _, allow_redir in probes_sent:
            self.assertTrue(allow_redir)
        # At least one probe has a file extension (e.g. .html or .txt)
        has_ext = any(url.endswith((".html", ".txt", ".json")) for url, _ in probes_sent)
        self.assertTrue(has_ext, "Expected at least one probe with file extension")
        self.assertTrue(detector.is_spa_catchall)

    def test_engine_calibrates_once_and_shares_with_plugins(self):
        """Engine calibrates SPADetector once and shares the instance across all plugins."""
        engine = Engine(mock_mode=False)
        engine.load_plugins()

        mock_detector = MagicMock(spec=SPADetector)
        with patch("core.engine.SPADetector", return_value=mock_detector) as mock_spa_cls:
            engine.calibrate_spa_detector("http://localhost:3000")
            mock_spa_cls.assert_called_once()
            self.assertIs(engine.spa_detector, mock_detector)

            # Injected into plugins
            for p in engine.plugins:
                if hasattr(p, "get_spa_detector"):
                    self.assertIs(p.get_spa_detector(), mock_detector)


class TestAUD45Enricher(unittest.TestCase):
    """AUD-45: Enricher mock mode zero HTTP calls, disk cache with TTL, and NVD API key."""

    def test_acceptance_mock_mode_zero_http_calls(self):
        """Acceptance: with mock mode on, enriching a finding that has a cve_id makes zero HTTP calls."""
        enricher = Enricher(mock_mode=True)
        findings = [
            Finding(
                id="TEST-001",
                title="Vulnerability with CVE",
                severity="High",
                host="127.0.0.1",
                port=80,
                description="Test finding",
                raw_output="CVE-2021-44228",
                cve_id="CVE-2021-44228",
            )
        ]

        with patch("requests.get") as mock_get:
            enriched = enricher.enrich(findings)
            mock_get.assert_not_called()

        self.assertEqual(len(enriched), 1)

    def test_disk_cache_with_ttl(self):
        """Enricher reads and writes disk cache with TTL at data/cve_cache.json."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_file = os.path.join(tmp_dir, "cve_cache.json")
            initial_cache = {
                "CVE-2020-0001": {
                    "timestamp": time.time(),
                    "data": {
                        "cvss_score": 7.5,
                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0001"],
                    },
                },
                "CVE-2010-9999": {
                    "timestamp": time.time() - (86400 * 40),  # Expired (> 30 days)
                    "data": {
                        "cvss_score": 5.0,
                        "references": [],
                    },
                },
            }
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(initial_cache, f)

            enricher = Enricher(mock_mode=False, cache_path=cache_file, ttl_days=30)

            # Hit unexpired cache without HTTP call
            with patch("requests.get") as mock_get:
                finding = Finding(id="F-1", title="Hit", severity="High", host="127.0.0.1", port=80, description="D", raw_output="R", cve_id="CVE-2020-0001")
                enricher.enrich([finding])
                mock_get.assert_not_called()
                self.assertEqual(finding.cvss_score, 7.5)

            # Expired cache triggers fetch and writes updated entry to disk cache
            mock_nvd_resp = MagicMock()
            mock_nvd_resp.status_code = 200
            mock_nvd_resp.json.return_value = {
                "vulnerabilities": [{
                    "cve": {
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.8}}]},
                        "references": [{"url": "https://example.com/ref"}],
                    }
                }]
            }
            with patch("requests.get", return_value=mock_nvd_resp) as mock_get:
                finding_exp = Finding(id="F-2", title="Exp", severity="Medium", host="127.0.0.1", port=80, description="D", raw_output="R", cve_id="CVE-2010-9999")
                enricher.enrich([finding_exp])
                mock_get.assert_called_once()
                self.assertEqual(finding_exp.cvss_score, 6.8)

            # Verify persisted to disk cache
            with open(cache_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertIn("CVE-2010-9999", saved)
            self.assertEqual(saved["CVE-2010-9999"]["data"]["cvss_score"], 6.8)

    def test_nvd_api_key_header_when_configured(self):
        """Enricher sends apiKey header when NVD_API_KEY environment variable or config is set."""
        enricher = Enricher(mock_mode=False, cache_path=None)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch.dict(os.environ, {"NVD_API_KEY": "test-secret-key"}):
            with patch("requests.get", return_value=mock_resp) as mock_get:
                enricher._fetch_from_nvd("CVE-2023-1234")
                mock_get.assert_called_once()
                _, kwargs = mock_get.call_args
                headers = kwargs.get("headers", {})
                self.assertEqual(headers.get("apiKey"), "test-secret-key")

    def test_enricher_default_uses_config_mock_mode(self):
        """When mock_mode is None, Enricher uses config.MOCK_MODE. In mock mode, 0 HTTP calls."""
        with patch("config.MOCK_MODE", True):
            enricher = Enricher()  # no args
            finding = Finding(
                id="TEST-DEFAULT-MOCK",
                title="Vulnerability with CVE",
                severity="High",
                host="127.0.0.1",
                port=80,
                description="Test finding",
                raw_output="CVE-2021-44228",
                cve_id="CVE-2021-44228",
            )
            with patch("intelligence.enricher.requests.get") as mock_get:
                enricher.enrich([finding])
                self.assertEqual(mock_get.call_count, 0)


if __name__ == "__main__":
    unittest.main()
