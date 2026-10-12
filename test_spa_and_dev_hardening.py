"""
Unit tests for SPA soft-404 detection, content-type integrity,
secret regex hardening, IDOR JSON validation, and dev-server fingerprinting.
"""

import unittest
from unittest.mock import MagicMock, patch
import hashlib
import requests

from core.spa_detector import SPADetector
from core.dev_detector import detect_dev_environment, tag_dev_artifact_finding
from core.http_client import ScanHttpClient
from plugins.base_plugin import BaseScanner
from plugins.dirbuster_plugin import DirBruteScanner
from plugins.secret_exposure_plugin import SecretExposureScanner, ENV_REGEX
from plugins.auth_plugin import AuthScanner


class TestSPADetector(unittest.TestCase):
    """Test suite for SPA soft-404 detector."""

    def test_spa_catchall_detected_and_soft_404_flagged(self):
        session = MagicMock(spec=requests.Session)
        
        spa_html = """<!doctype html>
<html>
<head><title>My Vite App</title></head>
<body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body>
</html>"""

        probe_resp = MagicMock(spec=requests.Response)
        probe_resp.status_code = 200
        probe_resp.text = spa_html
        probe_resp.headers = {"Content-Type": "text/html; charset=utf-8"}

        session.get.return_value = probe_resp

        detector = SPADetector(base_url="http://localhost:5173", session=session)
        self.assertTrue(detector.is_spa_catchall)
        self.assertEqual(detector.baseline_status, 200)

        # 1. Exact match response on /backup.sql
        fake_sql_resp = MagicMock(spec=requests.Response)
        fake_sql_resp.status_code = 200
        fake_sql_resp.text = spa_html
        fake_sql_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.assertTrue(detector.is_soft_404(fake_sql_resp))

        # 2. Similar length HTML response
        slight_variant_resp = MagicMock(spec=requests.Response)
        slight_variant_resp.status_code = 200
        slight_variant_resp.text = spa_html + " "
        slight_variant_resp.headers = {"Content-Type": "text/html"}
        self.assertTrue(detector.is_soft_404(slight_variant_resp))

        # 3. Genuine API JSON response should NOT be flagged as soft-404
        api_resp = MagicMock(spec=requests.Response)
        api_resp.status_code = 200
        api_resp.text = '{"status": "ok", "users": []}'
        api_resp.headers = {"Content-Type": "application/json"}
        self.assertFalse(detector.is_soft_404(api_resp))

    def test_non_spa_returns_normal_404(self):
        session = MagicMock(spec=requests.Session)
        probe_resp = MagicMock(spec=requests.Response)
        probe_resp.status_code = 404
        probe_resp.text = "Not Found"
        probe_resp.headers = {"Content-Type": "text/plain"}
        session.get.return_value = probe_resp

        detector = SPADetector(base_url="http://example.com", session=session)
        self.assertFalse(detector.is_spa_catchall)

        sample_resp = MagicMock(spec=requests.Response)
        sample_resp.status_code = 200
        sample_resp.text = "admin portal"
        sample_resp.headers = {"Content-Type": "text/html"}
        self.assertFalse(detector.is_soft_404(sample_resp))


class TestDevServerDetector(unittest.TestCase):
    """Test suite for dev-server fingerprinting."""

    def test_detect_vite(self):
        html = '<!DOCTYPE html><html><head><script type="module" src="/@vite/client"></script></head><body></body></html>'
        env = detect_dev_environment(html)
        self.assertEqual(env, "Vite Dev Server")

    def test_detect_webpack(self):
        html = '<script src="/webpack-dev-server.js"></script><script>__webpack_hmr</script>'
        env = detect_dev_environment(html)
        self.assertEqual(env, "Webpack Dev Server")

    def test_detect_production_none(self):
        html = '<!DOCTYPE html><html><head><script src="/assets/index-B7y9.js"></script></head><body></body></html>'
        env = detect_dev_environment(html)
        self.assertIsNone(env)

    def test_tag_dev_artifact_finding(self):
        finding = {
            "title": "CORS wildcard Access-Control-Allow-Origin",
            "severity": "Medium",
            "description": "Wildcard origin detected."
        }
        tagged = tag_dev_artifact_finding(finding, "Vite Dev Server")
        self.assertIn("[Dev Environment Artifact]", tagged["title"])
        self.assertEqual(tagged["severity"], "Info")
        self.assertIn("Vite Dev Server", tagged["description"])


class TestDirBruteIntegrity(unittest.TestCase):
    """Test suite for DirBrute content integrity."""

    def test_dirbrute_rejects_spa_html_for_sql_backup(self):
        scanner = DirBruteScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        # Mock requests to simulate SPA catch-all
        spa_html = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'
        
        mini_wordlist = [
            {"path": "/backup.sql", "severity": "Critical", "category": "backup"},
            {"path": "/database.zip", "severity": "Critical", "category": "backup"},
            {"path": "/admin", "severity": "High", "category": "admin_panel"},
        ]
        with patch("plugins.dirbuster_plugin.DIRECTORY_WORDLIST", mini_wordlist), \
             patch.object(ScanHttpClient, "request") as mock_req:
            head_resp = MagicMock(status_code=200, headers={"Content-Type": "text/html"})
            get_resp = MagicMock(status_code=200, text=spa_html, headers={"Content-Type": "text/html"})
            mock_req.side_effect = lambda method, *a, **kw: head_resp if method == "HEAD" else get_resp

            scanner.run()
            output = scanner.parse_output()
            
            # None of the findings should be .sql or .zip backups since they returned HTML!
            for f in output["findings"]:
                self.assertNotIn(".sql", f["description"].lower())
                self.assertNotIn(".zip", f["description"].lower())


class TestSecretExposureHardening(unittest.TestCase):
    """Test suite for secret regex and HTML rejection."""

    def test_env_regex_does_not_match_html_attributes(self):
        html_sample = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script type="module" src="/src/main.tsx"></script>
        </head>
        <body>
            <div id="app" class="container"></div>
        </body>
        </html>
        """
        # Overly broad regex matched name="viewport" or type="module"
        # Hardened regex must NOT match any line in standard HTML
        matches = [m.group(0) for m in ENV_REGEX.finditer(html_sample)]
        self.assertEqual(matches, [])

    def test_env_regex_matches_real_environment_variables(self):
        real_env = """
        # Configuration
        DB_HOST=localhost
        DB_PASSWORD=SuperSecretPass123!
        DATABASE_URL=postgres://user:secret@db.internal:5432/production
        AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
        API_KEY=998877665544332211
        PORT=8080
        SECRET_KEY=long_random_hmac_secret
        """
        matches = [m.group(0) for m in ENV_REGEX.finditer(real_env)]
        self.assertGreater(len(matches), 4)
        self.assertTrue(any("DB_PASSWORD=" in m for m in matches))
        self.assertTrue(any("AWS_SECRET_ACCESS_KEY=" in m for m in matches))


class TestAuthScannerHardening(unittest.TestCase):
    """Test suite for AuthScanner IDOR JSON parsing and rate limiting pre-probe."""

    def test_idor_rejects_html_with_common_words(self):
        scanner = AuthScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        spa_html = """<!doctype html>
        <html><head><meta name="description" content="user portal"></head>
        <body><div id="user-profile">Welcome user, your id is displayed here</div></body></html>"""

        mock_resp = MagicMock(status_code=200, text=spa_html, headers={"Content-Type": "text/html; charset=utf-8"})
        mock_resp.json.side_effect = ValueError("Not JSON")

        with patch.object(ScanHttpClient, "request", return_value=mock_resp):
            scanner._test_idor("http://localhost:5173")
            self.assertEqual(len(scanner.results), 0, "HTML with words 'user', 'id', 'name' must NOT be flagged as IDOR!")

    def test_idor_accepts_genuine_user_json(self):
        scanner = AuthScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        user_json = {"user_id": 101, "email": "alice@example.com", "username": "alice", "role": "admin"}
        mock_resp = MagicMock(status_code=200, headers={"Content-Type": "application/json"})
        mock_resp.json.return_value = user_json
        mock_resp.text = '{"user_id": 101, "email": "alice@example.com"}'

        with patch.object(ScanHttpClient, "request", return_value=mock_resp):
            scanner._test_idor("http://localhost:5173")
            self.assertGreater(len(scanner.results), 0, "Valid JSON user object must be flagged as IDOR!")

    def test_rate_limiting_skips_non_existent_endpoint(self):
        scanner = AuthScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        with patch.object(ScanHttpClient, "request") as mock_req:
            # Pre-check returns 404 Not Found
            mock_req.return_value = MagicMock(status_code=404, headers={"Content-Type": "text/html"})
            scanner._test_rate_limiting("http://localhost:5173")

            # Must NOT report missing rate limiting for non-existent endpoint!
            rate_findings = [r for r in scanner.results if "rate" in r.get("id", "").lower()]
            self.assertEqual(len(rate_findings), 0)


from plugins.cors_plugin import CORSScanner
from plugins.bola_idor_plugin import BOLAIdorScanner
from plugins.misconfig_plugin import MisconfigScanner


class TestCORSScannerDevHardening(unittest.TestCase):
    """Test suite for CORS scanner in dev environments."""

    def test_cors_tagged_in_dev_env(self):
        scanner = CORSScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")
        scanner.set_dev_environment("Vite Dev Server")
        scanner.results.append({
            "path": "/",
            "type": "wildcard_origin",
            "severity": "Medium",
            "acao": "*",
            "acac": "",
            "detail": "ACAO=*",
        })
        output = scanner.parse_output()
        self.assertEqual(len(output["findings"]), 1)
        f = output["findings"][0]
        self.assertIn("[Dev Environment Artifact]", f["title"])
        self.assertEqual(f["severity"], "Info")


class TestBOLAIDORHardening(unittest.TestCase):
    """Test suite for BOLA/IDOR SPA rejection."""

    def test_bola_rejects_spa_html(self):
        scanner = BOLAIdorScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        spa_html = "<!doctype html><html><title>App</title><body>Welcome user id 123</body></html>"
        mock_resp = MagicMock(status_code=200, text=spa_html, headers={"Content-Type": "text/html"})
        mock_resp.json.side_effect = ValueError("Not JSON")

        with patch.object(ScanHttpClient, "request", return_value=mock_resp):
            scanner.run()
            self.assertEqual(len(scanner.results), 0)

    def test_bola_accepts_genuine_user_json(self):
        scanner = BOLAIdorScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        user_json = {"user_id": 1, "email": "victim@example.com"}
        user_resp = MagicMock(status_code=200, headers={"Content-Type": "application/json"})
        user_resp.json.return_value = user_json
        user_resp.text = '{"user_id": 1, "email": "victim@example.com"}'

        probe_resp = MagicMock(status_code=404, text="Not Found", headers={"Content-Type": "text/plain"})

        def mock_get(method, url, *args, **kwargs):
            if "autosec-probe" in url:
                return probe_resp
            return user_resp

        with patch.object(ScanHttpClient, "request", side_effect=mock_get):
            scanner.run()
            self.assertGreater(len(scanner.results), 0)


from plugins.xss_plugin import XSSScanner


class TestXSSScannerDevHardening(unittest.TestCase):
    """Test suite for XSS scanner security header tagging in dev environments."""

    def test_xss_missing_headers_tagged_in_dev_env_live(self):
        scanner = XSSScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")
        scanner.set_dev_environment("Vite Dev Server")
        scanner.results = [
            {
                "endpoint": "/",
                "payload": "N/A",
                "status_code": 200,
                "type": "missing_header",
                "header_name": "Content-Security-Policy",
                "evidence": "Header 'Content-Security-Policy' not present",
                "confidence": "high",
            },
            {
                "endpoint": "/search?q=<script>alert(1)</script>",
                "payload": "<script>alert(1)</script>",
                "status_code": 200,
                "type": "reflected_xss",
                "evidence": "<script>alert(1)</script>",
                "confidence": "high",
            },
        ]
        output = scanner.parse_output()
        findings = output["findings"]
        self.assertEqual(len(findings), 2)

        # Header finding must be tagged as Dev Environment Artifact and downgraded to Info
        header_finding = next(f for f in findings if "Content-Security-Policy" in f["title"])
        self.assertIn("[Dev Environment Artifact]", header_finding["title"])
        self.assertEqual(header_finding["severity"], "Info")
        self.assertIn("Vite Dev Server", header_finding["description"])

        # Real reflected XSS finding must remain High severity and NOT tagged
        xss_finding = next(f for f in findings if "Reflected XSS" in f["title"])
        self.assertEqual(xss_finding["severity"], "High")
        self.assertNotIn("[Dev Environment Artifact]", xss_finding["title"])

    def test_xss_mock_mode_tags_headers_in_dev_env(self):
        scanner = XSSScanner(mock_mode=True)
        scanner.configure("http://localhost:5173")
        scanner.set_dev_environment("Vite Dev Server")
        output = scanner.get_standardized_output()
        findings = output["findings"]

        # XSS-003 and XSS-004 are missing headers in mock mode
        header_findings = [f for f in findings if "Header" in f["title"]]
        self.assertGreater(len(header_findings), 0)
        for hf in header_findings:
            self.assertIn("[Dev Environment Artifact]", hf["title"])
            self.assertEqual(hf["severity"], "Info")

        # Reflected and DOM XSS must NOT be downgraded
        vuln_findings = [f for f in findings if "Header" not in f["title"]]
        for vf in vuln_findings:
            self.assertNotIn("[Dev Environment Artifact]", vf["title"])
            self.assertIn(vf["severity"], ["High", "Medium"])


class TestRobotsTxtInformationalClassification(unittest.TestCase):
    """Test suite ensuring robots.txt is classified as informational and non-alarmist."""

    def test_dirbuster_robots_txt_is_informational(self):
        scanner = DirBruteScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")
        scanner.results = [
            {
                "path": "/robots.txt",
                "status_code": 200,
                "status_label": "accessible",
                "content_length": 120,
                "category": "info_disclosure",
                "severity": "Info",
                "confidence": "high",
            }
        ]
        output = scanner.parse_output()
        self.assertEqual(len(output["findings"]), 1)
        finding = output["findings"][0]
        self.assertEqual(finding["severity"], "Info")
        self.assertEqual(finding["title"], "Standard Web File: /robots.txt (Informational)")
        self.assertIn("standard web practice and expected", finding["description"])

    def test_misconfig_robots_txt_is_informational(self):
        scanner = MisconfigScanner(mock_mode=False)
        scanner.configure("http://localhost:5173")

        mock_resp = MagicMock(status_code=200, text="User-agent: *\nDisallow: /admin", headers={"Content-Type": "text/plain"})
        with patch.object(ScanHttpClient, "request", return_value=mock_resp), \
             patch.object(scanner, "is_soft_404", return_value=False):
            scanner.results = []
            scanner._check_sensitive_files("http://localhost:5173")

            robots_findings = [f for f in scanner.results if "robots.txt" in f["title"]]
            self.assertEqual(len(robots_findings), 1)
            f = robots_findings[0]
            self.assertEqual(f["severity"], "Info")
            self.assertEqual(f["title"], "Standard Web File: robots.txt (Informational)")
            self.assertIn("standard web practice and expected", f["description"])


if __name__ == "__main__":
    unittest.main()
