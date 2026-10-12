import unittest
import hashlib
import json
import dataclasses
import pkgutil
import importlib

from core.models import Finding, VulnType, Report, ScanResult
from core.engine import Engine
from intelligence.delta import DeltaAnalyzer
from intelligence.correlator import Correlator
from plugins.base_plugin import BaseScanner
from plugins.misconfig_plugin import MisconfigScanner
from plugins.cors_plugin import CORSScanner
from plugins.csrf_plugin import CSRFScanner
from plugins.nikto_plugin import NiktoPlugin
import plugins


class TestFindingIdentity(unittest.TestCase):
    """Unit tests for Batch 13: AUD-34, AUD-35, AUD-36."""

    def test_finding_fields_exist_and_enum_defined(self):
        """AUD-34: Finding has vuln_type, endpoint, param, method, evidence, fingerprint."""
        self.assertTrue(issubclass(VulnType, str))
        self.assertIn("sqli", [v.value for v in VulnType])
        self.assertIn("xss", [v.value for v in VulnType])

        f = Finding(
            id="FIND-001",
            title="SQL Injection",
            severity="High",
            host="example.com",
            port=443,
            description="SQL injection in search",
            raw_output="test output",
            vuln_type=VulnType.SQLI,
            endpoint="/search",
            param="q",
            method="GET",
            evidence="payload ' OR 1=1-- returned 200",
        )
        self.assertEqual(f.vuln_type, "sqli")
        self.assertEqual(f.endpoint, "/search")
        self.assertEqual(f.param, "q")
        self.assertEqual(f.method, "GET")
        self.assertEqual(f.evidence, "payload ' OR 1=1-- returned 200")
        self.assertIsNotNone(f.fingerprint)
        self.assertEqual(len(f.fingerprint), 64)

    def test_fingerprint_calculation_structured(self):
        """AUD-34: sha256 of tool|vuln_type|method|endpoint|param."""
        f = Finding(
            id="SQLI-001",
            title="SQLi in /search",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/search",
            param="q",
            method="GET",
        )
        expected_raw = "sqli_scanner|sqli|GET|/search|q"
        expected_fp = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()
        self.assertEqual(f.fingerprint, expected_fp)

    def test_fingerprint_fallback_when_structured_absent(self):
        """AUD-34: fallback to tool|title when structured fields absent."""
        f = Finding(
            id="OLD-001",
            title="Old Style Vulnerability",
            severity="Medium",
            host="example.com",
            port=80,
            description="old desc",
            raw_output="old raw",
            tool_name="nmap_scanner",
        )
        expected_raw = "nmap_scanner|Old Style Vulnerability"
        expected_fp = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()
        self.assertEqual(f.fingerprint, expected_fp)

    def test_loading_old_report_json(self):
        """AUD-34: Loading an old report JSON without new fields works and computes fingerprints."""
        old_json = {
            "target": "http://legacy.test",
            "timestamp": "2025-01-01T00:00:00",
            "all_findings": [
                {
                    "id": "LEGACY-001",
                    "title": "Legacy Issue",
                    "severity": "Low",
                    "host": "legacy.test",
                    "port": 80,
                    "description": "legacy description",
                    "raw_output": "legacy output",
                    "tool_name": "legacy_tool",
                }
            ],
            "scan_results": [],
            "summary": {"total": 1},
        }
        valid_fields = {fld.name for fld in dataclasses.fields(Finding)}
        findings = [Finding(**{k: v for k, v in f.items() if k in valid_fields}) for f in old_json["all_findings"]]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "LEGACY-001")
        self.assertIsNone(findings[0].vuln_type)
        expected_raw = "legacy_tool|Legacy Issue"
        self.assertEqual(findings[0].fingerprint, hashlib.sha256(expected_raw.encode("utf-8")).hexdigest())

    def test_all_plugins_mock_output_has_vuln_type(self):
        """AUD-34: Every plugin's mock output sets vuln_type."""
        for importer, modname, _ in pkgutil.iter_modules(plugins.__path__):
            if modname in ("base_plugin", "mock_plugin"):
                continue
            mod = importlib.import_module(f"plugins.{modname}")
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseScanner) and attr is not BaseScanner:
                    plugin = attr(mock_mode=True)
                    mock_out = plugin._get_mock_output()
                    findings = mock_out.get("findings", [])
                    for f in findings:
                        self.assertIn(
                            "vuln_type",
                            f,
                            f"Plugin {modname} finding {f.get('id')} missing vuln_type in mock output",
                        )
                        self.assertTrue(
                            f["vuln_type"],
                            f"Plugin {modname} finding {f.get('id')} has empty vuln_type",
                        )

    def test_delta_compares_by_fingerprint_same_id_different_content(self):
        """AUD-35: Two findings with same id but different titles/endpoints -> 1 new, 1 fixed, 0 unchanged."""
        analyzer = DeltaAnalyzer()
        # Previous report: SQLI-001 on /login
        prev_finding = Finding(
            id="SQLI-001",
            title="SQL Injection on /login",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/login",
            param="user",
            method="POST",
        )
        prev_report = Report(target="example.com", timestamp="2025-01-01", all_findings=[prev_finding])

        # Current report: SQLI-001 on /search (same id, different endpoint/title)
        curr_finding = Finding(
            id="SQLI-001",
            title="SQL Injection on /search",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/search",
            param="q",
            method="GET",
        )
        curr_report = Report(target="example.com", timestamp="2025-01-02", all_findings=[curr_finding])

        delta = analyzer.compare(curr_report, prev_report)
        self.assertEqual(delta["summary"]["new_count"], 1)
        self.assertEqual(delta["summary"]["fixed_count"], 1)
        self.assertEqual(delta["summary"]["unchanged_count"], 0)

    def test_delta_old_reports_without_fingerprint(self):
        """AUD-35: Delta computes fingerprint on load for old reports."""
        analyzer = DeltaAnalyzer()
        prev_data = {
            "all_findings": [
                {
                    "id": "SQLI-001",
                    "title": "SQL Injection on /login",
                    "tool_name": "sqli_scanner",
                }
            ]
        }
        curr_findings = [
            {
                "id": "SQLI-001",
                "title": "SQL Injection on /search",
                "tool_name": "sqli_scanner",
            }
        ]
        delta = analyzer.compare_with_dict(curr_findings, prev_data)
        self.assertEqual(delta["summary"]["new_count"], 1)
        self.assertEqual(delta["summary"]["fixed_count"], 1)
        if "unchanged_count" in delta["summary"]:
            self.assertEqual(delta["summary"]["unchanged_count"], 0)

    def test_correlator_deduplicates_identical_findings(self):
        """AUD-36: Two identical findings -> one with merged evidence/references."""
        correlator = Correlator()
        f1 = Finding(
            id="SQLI-001",
            title="SQLi in search",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/search",
            param="q",
            method="GET",
            evidence="evidence 1",
            references=["ref1"],
        )
        f2 = Finding(
            id="SQLI-001",
            title="SQLi in search",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/search",
            param="q",
            method="GET",
            evidence="evidence 2",
            references=["ref2"],
        )
        result = correlator.link_related([f1, f2])
        self.assertEqual(len(result), 1)
        self.assertIn("ref1", result[0].references)
        self.assertIn("ref2", result[0].references)
        self.assertIn("evidence 1", result[0].evidence)
        self.assertIn("evidence 2", result[0].evidence)

    def test_correlator_link_related_idempotency(self):
        """AUD-36: Running link_related twice yields the same references as running it once."""
        correlator = Correlator()
        f1 = Finding(
            id="SQLI-001",
            title="SQLi in search",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/search",
            param="q",
            method="GET",
        )
        f2 = Finding(
            id="XSS-001",
            title="XSS in search",
            severity="Medium",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="xss_scanner",
            vuln_type="xss",
            endpoint="/search",
            param="q",
            method="GET",
        )
        once = correlator.link_related([f1, f2])
        refs_f1_once = list(once[0].references or [])
        refs_f2_once = list(once[1].references or [])

        twice = correlator.link_related(once)
        refs_f1_twice = list(twice[0].references or [])
        refs_f2_twice = list(twice[1].references or [])

        self.assertEqual(refs_f1_once, refs_f1_twice)
        self.assertEqual(refs_f2_once, refs_f2_twice)

    def test_correlator_groups_by_endpoint_and_param_not_host_port(self):
        """AUD-36: Findings on different endpoints/params are not linked."""
        correlator = Correlator()
        f1 = Finding(
            id="SQLI-001",
            title="SQLi on /search",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="sqli_scanner",
            vuln_type="sqli",
            endpoint="/search",
            param="q",
            method="GET",
        )
        f2 = Finding(
            id="AUTH-001",
            title="Auth on /login",
            severity="High",
            host="example.com",
            port=443,
            description="desc",
            raw_output="raw",
            tool_name="auth_scanner",
            vuln_type="auth",
            endpoint="/login",
            param="user",
            method="POST",
        )
        result = correlator.link_related([f1, f2])
        self.assertEqual(len(result), 2)
        # Since they are on different endpoints, neither should get a "Related findings" link to the other
        for r in result:
            related_refs = [ref for ref in (r.references or []) if "Related findings" in ref]
            self.assertEqual(len(related_refs), 0)

    def test_all_plugins_mock_findings_distinct_fingerprints(self):
        """AUD-34: Every plugin's mock output findings have pairwise distinct fingerprints."""
        engine = Engine(mock_mode=True)
        for importer, modname, _ in pkgutil.iter_modules(plugins.__path__):
            if modname in ("base_plugin", "mock_plugin"):
                continue
            mod = importlib.import_module(f"plugins.{modname}")
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseScanner) and attr is not BaseScanner:
                    plugin = attr(mock_mode=True)
                    mock_out = plugin._get_mock_output()
                    raw_findings = mock_out.get("findings", [])
                    fs = engine._dict_to_findings(raw_findings)
                    self.assertEqual(
                        len({f.fingerprint for f in fs}),
                        len(fs),
                        f"Plugin {modname} has duplicate mock finding fingerprints!",
                    )

    def test_correlator_preserves_distinct_titles_on_all_mock_findings(self):
        """AUD-34/AUD-36: Correlator.link_related on combined mock findings drops zero distinct titles."""
        engine = Engine(mock_mode=True)
        all_mock_findings = []
        for importer, modname, _ in pkgutil.iter_modules(plugins.__path__):
            if modname in ("base_plugin", "mock_plugin"):
                continue
            mod = importlib.import_module(f"plugins.{modname}")
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseScanner) and attr is not BaseScanner:
                    plugin = attr(mock_mode=True)
                    mock_out = plugin._get_mock_output()
                    raw_findings = mock_out.get("findings", [])
                    all_mock_findings.extend(engine._dict_to_findings(raw_findings))

        distinct_titles_before = {f.title for f in all_mock_findings}
        correlator = Correlator()
        linked = correlator.link_related(all_mock_findings)
        distinct_titles_after = {f.title for f in linked}
        self.assertEqual(len(distinct_titles_before), len(distinct_titles_after))

    def test_misconfig_real_mode_distinct_fingerprints(self):
        """AUD-34: Real-mode misconfig_plugin.parse_output with ≥2 missing headers and multiple misconfigs."""
        scanner = MisconfigScanner(mock_mode=False)
        scanner.results = [
            {
                "id": "MISCONF-HDR-001",
                "title": "Missing security header: Strict-Transport-Security",
                "severity": "Medium",
                "host": "localhost",
                "port": 80,
                "description": "Missing HSTS",
                "raw_output": "Strict-Transport-Security missing",
                "param": "Strict-Transport-Security",
            },
            {
                "id": "MISCONF-HDR-002",
                "title": "Missing security header: Content-Security-Policy",
                "severity": "Low",
                "host": "localhost",
                "port": 80,
                "description": "Missing CSP",
                "raw_output": "Content-Security-Policy missing",
                "param": "Content-Security-Policy",
            },
            {
                "id": "MISCONF-CORS-003",
                "title": "CORS wildcard Access-Control-Allow-Origin",
                "severity": "Medium",
                "host": "localhost",
                "port": 80,
                "description": "CORS wildcard",
                "raw_output": "Access-Control-Allow-Origin: *",
                "param": "acao_wildcard",
            },
            {
                "id": "MISCONF-INFO-004",
                "title": "Information disclosure: Server",
                "severity": "Info",
                "host": "localhost",
                "port": 80,
                "description": "Server header discloses Apache",
                "raw_output": "Server: Apache/2.4.41",
                "param": "Server",
            },
        ]
        parsed = scanner.parse_output()
        engine = Engine(mock_mode=False)
        findings = engine._dict_to_findings(parsed["findings"])
        self.assertEqual(len(findings), 4)
        fingerprints = {f.fingerprint for f in findings}
        self.assertEqual(len(fingerprints), 4)

    def test_cors_real_mode_distinct_fingerprints(self):
        """AUD-34: CORSScanner real-mode with wildcard_origin, credentials_wildcard, origin_reflection on /api/."""
        scanner = CORSScanner(mock_mode=False)
        scanner.target = "http://localhost:3000"
        scanner.results = [
            {
                "type": "wildcard_origin",
                "path": "/api/",
                "severity": "Medium",
                "detail": "Wildcard origin",
                "acao": "*",
                "acac": "",
            },
            {
                "type": "credentials_wildcard",
                "path": "/api/",
                "severity": "High",
                "detail": "Credentials wildcard",
                "acao": "*",
                "acac": "true",
            },
            {
                "type": "origin_reflection",
                "path": "/api/",
                "severity": "High",
                "detail": "Origin reflection",
                "acao": "https://evil.com",
                "acac": "true",
                "evil_origin": "https://evil.com",
            },
        ]
        parsed = scanner.parse_output()
        engine = Engine(mock_mode=False)
        findings = engine._dict_to_findings(parsed["findings"])
        self.assertEqual(len(findings), 3)
        self.assertEqual(len({f.fingerprint for f in findings}), 3)
        linked = Correlator().link_related(findings)
        self.assertEqual(len(linked), 3)

    def test_csrf_real_mode_distinct_fingerprints(self):
        """AUD-34: CSRFScanner real-mode with 2 missing SameSite cookies and 1 insecure SameSite=None on /."""
        scanner = CSRFScanner(mock_mode=False)
        scanner.target = "http://localhost:3000"
        scanner.results = [
            {
                "type": "cookie_missing_samesite",
                "path": "/",
                "cookie_name": "session_id",
                "severity": "Low",
                "detail": "Cookie session_id missing SameSite",
                "url": "http://localhost:3000/",
            },
            {
                "type": "cookie_missing_samesite",
                "path": "/",
                "cookie_name": "remember_token",
                "severity": "Low",
                "detail": "Cookie remember_token missing SameSite",
                "url": "http://localhost:3000/",
            },
            {
                "type": "cookie_samesite_none_insecure",
                "path": "/",
                "cookie_name": "auth_cookie",
                "severity": "Medium",
                "detail": "Cookie auth_cookie uses SameSite=None insecurely",
                "url": "http://localhost:3000/",
            },
        ]
        parsed = scanner.parse_output()
        engine = Engine(mock_mode=False)
        findings = engine._dict_to_findings(parsed["findings"])
        self.assertEqual(len(findings), 3)
        self.assertEqual(len({f.fingerprint for f in findings}), 3)
        linked = Correlator().link_related(findings)
        self.assertEqual(len(linked), 3)

    def test_nikto_real_mode_distinct_fingerprints(self):
        """AUD-34: NiktoPlugin parsing lines with same URI but different messages, and server headers."""
        scanner = NiktoPlugin(mock_mode=False)
        scanner.target = "http://localhost:80"
        scanner.raw_output = "\n".join([
            "+ /admin/: Directory indexing found.",
            "+ /admin/: This might be interesting.",
            "+ Server: Apache/2.4.41 (Ubuntu)",
        ])
        parsed = scanner.parse_output()
        engine = Engine(mock_mode=False)
        findings = engine._dict_to_findings(parsed["findings"])
        self.assertEqual(len(findings), 3)
        
        # Verify endpoints
        admin_findings = [f for f in findings if f.endpoint == "/admin/"]
        server_findings = [f for f in findings if f.endpoint == "/"]
        self.assertEqual(len(admin_findings), 2)
        self.assertEqual(len(server_findings), 1)

        # Verify fingerprints are distinct
        self.assertEqual(len({f.fingerprint for f in findings}), 3)
        linked = Correlator().link_related(findings)
        self.assertEqual(len(linked), 3)

    def test_misconfig_title_fallback_when_param_omitted(self):
        """AUD-34: MisconfigScanner parse_output infers param from title when param is omitted."""
        scanner = MisconfigScanner(mock_mode=False)
        scanner.target = "http://localhost:80"
        scanner.results = [
            {
                "id": "MISCONF-HDR-001",
                "title": "Missing security header: Strict-Transport-Security",
                "severity": "Medium",
                "host": "localhost",
                "port": 80,
                "description": "Missing HSTS",
                "raw_output": "Strict-Transport-Security missing",
            },
            {
                "id": "MISCONF-HDR-002",
                "title": "Missing security header: Content-Security-Policy",
                "severity": "Low",
                "host": "localhost",
                "port": 80,
                "description": "Missing CSP",
                "raw_output": "Content-Security-Policy missing",
            },
            {
                "id": "MISCONF-CORS-003",
                "title": "CORS wildcard Access-Control-Allow-Origin",
                "severity": "Medium",
                "host": "localhost",
                "port": 80,
                "description": "CORS wildcard",
                "raw_output": "Access-Control-Allow-Origin: *",
            },
        ]
        parsed = scanner.parse_output()
        self.assertEqual(parsed["findings"][0]["param"], "Strict-Transport-Security")
        self.assertEqual(parsed["findings"][1]["param"], "Content-Security-Policy")
        self.assertEqual(parsed["findings"][2]["param"], "acao_wildcard")
        engine = Engine(mock_mode=False)
        findings = engine._dict_to_findings(parsed["findings"])
        self.assertEqual(len({f.fingerprint for f in findings}), 3)


if __name__ == "__main__":
    unittest.main()

