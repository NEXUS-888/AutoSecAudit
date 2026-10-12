"""
Unit tests for Batch 14: Classification & Grading (AUD-37, AUD-38, AUD-39).
"""

import unittest
from unittest.mock import MagicMock, patch
import io
import sys

from core.models import Finding, VulnType
from intelligence.taxonomy import (
    TAXONOMY_ENTRIES,
    get_taxonomy,
    infer_taxonomy_from_text,
    CATEGORY_CUSTOMER_DATA,
    CATEGORY_ACCOUNT_TAKEOVER,
    CATEGORY_PHISHING_DEFACEMENT,
    CATEGORY_SERVER_CONTROL,
)
from intelligence.compliance import ComplianceMapper
from intelligence.danger_engine import (
    classify_threat_category,
    calculate_security_posture,
)
from intelligence.remediation import get_remediation, enrich_with_remediation
from intelligence.recipes import get_fix_recipes
from core.dev_detector import detect_dev_environment, tag_dev_artifact_finding
from main import run_scan


class TestAUD37UnifiedTaxonomy(unittest.TestCase):
    """Test suite for AUD-37: Unified Taxonomy & Classifier Disagreements."""

    def test_taxonomy_covers_all_vuln_types(self):
        """All 21 VulnType enum values must have entries in the canonical taxonomy."""
        for v in VulnType:
            tax = get_taxonomy(v.value)
            self.assertIsNotNone(tax, f"Missing taxonomy for VulnType: {v.value}")
            self.assertTrue(tax.owasp.startswith("A"), f"Invalid OWASP tag for {v.value}")
            self.assertTrue(tax.cwe.startswith("CWE-"), f"Invalid CWE for {v.value}")
            self.assertTrue(tax.pci.startswith("PCI-DSS"), f"Invalid PCI for {v.value}")
            self.assertIn(
                tax.danger_category,
                [CATEGORY_CUSTOMER_DATA, CATEGORY_ACCOUNT_TAKEOVER, CATEGORY_PHISHING_DEFACEMENT, CATEGORY_SERVER_CONTROL],
            )
            self.assertTrue(tax.remediation_key)
            self.assertTrue(tax.recipe_key)

    def test_compliance_mapper_never_overwrites_plugin_owasp_tag(self):
        """ComplianceMapper must never overwrite a plugin-provided OWASP tag or CWE."""
        mapper = ComplianceMapper()
        # Finding with SQL injection in title and "Login Bypass", but already tagged A03:2021
        finding = Finding(
            id="SQLI-001",
            title="SQL Injection Login Bypass",
            severity="Critical",
            host="localhost",
            port=80,
            description="Bypasses login authentication via SQL injection",
            raw_output="",
            owasp_tag="A03:2021",
            cwe_id="CWE-89",
            pci_dss="PCI-DSS 6.2.4",
            vuln_type="sqli",
        )
        mapped = mapper.map_findings([finding])[0]
        self.assertEqual(mapped.owasp_tag, "A03:2021")
        self.assertEqual(mapped.cwe_id, "CWE-89")
        self.assertEqual(mapped.pci_dss, "PCI-DSS 6.2.4")

    def test_sqli_login_bypass_classified_as_injection_and_customer_data(self):
        """SQLi login bypass must be mapped to A03:2021 (not A01 Broken Access Control) and customer_data_theft."""
        mapper = ComplianceMapper()
        finding = Finding(
            id="SQLI-002",
            title="SQL Injection Login Bypass",
            severity="Critical",
            host="localhost",
            port=80,
            description="SQL query concatenation allows login bypass",
            raw_output="",
            vuln_type="sqli",
        )
        mapped = mapper.map_findings([finding])[0]
        self.assertEqual(mapped.owasp_tag, "A03:2021")
        self.assertEqual(mapped.cwe_id, "CWE-89")

        cat = classify_threat_category(finding)
        self.assertEqual(cat, CATEGORY_CUSTOMER_DATA)

    def test_dev_environment_header_artifact_not_customer_data_theft(self):
        """Header findings marked '[Dev Environment Artifact]' must NOT match 'env' or become customer_data_theft."""
        finding = {
            "title": "Strict-Transport-Security Header Missing [Dev Environment Artifact]",
            "description": "Running in Vite development environment",
            "severity": "Info",
            "tool_name": "nikto_plugin",
        }
        cat = classify_threat_category(finding)
        self.assertEqual(cat, CATEGORY_PHISHING_DEFACEMENT)
        self.assertNotEqual(cat, CATEGORY_CUSTOMER_DATA)

    def test_oauth_title_not_classified_as_auth_by_alone_keyword(self):
        """A title with 'OAuth' must not match word-boundary 'auth' alone to become account_takeover."""
        # e.g., OAuth misconfiguration or info disclosure
        tax = infer_taxonomy_from_text("OAuth provider discovery endpoint response leak")
        # Should not match auth
        if tax:
            self.assertNotEqual(tax.vuln_type, "auth")

        cat = classify_threat_category({
            "title": "OAuth provider discovery endpoint leak",
            "description": "Public OAuth provider metadata",
            "tool_name": "generic_scanner",
        })
        self.assertNotEqual(cat, CATEGORY_ACCOUNT_TAKEOVER)

    def test_remediation_lookup_via_vuln_type_without_free_text(self):
        """get_remediation should use vuln_type without requiring 'Type:' in description."""
        finding = Finding(
            id="T-001",
            title="Database Injection",
            severity="Critical",
            host="localhost",
            port=80,
            description="Parameter id is injectable without parameterized queries",
            raw_output="",
            vuln_type="sqli",
        )
        advice = get_remediation(finding)
        self.assertIsNotNone(advice)
        self.assertIn("parameterized queries", advice.lower())

    def test_recipes_lookup_via_vuln_type(self):
        """get_fix_recipes should resolve recipes via vuln_type."""
        recipes = get_fix_recipes({
            "vuln_type": "cors",
            "title": "Unrestricted Origin Allowed",
            "url": "/api/v1/user",
        })
        self.assertIn("cors", recipes["nodejs"].lower())
        self.assertIn("AutoSec_Enforce_CORS", recipes["waf"])

    def test_open_redirect_title_with_header_gets_redirect_recipe_not_helmet(self):
        """Open redirect with 'header' in title must get redirect recipe, not helmet."""
        recipes = get_fix_recipes({
            "vuln_type": "open_redirect",
            "title": "Open Redirect via Location header",
            "url": "https://example.com/login?redirect=https://evil.com",
        })
        self.assertIn("safeRedirect", recipes["nodejs"])
        self.assertNotIn("helmet", recipes["nodejs"])

    def test_finding_without_type_resolves_remediation_via_remediation_key(self):
        """A finding without 'Type:' in description resolves advice via taxonomy remediation_key."""
        finding = Finding(
            id="T-002",
            title="SQL Injection in users API",
            severity="High",
            host="localhost",
            port=80,
            description="parameter query is vulnerable",
            raw_output="",
            vuln_type="sqli",
            tool_name="sqli_scanner",
        )
        advice = get_remediation(finding)
        self.assertIsNotNone(advice)
        self.assertIn("parameterized queries", advice.lower())

    def test_exposed_dot_env_infers_secret_exposure(self):
        """Exposed .env file must infer secret_exposure taxonomy."""
        tax = infer_taxonomy_from_text("Exposed .env file found on root")
        self.assertIsNotNone(tax)
        self.assertEqual(tax.vuln_type, "secret_exposure")
        self.assertEqual(tax.danger_category, CATEGORY_CUSTOMER_DATA)

        cat = classify_threat_category({
            "title": "Exposed .env file",
            "description": "Sensitive credentials leaked in .env",
            "tool_name": "generic_scanner",
        })
        self.assertEqual(cat, CATEGORY_CUSTOMER_DATA)

    def test_compliance_mapper_preserves_plugin_disagreement_tag(self):
        """ComplianceMapper must preserve plugin-provided owasp_tag even if vuln_type differs."""
        mapper = ComplianceMapper()
        finding = Finding(
            id="AUTH-001",
            title="Broken Authentication",
            severity="High",
            host="localhost",
            port=80,
            description="Broken auth",
            raw_output="",
            owasp_tag="A03:2021",
            vuln_type="auth",
        )
        mapped = mapper.map_findings([finding])[0]
        self.assertEqual(mapped.owasp_tag, "A03:2021")

    def test_infer_taxonomy_from_tool_name_normalized(self):
        """Inferring taxonomy from text with tool names containing underscores like sqli_scanner."""
        tax = infer_taxonomy_from_text("Scanner sqli_scanner reported an issue")
        self.assertIsNotNone(tax)
        self.assertEqual(tax.vuln_type, "sqli")

    def test_title_only_misconfig_and_clickjacking_get_helmet_recipes(self):
        """
        Title-only findings for CSP, clickjacking, or missing headers must reach helmet recipe,
        and threat categories must agree between classify_threat_category and taxonomy.
        """
        # 1. Missing Content-Security-Policy Header
        csp_recipes = get_fix_recipes({"title": "Missing Content-Security-Policy Header"})
        self.assertIn("helmet", csp_recipes["nodejs"])
        csp_tax = infer_taxonomy_from_text("Missing Content-Security-Policy Header")
        self.assertIsNotNone(csp_tax)
        self.assertEqual(csp_tax.vuln_type, "misconfig")
        self.assertEqual(
            classify_threat_category({"title": "Missing Content-Security-Policy Header"}),
            csp_tax.danger_category,
        )

        # 2. Clickjacking: Missing X-Frame-Options
        click_recipes = get_fix_recipes({"title": "Clickjacking: Missing X-Frame-Options"})
        self.assertIn("helmet", click_recipes["nodejs"])
        click_tax = infer_taxonomy_from_text("Clickjacking: Missing X-Frame-Options")
        self.assertIsNotNone(click_tax)
        self.assertEqual(click_tax.vuln_type, "misconfig")
        self.assertEqual(
            classify_threat_category({"title": "Clickjacking: Missing X-Frame-Options"}),
            click_tax.danger_category,
        )

        # 3. Open Redirect via Location header still resolves to open_redirect
        redir_tax = infer_taxonomy_from_text("Open Redirect via Location header")
        self.assertIsNotNone(redir_tax)
        self.assertEqual(redir_tax.vuln_type, "open_redirect")

    def test_remediation_subtype_refinement_priority(self):
        """
        When description includes 'Type: error_based' with matching tool and vuln_type,
        the specific sub-type refinement is used.
        """
        f = Finding(
            id="SQLI-REF-01",
            title="SQL Injection",
            severity="High",
            host="localhost",
            port=80,
            description="Type: error_based\nDatabase syntax error returned",
            raw_output="",
            vuln_type="sqli",
            tool_name="sqli_scanner",
        )
        advice = get_remediation(f)
        self.assertIsNotNone(advice)
        self.assertIn("Suppress database error messages", advice)


class TestAUD38ConfidenceWeightedGrading(unittest.TestCase):
    """Test suite for AUD-38: Confidence-Weighted Security Posture Grading."""

    def test_single_low_confidence_critical_is_not_f(self):
        """A single low-confidence Critical vulnerability must NOT force an automatic 'F'."""
        findings = [
            {
                "fingerprint": "fp_crit_low",
                "title": "Heuristic SQLi",
                "severity": "Critical",
                "confidence": "low",
            }
        ]
        posture = calculate_security_posture(findings)
        self.assertNotEqual(posture["grade"], "F")
        # Base penalty 25 * 0.25 = 6.25 -> Score 94 -> Grade B
        self.assertEqual(posture["grade"], "B")
        self.assertGreaterEqual(posture["score"], 90)

    def test_single_high_confidence_critical_forces_f(self):
        """A single high-confidence Critical vulnerability MUST force an automatic 'F'."""
        findings = [
            {
                "fingerprint": "fp_crit_high",
                "title": "Confirmed SQLi",
                "severity": "Critical",
                "confidence": "high",
            }
        ]
        posture = calculate_security_posture(findings)
        self.assertEqual(posture["grade"], "F")
        self.assertEqual(posture["critical_count"], 1)

    def test_single_medium_confidence_critical_forces_f(self):
        """A single medium-confidence (or default) Critical vulnerability MUST force an automatic 'F'."""
        findings = [
            {
                "fingerprint": "fp_crit_med",
                "title": "Probable SQLi",
                "severity": "Critical",
                "confidence": "medium",
            }
        ]
        posture = calculate_security_posture(findings)
        self.assertEqual(posture["grade"], "F")

    def test_confidence_weighting_penalties(self):
        """Penalties should scale with confidence (high: 1.0, medium: 0.6, low: 0.25)."""
        # High severity finding (base penalty 12)
        p_high = calculate_security_posture([{"fingerprint": "1", "severity": "High", "confidence": "high"}])
        p_med = calculate_security_posture([{"fingerprint": "2", "severity": "High", "confidence": "medium"}])
        p_low = calculate_security_posture([{"fingerprint": "3", "severity": "High", "confidence": "low"}])

        # 100 - (12 * 1.0) = 88
        self.assertEqual(p_high["score"], 88)
        # 100 - round(12 * 0.6 = 7.2) = 93
        self.assertEqual(p_med["score"], 93)
        # 100 - round(12 * 0.25 = 3.0) = 97
        self.assertEqual(p_low["score"], 97)

    def test_fingerprint_deduplication(self):
        """Duplicate findings sharing the same fingerprint must only be counted and penalized once."""
        duplicate_findings = [
            {
                "fingerprint": "dup_fp_123",
                "title": "Missing HSTS Header",
                "severity": "Medium",
                "confidence": "high",
            }
            for _ in range(10)
        ]
        posture = calculate_security_posture(duplicate_findings)
        self.assertEqual(posture["total_findings"], 1)
        self.assertEqual(posture["medium_count"], 1)
        # Medium base 5 * 1.0 = 5 -> Score 95
        self.assertEqual(posture["score"], 95)

    def test_fingerprint_dedup_prefers_higher_confidence_and_severity(self):
        """
        Deduplication must retain the highest confidence and highest severity
        regardless of input ordering.
        """
        low_crit = {
            "fingerprint": "fp_shared_crit",
            "title": "SQLi finding",
            "severity": "Critical",
            "confidence": "low",
        }
        high_crit = {
            "fingerprint": "fp_shared_crit",
            "title": "SQLi finding confirmed",
            "severity": "Critical",
            "confidence": "high",
        }

        # Order 1: low first, high second -> must evaluate to F
        posture1 = calculate_security_posture([low_crit, high_crit])
        self.assertEqual(posture1["grade"], "F")
        self.assertEqual(posture1["critical_count"], 1)

        # Order 2: high first, low second -> must evaluate to F
        posture2 = calculate_security_posture([high_crit, low_crit])
        self.assertEqual(posture2["grade"], "F")
        self.assertEqual(posture2["critical_count"], 1)


class TestAUD39StructuralDevDetection(unittest.TestCase):
    """Test suite for AUD-39: Structural Dev-Environment Detection & CI Gating."""

    def test_free_text_turbopack_does_not_trigger_dev_server(self):
        """Mentioning 'turbopack' in free text body must return None (acceptance criterion)."""
        html = "<p>We moved to turbopack last week!</p>"
        env = detect_dev_environment(html)
        self.assertIsNone(env)

    def test_structural_vite_script_detected(self):
        """<script type='module' src='/@vite/client'> must detect Vite Dev Server (acceptance criterion)."""
        html = '<script type="module" src="/@vite/client"></script>'
        env = detect_dev_environment(html)
        self.assertEqual(env, "Vite Dev Server")

    def test_structural_next_webpack_scripts_detected(self):
        """Next.js and Webpack structural script signatures must be detected."""
        next_html = '<script src="/_next/static/webpack/abc123.js"></script>'
        self.assertEqual(detect_dev_environment(next_html), "Next.js Dev Server")

        webpack_html = '<script src="/__webpack_hmr"></script>'
        self.assertEqual(detect_dev_environment(webpack_html), "Webpack Dev Server")

    def test_server_header_dev_detected(self):
        """Server header containing vite or webpack must detect dev environment."""
        self.assertEqual(detect_dev_environment("", headers={"Server": "Vite / 4.5"}), "Vite Dev Server")
        self.assertEqual(detect_dev_environment("", headers={"Server": "webpack-dev-server"}), "Webpack Dev Server")
        self.assertIsNone(detect_dev_environment("", headers={"Server": "nginx/1.24"}))

    def test_tag_dev_artifact_preserves_original_severity(self):
        """tag_dev_artifact_finding must preserve original_severity before setting severity = 'Info'."""
        finding = {
            "title": "Open CORS Wildcard",
            "severity": "High",
            "description": "Wildcard origin enabled",
        }
        tagged = tag_dev_artifact_finding(finding, "Vite Dev Server")
        self.assertEqual(tagged["severity"], "Info")
        self.assertEqual(tagged["original_severity"], "High")

        # Dataclass instance
        f_obj = Finding(
            id="CORS-1",
            title="Open CORS",
            severity="Medium",
            host="localhost",
            port=5173,
            description="CORS",
            raw_output="",
        )
        tag_dev_artifact_finding(f_obj, "Vite Dev Server")
        self.assertEqual(f_obj.severity, "Info")
        self.assertEqual(f_obj.original_severity, "Medium")

    def test_ci_gating_evaluates_original_severity_unless_flag_passed(self):
        """
        CI gating (--fail-on) evaluates original_severity when dev artifact was downgraded,
        unless --treat-dev-artifacts-as-info is passed.
        """
        from core.models import Report

        f = Finding(
            id="DEV-001",
            title="Missing Security Headers [Dev Environment Artifact]",
            severity="Info",
            host="localhost",
            port=5173,
            description="Dev artifact",
            raw_output="",
            original_severity="High",
        )
        mock_report = Report(
            target="http://localhost:5173",
            timestamp="2026-10-12_200000",
            all_findings=[f],
            summary={"total": 1, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
        )

        with patch("main.validate_target", return_value=True), \
             patch("main.is_target_allowed", return_value=(True, "")), \
             patch("main.ReportGenerator"), \
             patch("main.Engine") as mock_engine_cls:
            engine_inst = MagicMock()
            mock_engine_cls.return_value = engine_inst
            engine_inst.generate_report.return_value = mock_report
            engine_inst._generate_summary.return_value = {"total": 1, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1}
            engine_inst.save_report.return_value = ("report.json", "report.html")

            # 1. Without flag: evaluate against original_severity="High" -> Fail on "high"
            ret_fail = run_scan(
                target="http://localhost:5173",
                fail_on="high",
                mock_mode=True,
                treat_dev_artifacts_as_info=False,
            )
            self.assertEqual(ret_fail, 1)

            # 2. With flag: treat as Info -> Pass on "high"
            ret_pass = run_scan(
                target="http://localhost:5173",
                fail_on="high",
                mock_mode=True,
                treat_dev_artifacts_as_info=True,
            )
            self.assertEqual(ret_pass, 0)


if __name__ == "__main__":
    unittest.main()
