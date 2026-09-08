"""
Unit tests for AutoSecAudit Plain-English Danger Engine and Code-Fix Recipes.
"""

import unittest
from intelligence.danger_engine import (
    classify_threat_category,
    analyze_real_danger,
    calculate_security_posture,
    CATEGORY_CUSTOMER_DATA,
    CATEGORY_ACCOUNT_TAKEOVER,
    CATEGORY_PHISHING_DEFACEMENT,
    CATEGORY_SERVER_CONTROL
)
from intelligence.recipes import get_fix_recipes, generate_dev_ticket_markdown


class TestDangerEngineAndRecipes(unittest.TestCase):
    """Test suite for threat categorization, posture grades, and fix recipes."""

    def test_sqli_danger_classification(self):
        finding = {
            "id": "SQLI-001",
            "title": "SQL Injection in search parameter",
            "severity": "CRITICAL",
            "parameter": "query",
            "url": "/search"
        }
        category = classify_threat_category(finding)
        self.assertEqual(category, CATEGORY_CUSTOMER_DATA)

        danger = analyze_real_danger(finding)
        self.assertIn("Database", danger["headline"])
        self.assertIn("customer table", danger["what_attacker_can_do"])
        self.assertIn("Critical", danger["business_impact"])

    def test_cors_danger_classification(self):
        finding = {
            "id": "CORS-001",
            "title": "CORS Wildcard with Credentials",
            "severity": "HIGH",
            "url": "/api/profile"
        }
        category = classify_threat_category(finding)
        self.assertEqual(category, CATEGORY_PHISHING_DEFACEMENT)

        danger = analyze_real_danger(finding)
        self.assertIn("Cross-Domain", danger["headline"])
        self.assertIn("malicious website", danger["what_attacker_can_do"])

    def test_auth_danger_classification(self):
        finding = {
            "id": "AUTH-001",
            "title": "Authentication Token Signature Weakness",
            "severity": "HIGH",
            "url": "/api/auth/login"
        }
        category = classify_threat_category(finding)
        self.assertEqual(category, CATEGORY_ACCOUNT_TAKEOVER)

        danger = analyze_real_danger(finding)
        self.assertIn("Authentication", danger["headline"])
        self.assertIn("passwords", danger["what_attacker_can_do"])

    def test_security_posture_calculation(self):
        findings = [
            {"title": "SQLi", "severity": "critical"},
            {"title": "CORS", "severity": "high"},
            {"title": "Headers", "severity": "low"}
        ]
        posture = calculate_security_posture(findings)
        self.assertEqual(posture["grade"], "F")
        self.assertEqual(posture["critical_count"], 1)
        self.assertEqual(posture["high_count"], 1)
        self.assertEqual(len(posture["threat_matrix"]), 4)

        # Secure posture
        clean_posture = calculate_security_posture([])
        self.assertEqual(clean_posture["grade"], "A+")
        self.assertEqual(clean_posture["score"], 100)

    def test_code_recipes_generation(self):
        finding = {
            "id": "SQLI-001",
            "title": "SQL Injection in User Login",
            "parameter": "username",
            "url": "/api/login"
        }
        recipes = get_fix_recipes(finding)
        self.assertIn("nodejs", recipes)
        self.assertIn("python", recipes)
        self.assertIn("nginx", recipes)
        self.assertIn("waf", recipes)

        # Node.js check
        self.assertIn("Parameterized", recipes["nodejs"])
        # Python check
        self.assertIn("SQLAlchemy", recipes["python"])
        # WAF check
        self.assertIn("AutoSec_Block_SQLi", recipes["waf"])

    def test_dev_ticket_markdown_generation(self):
        finding = {
            "id": "SEC-404",
            "title": "Directory Listing Enabled",
            "severity": "MEDIUM",
            "url": "http://localhost:3000/uploads"
        }
        ticket = generate_dev_ticket_markdown(finding, target_url="http://localhost:3000")
        self.assertIn("[SECURITY] Directory Listing Enabled", ticket)
        self.assertIn("Real Danger:", ticket)
        self.assertIn("Recommended Code Fix", ticket)
        self.assertIn("Verification Instructions", ticket)


    def test_report_css_media_print_is_closed(self):
        from pathlib import Path
        template_path = Path("reports/templates/report.html")
        content = template_path.read_text(encoding="utf-8")

        # Ensure @media print is closed before threat-matrix-grid and code-tab-btn
        idx_print = content.find("@media print")
        idx_matrix = content.find(".threat-matrix-grid")
        self.assertNotEqual(idx_print, -1)
        self.assertNotEqual(idx_matrix, -1)
        self.assertLess(idx_print, idx_matrix)

        print_section = content[idx_print:idx_matrix]
        self.assertEqual(print_section.count("{"), print_section.count("}"),
                         "@media print section must be closed before other styles!")

        # Verify .code-tab-btn CSS is defined with explicit styling
        self.assertIn(".code-tab-btn {", content)
        self.assertIn("appearance: none;", content)
        self.assertIn(".code-tab-btn.active {", content)

    def test_view_report_route_enriches_recipes(self):
        import json
        import os
        from ui.app import app
        import config

        # Create a raw mock report without pre-generated recipes in data/reports
        mock_id = "test_raw_enrichment_mock"
        raw_report = {
            "target": "http://localhost:3000",
            "timestamp": "2026-09-08 23:59:59",
            "all_findings": [
                {
                    "id": "AUTH-TEST-001",
                    "title": "BOLA Broken Object Level Authorization",
                    "severity": "HIGH",
                    "description": "User can access other users' baskets.",
                    "remediation": "Validate owner ID."
                }
            ],
            "scan_results": [],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
        }
        json_path = f"{config.REPORTS_DIR}/scan_{mock_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(raw_report, f)

        try:
            client = app.test_client()
            resp = client.get(f"/report/{mock_id}")
            self.assertEqual(resp.status_code, 200)
            html = resp.data.decode("utf-8")

            # Check that recipes are enriched and injected into HTML findingsData
            self.assertIn('"nginx":', html)
            self.assertIn('"nodejs":', html)
            self.assertIn('"python":', html)
            self.assertIn('"waf":', html)
            self.assertIn('"danger":', html)
            self.assertIn('"dev_ticket":', html)
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)


if __name__ == "__main__":
    unittest.main()
