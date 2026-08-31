"""Test PDF generation, safe download headers, report resolution, and theme styling."""
import os
import sys
import json
from pathlib import Path

sys.path.insert(0, ".")

from ui.app import app, _resolve_report_data
from reports.generator import ReportGenerator
import config

print("=" * 60)
print("TESTING: PDF Generation, Safe Downloads & Light Mode Styling")
print("=" * 60)

# 1. Test Report Generator PDF creation
generator = ReportGenerator()
sample_report = {
    "target": "http://localhost:3000",
    "timestamp": "2026-08-31 19:20:31",
    "summary": {"total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
    "all_findings": [
        {
            "id": "SEC-01",
            "title": "SQL Injection on /api/items?q=",
            "severity": "critical",
            "tool_name": "SQLiScanner",
            "owasp_tag": "A03:2021-Injection",
            "cwe_id": "CWE-89",
            "description": "Critical flaw allowing arbitrary database queries & data extraction.\nSecond line detail with special chars test & quotes.",
            "remediation": "Use parameterized queries.\nAudit all inputs with validation middleware."
        },
        {
            "id": "SEC-02",
            "title": "JWT Algorithm None Allowed",
            "severity": "high",
            "tool_name": "JWTScanner",
            "owasp_tag": "A07:2021-Identification and Authentication Failures",
            "cwe_id": "CWE-287",
            "description": "Tokens with alg: none are accepted by the authentication middleware.",
            "remediation": "Enforce signature verification algorithms (RS256 or HS256)."
        }
    ]
}

test_pdf_path = f"{config.REPORTS_DIR}/test_unit_report.pdf"
res = generator.generate_pdf(sample_report, test_pdf_path)
assert os.path.exists(test_pdf_path), "PDF file should be created"
with open(test_pdf_path, "rb") as f:
    pdf_bytes = f.read()
    assert pdf_bytes.startswith(b"%PDF-"), "Generated file should have valid PDF binary header"
print("[PASS] PDF generation produces valid %PDF binary document")

# 2. Test _resolve_report_data helper
sample_json_path = f"{config.REPORTS_DIR}/scan_test_unit_sample.json"
with open(sample_json_path, "w", encoding="utf-8") as f:
    json.dump(sample_report, f)

data, resolved_id = _resolve_report_data("test_unit_sample")
assert data is not None, "Should resolve by direct clean_id"
assert resolved_id == "test_unit_sample"
print("[PASS] Report resolution resolves clean_id directly")

# Test resolution via timestamp formatting
data2, resolved_id2 = _resolve_report_data("20260831_192031")
assert data2 is not None, "Should resolve via timestamp match"
print("[PASS] Report resolution resolves via normalized timestamp fallback")

# 3. Test /download_pdf/<report_id> route and safe download headers
with app.test_client() as client:
    resp = client.get("/download_pdf/test_unit_sample")
    assert resp.status_code == 200, f"Expected 200 but got {resp.status_code}"
    assert "application/pdf" in resp.headers.get("Content-Type", ""), "Content-Type must be application/pdf"
    assert "attachment" in resp.headers.get("Content-Disposition", ""), "Content-Disposition must be attachment"
    assert "report_test_unit_sample.pdf" in resp.headers.get("Content-Disposition", "")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff", "Must include nosniff security header"
    assert resp.data.startswith(b"%PDF-"), "Response data must be a valid PDF"
    print("[PASS] /download_pdf endpoint returns 200 with application/pdf and safe download headers")

# 4. Test /download/<report_id> route for JSON
with app.test_client() as client:
    resp = client.get("/download/test_unit_sample")
    assert resp.status_code == 200, f"Expected 200 but got {resp.status_code}"
    assert "application/json" in resp.headers.get("Content-Type", ""), "Content-Type must be application/json"
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    data_json = json.loads(resp.data.decode("utf-8"))
    assert data_json.get("target") == "http://localhost:3000"
    print("[PASS] /download endpoint returns 200 with application/json and attachment header")

# 5. Test Light Mode CSS tokens and component rules in landing.html
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert '[data-theme="light"]' in html, "Landing page must contain [data-theme=light] rules"
    assert '[data-theme="light"] .flow-step-node' in html, "Landing page must style flow-step-node in light mode"
    assert '[data-theme="light"] .pipeline-meta' in html, "Landing page must style pipeline-meta in light mode"
    assert '[data-theme="light"] .value-chip-row' in html, "Landing page must style value-chip-row in light mode"
    assert '[data-theme="light"] .attack-graph-card' in html, "Landing page must style attack-graph-card in light mode"
    assert '[data-theme="light"] .action-box' in html, "Landing page must style action-box in light mode"
    assert '[data-theme="light"] .findings-table-wrap' in html, "Landing page must style findings-table-wrap in light mode"
    print("[PASS] Landing page includes full suite of light theme component CSS overrides")

# Clean up test artifacts
for p in [test_pdf_path, sample_json_path, f"{config.REPORTS_DIR}/report_test_unit_sample.pdf"]:
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass

print()
print("=" * 60)
print("ALL PDF & LIGHT MODE TESTS PASSED!")
print("=" * 60)
