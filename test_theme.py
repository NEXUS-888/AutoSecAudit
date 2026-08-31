"""Test dark/light mode toggle feature."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 8 - Dark/Light Mode Toggle")
print("=" * 50)

from ui.app import app

# Test 1: Home page has theme toggle
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert "themeToggle" in html, "Should have theme toggle button"
    assert "toggleTheme" in html, "Should have toggleTheme function"
    assert "themeIcon" in html, "Should have theme icon SVG"
    print("[PASS] Home page has theme toggle button and JS")

# Test 2: Light theme CSS variables exist
    assert 'data-theme="light"' in html, "Should have [data-theme=light] CSS"
    assert ("#f8fafc" in html or "#f5f5f7" in html), "Light theme should have light background"
    assert ("#0f172a" in html or "#1a1a2e" in html), "Light theme should have dark text color"
    print("[PASS] Light theme CSS variables defined")

# Test 3: Theme persists via localStorage
    assert "localStorage" in html, "Should use localStorage for persistence"
    assert "autosec-theme" in html, "Should use 'autosec-theme' key"
    print("[PASS] Theme persists via localStorage")

# Test 4: History page also has theme toggle
    resp = client.get("/history")
    html = resp.data.decode("utf-8")
    assert "themeToggle" in html or "toggleTheme" in html, "History page should have theme toggle"
    assert 'data-theme="light"' in html, "History should have light theme CSS"
    print("[PASS] History page also supports theme toggle")

# Test 5: Icon switches between sun and moon
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert "M21 12.79A9 9 0 1 1 11.21 3" in html, "Should have moon icon SVG path"
    assert 'r="5"' in html, "Should have sun icon circle"
    print("[PASS] Sun (dark mode) and moon (light mode) icons are present")

# Test 6: Light theme component overrides in landing.html
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert '[data-theme="light"] .flow-step-node' in html, "Flow step nodes must have light mode styling"
    assert '[data-theme="light"] .pipeline-meta' in html, "Pipeline meta must have light mode styling"
    assert '[data-theme="light"] .value-chip-row' in html, "Value chips must have light mode styling"
    assert '[data-theme="light"] .attack-graph-card' in html, "Attack graph card must have light mode styling"
    assert '[data-theme="light"] .action-box' in html, "Action CTA box must have light mode styling"
    assert '[data-theme="light"] .findings-table-wrap' in html, "Findings table must have light mode styling"
    print("[PASS] All landing page components properly configured for light mode")

# Test 7: PDF Generation and Safe Download Headers
import os
import json
import config
from reports.generator import ReportGenerator
from ui.app import _resolve_report_data

generator = ReportGenerator()
sample_report = {
    "target": "http://localhost:3000",
    "timestamp": "2026-08-31 19:20:31",
    "summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
    "all_findings": [
        {
            "id": "SEC-01",
            "title": "SQL Injection",
            "severity": "critical",
            "tool_name": "SQLiScanner",
            "owasp_tag": "A03:2021-Injection",
            "cwe_id": "CWE-89",
            "description": "SQL injection in query parameter.\nPayload: ' OR 1=1--",
            "remediation": "Use parameterized queries."
        }
    ]
}

sample_json_path = f"{config.REPORTS_DIR}/scan_test_theme_sample.json"
with open(sample_json_path, "w", encoding="utf-8") as f:
    json.dump(sample_report, f)

with app.test_client() as client:
    resp = client.get("/download_pdf/test_theme_sample")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert "application/pdf" in resp.headers.get("Content-Type", ""), "MIME type must be application/pdf"
    assert "attachment" in resp.headers.get("Content-Disposition", ""), "Must be attachment"
    assert "report_test_theme_sample.pdf" in resp.headers.get("Content-Disposition", "")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff", "Must enforce nosniff"
    assert resp.data.startswith(b"%PDF-"), "Must be valid PDF binary"
    print("[PASS] PDF generation and safe download headers verified")

for p in [sample_json_path, f"{config.REPORTS_DIR}/report_test_theme_sample.pdf"]:
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
