"""Test finding detail modals feature."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 9 - Finding Detail Modals")
print("=" * 50)

# Test 1: Template has modal elements
from pathlib import Path
template = Path("reports/templates/report.html").read_text(encoding="utf-8")

assert "findingModal" in template, "Should have findingModal element"
assert "openFindingModal" in template, "Should have openFindingModal function"
assert "closeFindingModal" in template, "Should have closeFindingModal function"
assert "navigateFinding" in template, "Should have navigateFinding function"
print("[PASS] Report template has modal HTML and JS functions")

# Test 2: Finding cards are clickable
assert 'onclick="openFindingModal' in template, "Cards should have onclick"
assert "cursor: pointer" in template, "Cards should show pointer cursor"
assert "data-index=" in template, "Cards should have data-index"
print("[PASS] Finding cards are clickable with onclick and cursor: pointer")

# Test 3: Modal has all sections
assert "modalTitle" in template, "Modal should have title"
assert "modalSeverity" in template, "Modal should have severity badge"
assert "modalConfidence" in template, "Modal should have confidence badge"
assert "modalTags" in template, "Modal should have tags section"
assert "modalDesc" in template, "Modal should have description"
assert "modalRefsSection" in template, "Modal should have references section"
assert "modalRemedSection" in template, "Modal should have remediation section"
assert "modalRawSection" in template, "Modal should have raw output section"
print("[PASS] Modal has all sections: title, severity, confidence, tags, desc, refs, remediation, raw")

# Test 4: Modal has navigation
assert "modalPrev" in template, "Should have Previous button"
assert "modalNext" in template, "Should have Next button"
assert "modalCounter" in template, "Should have counter"
print("[PASS] Modal has Previous/Next navigation and counter")

# Test 5: Close mechanisms
assert "Escape" in template, "Should close on Escape key"
assert "backdrop" in template or "e.target === this" in template, "Should close on backdrop click"
print("[PASS] Modal closes on Escape key and backdrop click")

# Test 6: Modal animations
assert "modalFadeIn" in template, "Should have fade-in animation"
assert "modalSlideIn" in template, "Should have slide-in animation"
print("[PASS] Modal has fade-in and slide-in animations")

# Test 7: findingsData JSON is populated from Jinja
assert "findingsData" in template, "Should have findingsData array"
assert "tojson" in template, "Should use tojson filter for safe JSON"
print("[PASS] findingsData populated via Jinja tojson filter")

# Test 8: Generate a real report and verify
from core.engine import Engine
from reports.generator import ReportGenerator

engine = Engine(mock_mode=True)
engine.load_plugins()
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()
generator = ReportGenerator()
html_path = generator.generate_report(report)
html = Path(html_path).read_text(encoding="utf-8")

assert "findingModal" in html, "Generated report should have modal"
assert "openFindingModal(0)" in html, "First card should open modal at index 0"
assert '"title":' in html, "findingsData should be populated"
cards_with_onclick = html.count('onclick="openFindingModal(')
print(f"[PASS] Generated report has modal + {cards_with_onclick} clickable finding cards")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
