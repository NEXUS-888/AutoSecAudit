"""Test interactive report filtering feature."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 7 - Interactive Report Filtering")
print("=" * 50)

# Test 1: Report template has filter elements
from pathlib import Path
template = Path("reports/templates/report.html").read_text(encoding="utf-8")

assert "filterBar" in template, "Should have filterBar element"
assert "filter-btn" in template, "Should have filter buttons"
assert "findingSearch" in template, "Should have search input"
assert "filterFindings" in template, "Should have filterFindings function"
print("[PASS] Report template contains filter bar HTML")

# Test 2: Filter buttons for all severities
for sev in ["critical", "high", "medium", "low", "info", "all"]:
    assert f'data-filter-severity="{sev}"' in template, f"Missing filter button for {sev}"
print("[PASS] Filter buttons exist for all severity levels + 'All'")

# Test 3: Finding cards have data attributes
assert "data-severity=" in template, "Finding cards should have data-severity"
assert "data-tool=" in template, "Finding cards should have data-tool"
assert "data-confidence=" in template, "Finding cards should have data-confidence"
assert "data-title=" in template, "Finding cards should have data-title for search"
print("[PASS] Finding cards have data-severity, data-tool, data-confidence, data-title")

# Test 4: JavaScript filter logic is present
assert "matchSev" in template, "JS should check severity match"
assert "matchSearch" in template, "JS should check search match"
assert "filterCount" in template, "Should show count of filtered results"
assert "card.style.display" in template, "Should toggle display on cards"
print("[PASS] JavaScript filter logic is complete")

# Test 5: Filter bar is sticky
assert "position: sticky" in template, "Filter bar should be sticky"
assert "backdrop-filter" in template, "Should have backdrop blur"
print("[PASS] Filter bar is sticky with backdrop blur")

# Test 6: Generate a real report and check it contains filter elements
from core.engine import Engine
from reports.generator import ReportGenerator

engine = Engine(mock_mode=True)
engine.load_plugins()
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()

generator = ReportGenerator()
html_path = generator.generate_report(report)
html_content = Path(html_path).read_text(encoding="utf-8")

assert "filterBar" in html_content, "Generated report should have filter bar"
assert 'data-severity="high"' in html_content, "Generated report should have data attributes on cards"
count_cards = html_content.count('data-severity="')
print(f"[PASS] Generated report has filter bar and {count_cards} filterable finding cards")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
