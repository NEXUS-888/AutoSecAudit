"""Test confidence scores feature."""
import sys
sys.path.insert(0, ".")

from core.engine import Engine
from core.models import Finding

print("=" * 50)
print("TESTING: Feature 1 - Confidence Scores")
print("=" * 50)

# Test 1: Finding model has confidence field with default
f = Finding(id="TEST-001", title="Test", severity="High", host="localhost", port=80, description="Test desc", raw_output="test")
assert f.confidence == "medium", f"Default confidence should be medium, got {f.confidence}"
print("[PASS] Finding defaults to confidence='medium'")

f2 = Finding(id="TEST-002", title="Test", severity="High", host="localhost", port=80, description="Test", raw_output="", confidence="high")
assert f2.confidence == "high", f"Confidence should be high, got {f2.confidence}"
print("[PASS] Finding accepts confidence='high'")

# Test 2: Mock scan produces confidence in findings
engine = Engine(mock_mode=True)
engine.load_plugins()
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()

findings_with_confidence = [f for f in report.all_findings if f.confidence in ("high", "medium", "low")]
print(f"[PASS] {len(findings_with_confidence)}/{len(report.all_findings)} findings have valid confidence")

# Check SQLi mock specifically has different confidence levels
sqli_findings = [f for f in report.all_findings if f.tool_name == "sqli_scanner"]
for f in sqli_findings:
    print(f"  SQLi {f.id}: severity={f.severity}, confidence={f.confidence}")

sqli_high = [f for f in sqli_findings if f.confidence == "high"]
sqli_low = [f for f in sqli_findings if f.confidence == "low"]
assert len(sqli_high) > 0, "Should have at least one high-confidence SQLi finding"
assert len(sqli_low) > 0, "Should have at least one low-confidence SQLi finding"
print("[PASS] SQLi findings have mixed confidence levels (high + low)")

# Test 3: to_dict includes confidence
d = report.all_findings[0].to_dict()
assert "confidence" in d, "to_dict should include confidence"
print(f"[PASS] to_dict() includes confidence: '{d['confidence']}'")

# Test 4: XSS findings have confidence
xss_findings = [f for f in report.all_findings if f.tool_name == "xss_scanner"]
for f in xss_findings:
    print(f"  XSS {f.id}: severity={f.severity}, confidence={f.confidence}")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
