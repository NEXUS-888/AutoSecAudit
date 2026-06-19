"""Test remediation suggestions feature."""
import sys
sys.path.insert(0, ".")

from core.engine import Engine
from core.models import Finding
from intelligence.remediation import get_remediation, enrich_with_remediation

print("=" * 50)
print("TESTING: Feature 2 - Remediation Suggestions")
print("=" * 50)

# Test 1: Finding model has remediation field
f = Finding(id="TEST-001", title="Test", severity="High", host="localhost", port=80,
            description="Test desc", raw_output="test")
assert f.remediation is None, f"Default remediation should be None, got {f.remediation}"
print("[PASS] Finding defaults to remediation=None")

# Test 2: get_remediation returns advice for OWASP-tagged finding
f_owasp = Finding(id="TEST-002", title="Test", severity="High", host="localhost", port=80,
                  description="Test", raw_output="", owasp_tag="A03:2021 Injection")
advice = get_remediation(f_owasp)
assert advice is not None, "Should return remediation for A03:2021 Injection"
assert "parameterized" in advice.lower(), "Should mention parameterized queries"
print("[PASS] get_remediation returns advice for OWASP A03:2021")

# Test 3: get_remediation returns tool-specific advice
f_sqli = Finding(id="TEST-003", title="SQLi", severity="High", host="localhost", port=80,
                 description="SQL Injection\nType: error_based", raw_output="",
                 tool_name="sqli_scanner", owasp_tag="A03:2021 Injection")
advice = get_remediation(f_sqli)
assert advice is not None, "Should return tool-specific remediation"
assert "suppress database error" in advice.lower() or "string concatenation" in advice.lower(), \
    "Should contain SQLi-specific fix advice"
print("[PASS] get_remediation returns tool-specific advice for sqli_scanner:error_based")

# Test 4: Tool-specific takes priority over OWASP generic
f_generic = Finding(id="TEST-004", title="Test", severity="High", host="localhost", port=80,
                    description="XSS\nType: reflected_xss", raw_output="",
                    tool_name="xss_scanner", owasp_tag="A03:2021 Injection")
advice_specific = get_remediation(f_generic)
advice_owasp = "Use parameterized queries"  # from the OWASP generic
assert advice_specific is not None
# Tool-specific advice should be about XSS, not SQL
assert "encode" in advice_specific.lower() or "escaping" in advice_specific.lower(), \
    f"Tool-specific advice should be about XSS encoding, got: {advice_specific[:100]}"
print("[PASS] Tool-specific advice takes priority over OWASP generic")

# Test 5: enrich_with_remediation works on a full mock scan
engine = Engine(mock_mode=True)
engine.load_plugins()
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()

# Before enrichment
no_remediation = [f for f in report.all_findings if f.remediation is None]
print(f"Before: {len(no_remediation)}/{len(report.all_findings)} findings have no remediation")

# Enrich
report.all_findings = enrich_with_remediation(report.all_findings)

# After enrichment
with_remediation = [f for f in report.all_findings if f.remediation is not None]
print(f"After:  {len(with_remediation)}/{len(report.all_findings)} findings have remediation")

assert len(with_remediation) > 0, "Should have enriched at least some findings"
print(f"[PASS] Enriched {len(with_remediation)} findings with remediation advice")

# Test 6: to_dict includes remediation
d = with_remediation[0].to_dict()
assert "remediation" in d, "to_dict should include remediation"
assert d["remediation"] is not None, "remediation should not be None after enrichment"
print(f"[PASS] to_dict() includes remediation field")

# Print a sample
print()
print("--- Sample remediation ---")
sample = with_remediation[0]
print(f"Finding: {sample.title}")
print(f"Tool:    {sample.tool_name}")
print(f"OWASP:   {sample.owasp_tag}")
print(f"Fix:\n{sample.remediation[:200]}...")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
