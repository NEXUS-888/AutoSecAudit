"""Test CORS misconfiguration scanner plugin."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 11 - CORS Misconfiguration Scanner")
print("=" * 50)

# Test 1: Plugin loads
from plugins.cors_plugin import CORSScanner
scanner = CORSScanner(mock_mode=True)
scanner.configure("http://localhost:3000")
assert scanner.target == "http://localhost:3000"
print("[PASS] CORSScanner loads and configures")

# Test 2: Mock output
output = scanner.get_standardized_output()
assert output["tool_name"] == "CORSScanner"
assert len(output["findings"]) >= 3
print(f"[PASS] Mock scan found {len(output['findings'])} CORS misconfigs")

# Test 3: Finding structure
for f in output["findings"]:
    assert f["id"].startswith("CORS-"), f"ID should start with CORS-"
    assert f["severity"] in ("Critical", "High", "Medium", "Low", "Info")
    assert f["tool_name"] == "CORSScanner"
    assert f["remediation"], f"Missing remediation for {f['id']}"
    assert f["confidence"] in ("high", "medium", "low")
    assert "CORS" in f["title"] or "cors" in f["title"].lower()
print("[PASS] Finding structure correct")

for f in output["findings"]:
    print(f"  [{f['severity']:8s}] {f['title']}")

# Test 4: Engine auto-discovers
from core.engine import Engine
engine = Engine(mock_mode=True)
count = engine.load_plugins()
names = [p.__class__.__name__ for p in engine.plugins]
assert "CORSScanner" in names, f"CORSScanner not found in {names}"
print(f"[PASS] Engine auto-discovered CORSScanner (total: {count} plugins)")

# Test 5: Full scan includes CORS findings
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()
cors_findings = [f for f in report.all_findings if f.tool_name == "CORSScanner"]
assert len(cors_findings) > 0
print(f"[PASS] Full scan: {len(cors_findings)} CORS findings (total: {len(report.all_findings)})")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
