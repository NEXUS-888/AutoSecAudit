"""Test directory bruteforcer plugin."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 10 - Directory Bruteforcer Plugin")
print("=" * 50)

# Test 1: Plugin loads
from plugins.dirbuster_plugin import DirBruteScanner
scanner = DirBruteScanner(mock_mode=True)
scanner.configure("http://localhost:3000")
assert scanner.target == "http://localhost:3000"
print("[PASS] DirBruteScanner loads and configures")

# Test 2: Mock output produces findings
output = scanner.get_standardized_output()
assert output["tool_name"] == "DirBrute"
assert len(output["findings"]) > 0
print(f"[PASS] Mock scan found {len(output['findings'])} hidden resources")

# Test 3: Findings have correct structure
for f in output["findings"]:
    assert f["id"].startswith("DIR-"), f"ID should start with DIR-: {f['id']}"
    assert f["severity"] in ("Critical", "High", "Medium", "Low", "Info")
    assert f["tool_name"] == "DirBrute"
    assert f["owasp_tag"] == "A05:2021 Security Misconfiguration"
    assert f["remediation"], f"Finding {f['id']} missing remediation"
    assert f["confidence"] in ("high", "medium", "low")
print("[PASS] Finding structure is correct (ID, severity, tool, OWASP, remediation, confidence)")

# Print findings
for f in output["findings"]:
    print(f"  [{f['severity']:8s}] {f['title']}")

# Test 4: Engine auto-discovers the plugin
from core.engine import Engine
engine = Engine(mock_mode=True)
count = engine.load_plugins()
plugin_names = [p.__class__.__name__ for p in engine.plugins]
assert "DirBruteScanner" in plugin_names, f"DirBruteScanner not loaded. Got: {plugin_names}"
print(f"[PASS] Engine auto-discovered DirBruteScanner (total: {count} plugins)")

# Test 5: Full scan includes DirBrute findings
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()
dir_findings = [f for f in report.all_findings if f.tool_name == "DirBrute"]
assert len(dir_findings) > 0, "Should have DirBrute findings in report"
print(f"[PASS] Full scan includes {len(dir_findings)} DirBrute findings (total: {len(report.all_findings)})")

# Test 6: Wordlist has enough entries
from plugins.dirbuster_plugin import DIRECTORY_WORDLIST
assert len(DIRECTORY_WORDLIST) >= 40, f"Wordlist too small: {len(DIRECTORY_WORDLIST)}"
print(f"[PASS] Wordlist has {len(DIRECTORY_WORDLIST)} curated paths")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
