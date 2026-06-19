"""Test baseline verification feature."""
import sys
sys.path.insert(0, ".")

from unittest.mock import MagicMock
from plugins.base_plugin import BaseScanner
from core.engine import Engine

print("=" * 50)
print("TESTING: Feature 4 - Baseline Verification")
print("=" * 50)

# Test 1: _verify_against_baseline detects real change (status code diff)
baseline = {"status_code": 200, "length": 500, "content": "normal page"}
mock_resp = MagicMock()
mock_resp.status_code = 500
mock_resp.text = "SQL error: you have an error in your SQL syntax" + "x" * 300

is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp)
assert is_verified is True, f"Should verify: status 200->500 is a real change"
assert confidence == "high", f"Status + length change should be high confidence, got {confidence}"
print(f"[PASS] Status 200->500 with length change: verified={is_verified}, confidence={confidence}")

# Test 2: Same status, big length change = medium confidence
mock_resp2 = MagicMock()
mock_resp2.status_code = 200
mock_resp2.text = "x" * 1500  # 500 -> 1500 = 200% change

is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp2)
assert is_verified is True, "Big length change should be verified"
assert confidence in ("medium", "high"), f"Expected medium or high, got {confidence}"
print(f"[PASS] Same status, 200% length change: verified={is_verified}, confidence={confidence}")

# Test 3: No change at all = NOT verified (false positive)
mock_resp3 = MagicMock()
mock_resp3.status_code = 200
mock_resp3.text = "normal page content here" + "x" * 475  # ~500 length

is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp3)
assert is_verified is False, f"No change should NOT be verified, got verified={is_verified}"
print(f"[PASS] No behavioral change: verified={is_verified} (correctly rejected as false positive)")

# Test 4: Minor change = low confidence
mock_resp4 = MagicMock()
mock_resp4.status_code = 201  # slightly different
mock_resp4.text = "x" * 500  # same length

is_verified, confidence = BaseScanner._verify_against_baseline(baseline, mock_resp4)
assert confidence == "low", f"Minor change should be low confidence, got {confidence}"
print(f"[PASS] Minor status change: verified={is_verified}, confidence={confidence}")

# Test 5: Full mock scan still works with verification in the pipeline
engine = Engine(mock_mode=True)
engine.load_plugins()
engine.set_target("http://localhost:3000")
engine.run_plugins()
report = engine.generate_report()
assert len(report.all_findings) > 0, "Mock scan should still produce findings"
print(f"[PASS] Mock scan produces {len(report.all_findings)} findings (verification doesn't break mock mode)")

# Test 6: Baseline cache works
class DummyScanner(BaseScanner):
    def configure(self, target): self.target = target
    def run(self): pass
    def parse_output(self): return {"tool_name": "dummy", "findings": []}
    def _get_tool_name(self): return "dummy"
    def _get_mock_output(self): return {"tool_name": "dummy", "findings": []}

scanner = DummyScanner()
# Cache should be a class-level dict
assert isinstance(scanner._baseline_cache, dict), "Should have baseline cache"
print(f"[PASS] Baseline cache is available on scanner instances")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
