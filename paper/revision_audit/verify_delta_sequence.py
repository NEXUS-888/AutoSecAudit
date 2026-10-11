"""Run the repository's DeltaAnalyzer on a SYNTHETIC identifier sequence built to match the
paper's reported counts (47 -> 40 -> 26), then demonstrate documented edge cases.

The sequence is constructed here, so a pass shows only that the set arithmetic over identifiers
is implemented as described. It is not evidence about real builds.
"""
import logging, os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
logging.disable(logging.CRITICAL)
from core.models import Finding, Report
from intelligence.delta import DeltaAnalyzer

def F(i, title="t"):
    return Finding(id=i, title=title, severity="High", host="h", port=3000, description="", raw_output="")
def R(ids):
    return Report(target="t", timestamp="", all_findings=[F(i) for i in ids])

v10 = [f"F-{n:03d}" for n in range(1, 48)]                      # 47
v11 = v10[10:] + ["NEW-1", "NEW-2", "NEW-3"]                     # 10 fixed, 3 new -> 40
v12 = v11[14:]                                                   # 14 fixed -> 26
d1 = DeltaAnalyzer().compare(R(v11), R(v10))["summary"]
d2 = DeltaAnalyzer().compare(R(v12), R(v11))["summary"]
print("v1.0->v1.1", d1); print("v1.1->v1.2", d2)
ok = d1 == {"new_count": 3, "fixed_count": 10, "unchanged_count": 37} and d2 == {"new_count": 0, "fixed_count": 14, "unchanged_count": 26}
print("synthetic sequence classified as reported:", ok)

# Edge cases (documented in the paper)
a = Report(target="t", timestamp="", all_findings=[F("XSS-001", "xss /a"), F("XSS-002", "xss /b")])
b = Report(target="t", timestamp="", all_findings=[F("XSS-001", "xss /b")])   # /a fixed; /b renumbered
print("renumbering edge case (expected true result: 0 new, 1 fixed, 1 unchanged):", DeltaAnalyzer().compare(b, a)["summary"])
print("  -> classified FIXED title:", [x["title"] for x in DeltaAnalyzer().compare(b, a)["fixed_issues"]], "(actually still present)")
c = Report(target="t", timestamp="", all_findings=[F("XSS-001", "SQLi on another endpoint")])
print("same id, different finding:", DeltaAnalyzer().compare(c, a)["summary"])
e = Report(target="t", timestamp="", all_findings=[F("", "no id")])
print("empty id dropped:", DeltaAnalyzer().compare(e, a)["summary"])
raise SystemExit(0 if ok else 1)
