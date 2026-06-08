"""Quick demo: full scan pipeline on any target."""
import os
import sys

os.environ["AUTOSEC_MOCK_MODE"] = "true"
sys.path.insert(0, os.path.dirname(__file__))

from core.engine import Engine
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper

# 1. Initialize engine
engine = Engine(mock_mode=True)

# 2. Load ALL plugins
count = engine.load_plugins()
print(f"[+] Loaded {count} scanner plugins")

# 3. Set target (any website)
target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
engine.set_target(target)
print(f"[+] Target: {target}")

# 4. Run all scanners
results = engine.run_plugins()
print(f"[+] Scanners completed: {len(results)} tools ran")

# 5. Generate report
report = engine.generate_report()

# 6. Intelligence pipeline
correlator = Correlator()
correlator.correlate(report.all_findings)

enricher = Enricher()
enricher.enrich(report.all_findings)

mapper = ComplianceMapper()
mapper.map_findings(report.all_findings)

# 7. Save report
path = engine.save_report(report)

# 8. Print summary
print()
print("=" * 50)
print("        AUTOSECAUDIT SCAN REPORT")
print("=" * 50)
print(f"  Target:   {report.target}")
print(f"  Time:     {report.timestamp}")
total = report.summary.get("total", 0)
crit = report.summary.get("critical", 0)
high = report.summary.get("high", 0)
med = report.summary.get("medium", 0)
low = report.summary.get("low", 0)
info = report.summary.get("info", 0)

print(f"  Total Findings: {total}")
print(f"    Critical: {crit}")
print(f"    High:     {high}")
print(f"    Medium:   {med}")
print(f"    Low:      {low}")
print(f"    Info:     {info}")
print()

print("Findings by Scanner:")
for sr in report.scan_results:
    print(f"  {sr.tool_name:25s} -> {len(sr.findings)} findings")
print()

print("All Findings:")
for f in report.all_findings:
    sev = f.severity.upper()
    owasp = f.owasp_tag or "-"
    print(f"  [{sev:8s}] {f.title}")
    print(f"             OWASP: {owasp} | Tool: {f.tool_name or 'N/A'}")
    print()

print(f"Report saved to: {path}")
print("=" * 50)
