"""Quick demo: full scan pipeline on any target."""
import os
import sys

os.environ["AUTOSEC_MOCK_MODE"] = "true"
sys.path.insert(0, os.path.dirname(__file__))

from core.pipeline import run_scan_pipeline, ScanRequest

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
print(f"[+] Target: {target}")

report, paths = run_scan_pipeline(ScanRequest(target=target, mock_mode=True))

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

print(f"Report saved to: {paths.json}")
print("=" * 50)
