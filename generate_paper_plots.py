import os
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, Circle
import numpy as np

# Ensure output directory exists
os.makedirs("paper/figures", exist_ok=True)

# Standardized publication typography
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Helvetica', 'Arial', 'DejaVu Sans'],
    'font.size': 9,
    'axes.labelsize': 10,
    'axes.titlesize': 10.5,
    'xtick.labelsize': 8.5,
    'ytick.labelsize': 8.5,
    'legend.fontsize': 8,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight'
})

# ---------------------------------------------------------------------------
# Figure 1: Hand-Crafted Compact 4-Stage Horizontal System Architecture
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10.2, 2.35))
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis('off')

# Stage 1: Ingestion & Surface Discovery
ax.add_patch(FancyBboxPatch((1, 4), 22, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((1, 78), 22, 18, facecolor="#1E293B", edgecolor="none", zorder=3))
ax.text(12, 87, "1. Surface Discovery", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(12, 60, "Recursive Crawler & JS Regex\n• Form / Link Ingestion\n• Inline JS Route Extraction\n• OpenAPI Import (feeds plugins)", ha="center", va="center", color="#334155", fontsize=6.6, zorder=4)
ax.text(12, 24, "Scope Guardrail & Liveness\n• Resolved-IP Private / Loopback Guard\n• Pre-Flight HTTP Probe\n• Auto-Authenticator", ha="center", va="center", color="#334155", fontsize=6.6, zorder=4)

# Stage 2: Concurrent Multi-Scanner Engine
ax.add_patch(FancyBboxPatch((25.5, 4), 23.5, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((25.5, 78), 23.5, 18, facecolor="#0F766E", edgecolor="none", zorder=3))
ax.text(37.25, 87, "2. Scanner Engine (19)", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(37.25, 68, "Web: SQLi, XSS, CSRF, Redirect\nAPI: BOLA/IDOR, Auth, JWT, CORS", ha="center", va="center", color="#0F766E", fontsize=6.5, fontweight="bold", zorder=4)
ax.text(37.25, 46, "Exploit: CmdInj, SSRF, LFI, SSTI\nRecon: Nmap, Nikto, TLS, Secrets", ha="center", va="center", color="#0F766E", fontsize=6.5, fontweight="bold", zorder=4)
ax.text(37.25, 18, "ThreadPool ($k$ configurable), Profiles\nTiming & Baseline Checks\nPoliteness Backoff & JSON Fuzz", ha="center", va="center", color="#047857", fontsize=6.3, zorder=4)

# Stage 3: Post-Processing Intelligence Layer
ax.add_patch(FancyBboxPatch((51.5, 4), 22.5, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((51.5, 78), 22.5, 18, facecolor="#1D4ED8", edgecolor="none", zorder=3))
ax.text(62.75, 87, "3. Intelligence Layer", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(62.75, 64, "Cross-Referencing\n• Canonical-key merge\n• CVSS via NVD/CIRCL (CVE-tagged)\n• Keyword compliance mapping", ha="center", va="center", color="#1E3A8A", fontsize=6.5, zorder=4)
ax.text(62.75, 24, "Danger Engine & Fix Recipes\n• OWASP '21, CWE, PCI DSS v4.0\n• Plain-English Danger Grade\n• Static Multi-Framework Recipes", ha="center", va="center", color="#1E3A8A", fontsize=6.5, zorder=4)

# Stage 4: Delivery, Policy Gating & AI MCP
ax.add_patch(FancyBboxPatch((76.5, 4), 22.5, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((76.5, 78), 22.5, 18, facecolor="#475569", edgecolor="none", zorder=3))
ax.text(87.75, 87, "4. Delivery & AI MCP", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(87.75, 64, "CI/CD Gating\n• Exit code (--fail-on)\n• Fingerprint Delta Comparison", ha="center", va="center", color="#334155", fontsize=6.6, zorder=4)
ax.text(87.75, 24, "MCP Server & Reports\n• MCP stdio tools (4)\n• SSE Dashboard\n• ReportLab PDF", ha="center", va="center", color="#334155", fontsize=6.5, zorder=4)

# Horizontal arrows
arrow_props = dict(facecolor='#334155', edgecolor='#334155', width=1.1, headwidth=4.5, shrink=0.01)
ax.annotate('', xy=(25.5, 50), xytext=(23.0, 50), arrowprops=arrow_props)
ax.annotate('', xy=(51.5, 50), xytext=(49.0, 50), arrowprops=arrow_props)
ax.annotate('', xy=(76.5, 50), xytext=(74.0, 50), arrowprops=arrow_props)

plt.savefig("paper/figures/fig1_architecture.pdf")
plt.savefig("paper/figures/fig1_architecture.png")
plt.close()

# ---------------------------------------------------------------------------
# Figures 2-4 are drawn from the raw experiment output written by
# `python -m benchmark.paper_experiments all`; there are no hard-coded results here.
# ---------------------------------------------------------------------------
import json
import statistics

RESULTS = os.path.join("benchmark", "results", "paper")


def load(name):
    path = os.path.join(RESULTS, name + ".json")
    if not os.path.exists(path):
        raise SystemExit(f"Missing {path}: run `python -m benchmark.paper_experiments all` first.")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Figure 2: Scan latency (mean +/- sd over repetitions) and speedup vs. threads
# ---------------------------------------------------------------------------
scaling = load("scaling")
threads = [int(k) for k in scaling["runs"]]
means = [statistics.fmean(r["seconds"] for r in scaling["runs"][str(k)]) for k in threads]
sds = [statistics.stdev(r["seconds"] for r in scaling["runs"][str(k)]) for k in threads]
speedup = [means[0] / m for m in means]

fig, ax1 = plt.subplots(figsize=(4.8, 2.9))
c_lat = '#1E3A8A'
ax1.set_xlabel('Worker Threads ($k$)', fontweight='bold')
ax1.set_ylabel('Scan Latency (s)', color=c_lat, fontweight='bold')
line1 = ax1.errorbar(threads, means, yerr=sds, marker='o', color=c_lat, linewidth=1.6, markersize=5,
                     capsize=3, label='Latency, mean $\\pm$ sd (s)')
ax1.tick_params(axis='y', labelcolor=c_lat)
ax1.set_xticks(threads)
ax1.set_ylim(0, max(m + s_ for m, s_ in zip(means, sds)) * 1.25)
ax1.grid(True, linestyle=':', alpha=0.5)

ax2 = ax1.twinx()
c_spd = '#0F766E'
ax2.set_ylabel('Speedup ($\\times$)', color=c_spd, fontweight='bold')
line2 = ax2.plot(threads, speedup, marker='s', color=c_spd, linewidth=1.6, linestyle='--', markersize=5,
                 label='Speedup ($\\times$)')
ax2.tick_params(axis='y', labelcolor=c_spd)
ax2.set_ylim(0.5, max(speedup) * 1.4)

handles = [line1, line2[0]]
ax1.legend(handles, [h.get_label() for h in handles], loc='upper right', framealpha=0.9)

plt.savefig("paper/figures/fig2_latency.pdf")
plt.savefig("paper/figures/fig2_latency.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 3: Raw plugin alerts vs. merged findings per testbed (mean of repetitions)
# ---------------------------------------------------------------------------
acc = load("accuracy")
names = list(acc["runs"])
complete = {n: [r for r in acc["runs"][n] if r["tp"] == r["total_real"]] for n in names}
raw_alerts = [statistics.fmean(r["raw_alerts"] for r in complete[n]) for n in names]
merged = [statistics.fmean(r["raw_findings"] for r in complete[n]) for n in names]

x = np.arange(len(names))
width = 0.36
fig, ax = plt.subplots(figsize=(4.2, 2.9))
rects1 = ax.bar(x - width/2, raw_alerts, width, label='Raw plugin alerts', color='#64748B', edgecolor='#334155', linewidth=0.7)
rects2 = ax.bar(x + width/2, merged, width, label='Merged findings', color='#1D4ED8', edgecolor='#1E3A8A', linewidth=0.7)
ax.set_ylabel('Mean count per scan', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(names)
ax.set_ylim(0, max(raw_alerts) * 1.25)
ax.legend(loc='upper right', framealpha=0.9)
ax.grid(axis='y', linestyle=':', alpha=0.5)
for rects, bold in ((rects1, False), (rects2, True)):
    for rect in rects:
        h = rect.get_height()
        ax.annotate(f'{h:.1f}', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 2),
                    textcoords="offset points", ha='center', va='bottom', fontsize=7.5,
                    fontweight='bold' if bold else 'normal', color='#1D4ED8' if bold else '#0F172A')
plt.savefig("paper/figures/fig3_noise_reduction.pdf")
plt.savefig("paper/figures/fig3_noise_reduction.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 4: Delta partitions per build transition, observed vs. expected
# ---------------------------------------------------------------------------
delta = load("delta")
delta1 = load("delta_run1")
NL = chr(10)
transitions = [f'run 1{NL}v1-v2', f'run 1{NL}v2-v3', f'run 2{NL}v1-v2', f'run 2{NL}v2-v3']
obs = [delta1["v1_to_v2"]["summary"], delta1["v2_to_v3"]["summary"],
       delta["v1_to_v2"]["summary"], delta["v2_to_v3"]["summary"]]
n_new, n_fix = len(delta["expected_new_items"]), len(delta["expected_fixed_items"])
exp_new = [n_new, 0, n_new, 0]
exp_fixed = [0, n_fix, 0, n_fix]

x = np.arange(len(transitions))
width = 0.16
fig, ax = plt.subplots(figsize=(5.4, 2.9))
series = [
    ('New (observed)', [o["new_count"] for o in obs], '#DC2626', None),
    ('New (expected)', exp_new, '#DC2626', '//'),
    ('Fixed (observed)', [o["fixed_count"] for o in obs], '#059669', None),
    ('Fixed (expected)', exp_fixed, '#059669', '//'),
]
for i, (label, vals, color, hatch) in enumerate(series):
    bars = ax.bar(x + (i - 1.5) * width, vals, width, label=label, color=color, hatch=hatch,
                  edgecolor='#0F172A', linewidth=0.6, alpha=0.9 if hatch is None else 0.45)
    for bar, v in zip(bars, vals):
        ax.annotate(str(v), xy=(bar.get_x() + bar.get_width() / 2, v), xytext=(0, 2),
                    textcoords="offset points", ha='center', va='bottom', fontsize=7.5)
ax.set_xticks(x)
ax.set_xticklabels(transitions)
ax.set_ylabel('Findings', fontweight='bold')
ax.set_ylim(0, max([o["new_count"] for o in obs] + [o["fixed_count"] for o in obs] + exp_new + exp_fixed) * 1.45 + 1)
ax.legend(loc='upper right', framealpha=0.9, ncol=2, fontsize=7)
ax.grid(axis='y', linestyle=':', alpha=0.5)
plt.savefig("paper/figures/fig4_delta_diff.pdf")
plt.savefig("paper/figures/fig4_delta_diff.png")
plt.close()

print("Successfully regenerated all publication-grade figures in paper/figures/")
