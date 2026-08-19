import os
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np

# Ensure output directory exists
os.makedirs("paper/figures", exist_ok=True)

# Set high-DPI and professional publication styling
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['DejaVu Sans', 'Arial', 'Helvetica'],
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 11,
    'xtick.labelsize': 9.5,
    'ytick.labelsize': 9.5,
    'legend.fontsize': 9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight'
})

# ---------------------------------------------------------------------------
# Figure 1: Architecture Pipeline Overview
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(9.0, 4.2))
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

boxes = [
    {
        "title": "1. Surface Discovery\n• Breadth-First Web Crawler\n• OpenAPI / Swagger 3.0 Ingestion\n• Endpoint & Parameter Seeding",
        "xy": (0.03, 0.54), "w": 0.28, "h": 0.40, "fc": "#EBF5FB", "ec": "#2980B9"
    },
    {
        "title": "2. Multi-Scanner Engine\n• 14 Specialized Plugins (DAST)\n• Bounded ThreadPool ($k=8$)\n• Differential Baseline Cache",
        "xy": (0.36, 0.54), "w": 0.28, "h": 0.40, "fc": "#EAFAF1", "ec": "#27AE60"
    },
    {
        "title": "3. Intelligence Layer\n• Heuristic Deduplication\n• Live NIST / CIRCL CVE Lookup\n• OWASP / CWE / PCI Mapping\n• Set-Theoretic Delta Diffing",
        "xy": (0.69, 0.54), "w": 0.28, "h": 0.40, "fc": "#FEF9E7", "ec": "#F39C12"
    },
    {
        "title": "4. Delivery, CI/CD Policy Gating & Monitoring\n• Native Exit-Code Gating (--fail-on)    • Asynchronous Webhooks (Slack/Discord)    • Real-Time Interactive SSE Dashboard",
        "xy": (0.03, 0.08), "w": 0.94, "h": 0.34, "fc": "#F4ECF7", "ec": "#8E44AD"
    }
]

for b in boxes:
    patch = FancyBboxPatch(b["xy"], b["w"], b["h"],
                           boxstyle="round,pad=0.015,rounding_size=0.025",
                           facecolor=b["fc"], edgecolor=b["ec"], linewidth=1.8, zorder=2)
    ax.add_patch(patch)
    ax.text(b["xy"][0] + b["w"]/2, b["xy"][1] + b["h"]/2, b["title"],
            ha="center", va="center", fontsize=9.2, fontweight="medium", color="#1A252F", zorder=3, linespacing=1.35)

# Draw connecting arrows
arrow_props = dict(facecolor='#2C3E50', edgecolor='#2C3E50', width=1.4, headwidth=5.5, shrink=0.02)
ax.annotate('', xy=(0.36, 0.74), xytext=(0.31, 0.74), arrowprops=arrow_props)
ax.annotate('', xy=(0.69, 0.74), xytext=(0.64, 0.74), arrowprops=arrow_props)
ax.annotate('', xy=(0.50, 0.42), xytext=(0.83, 0.54), arrowprops=dict(facecolor='#2C3E50', edgecolor='#2C3E50', width=1.4, headwidth=5.5, shrink=0.02))

plt.savefig("paper/figures/fig1_architecture.pdf")
plt.savefig("paper/figures/fig1_architecture.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 2: Scan Latency vs. Concurrency Threads
# ---------------------------------------------------------------------------
threads = [1, 2, 4, 8, 16]
latency = [184.2, 102.5, 71.4, 64.8, 66.1]
speedup = [1.0, 1.80, 2.58, 2.84, 2.79]

fig, ax1 = plt.subplots(figsize=(5.5, 3.4))

color = '#1A5276'
ax1.set_xlabel('Concurrency Worker Threads ($k$)', fontweight='bold')
ax1.set_ylabel('Scan Execution Latency (seconds)', color=color, fontweight='bold')
line1 = ax1.plot(threads, latency, marker='o', color=color, linewidth=2.2, markersize=6.5, label='Scan Latency (s)')
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_xticks(threads)
ax1.set_ylim(40, 200)
ax1.grid(True, linestyle='--', alpha=0.45)

ax1.annotate('Optimal Latency\n(64.8s at k=8)', xy=(8, 64.8), xytext=(8.2, 115),
             arrowprops=dict(arrowstyle="->", color='#C0392B', lw=1.4),
             bbox=dict(boxstyle="round,pad=0.25", fc="#FDEDEC", ec="#C0392B", lw=0.9),
             fontweight='bold', fontsize=8.5, color='#922B21')

ax2 = ax1.twinx()
color = '#1E8449'
ax2.set_ylabel('Speedup Factor vs. Sequential ($\\times$)', color=color, fontweight='bold')
line2 = ax2.plot(threads, speedup, marker='s', color=color, linewidth=2.2, linestyle='--', markersize=6.5, label='Speedup Factor ($\\times$)')
ax2.tick_params(axis='y', labelcolor=color)
ax2.set_ylim(0.8, 3.2)

lines = line1 + line2
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='center right', framealpha=0.92)

plt.savefig("paper/figures/fig2_latency.pdf")
plt.savefig("paper/figures/fig2_latency.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 3: Alert Noise Reduction (Raw vs Correlated Findings)
# ---------------------------------------------------------------------------
categories = ['SQLi\n(A03)', 'XSS\n(A03)', 'Misconfig\n(A05)', 'Access\n(A01)', 'API/JWT\n(A07)', 'Adv Expl\n(A03/10)']
raw_alerts = [14, 19, 26, 9, 8, 4]
correlated = [8, 12, 15, 6, 5, 4]

x = np.arange(len(categories))
width = 0.35

fig, ax = plt.subplots(figsize=(5.8, 3.4))
rects1 = ax.bar(x - width/2, raw_alerts, width, label='Raw Tool Alerts (76 Total)', color='#E74C3C', edgecolor='#922B21', linewidth=0.8)
rects2 = ax.bar(x + width/2, correlated, width, label='Correlated Findings (46 Total)', color='#3498DB', edgecolor='#1B4F72', linewidth=0.8)

ax.set_ylabel('Number of Findings', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=8.5)
ax.set_ylim(0, 31)
ax.legend(loc='upper right', framealpha=0.92)
ax.grid(axis='y', linestyle='--', alpha=0.45)

def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 2.5),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8.5, fontweight='bold')

autolabel(rects1)
autolabel(rects2)

plt.savefig("paper/figures/fig3_noise_reduction.pdf")
plt.savefig("paper/figures/fig3_noise_reduction.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 4: Set-Theoretic Delta Differential Tracking Across Builds
# ---------------------------------------------------------------------------
builds = ['Build v1.0\n(Baseline)', 'Build v1.1\n(Patch & New)', 'Build v1.2\n(Hardened)']
unchanged = [46, 36, 25]
new_issues = [0, 3, 0]
fixed_issues = [0, 10, 14]

fig, ax = plt.subplots(figsize=(5.5, 3.4))

bar1 = ax.bar(builds, unchanged, label=r'Unchanged ($\Delta_{\mathrm{UNCHANGED}}$)', color='#95A5A6', edgecolor='#566573', linewidth=0.8)
bar2 = ax.bar(builds, new_issues, bottom=unchanged, label=r'New Issues ($\Delta_{\mathrm{NEW}}$)', color='#E74C3C', edgecolor='#922B21', linewidth=0.8)
bar3 = ax.bar(builds, fixed_issues, label=r'Fixed Issues ($\Delta_{\mathrm{FIXED}}$)', color='#2ECC71', edgecolor='#196F3D', linewidth=0.8, alpha=0.88)

ax.set_ylabel('Vulnerability Count', fontweight='bold')
ax.set_ylim(0, 62)
ax.legend(loc='upper right', framealpha=0.92)
ax.grid(axis='y', linestyle='--', alpha=0.45)

for i, total in enumerate([46, 39, 25]):
    ax.text(i, total + 1.8, f'Active: {total}', ha='center', fontweight='bold', fontsize=9, color='#1A252F')

plt.savefig("paper/figures/fig4_delta_diff.pdf")
plt.savefig("paper/figures/fig4_delta_diff.png")
plt.close()

print("Successfully regenerated all 4 polished publication-grade figures in paper/figures/")
