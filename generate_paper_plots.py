import os
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np

# Ensure output directory exists
os.makedirs("paper/figures", exist_ok=True)

# Set high-DPI and professional publication styling
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight'
})

# ---------------------------------------------------------------------------
# Figure 1: Architecture Pipeline Overview
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(9.0, 4.5))
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

boxes = [
    {
        "title": "1. Surface Discovery\n• BFS Crawler\n• OpenAPI/Swagger 3.0",
        "xy": (0.04, 0.55), "w": 0.26, "h": 0.38, "fc": "#E3F2FD", "ec": "#1976D2"
    },
    {
        "title": "2. Multi-Scanner Engine\n• 14 Specialized Plugins\n• ThreadPoolExecutor\n• Baseline Cache",
        "xy": (0.37, 0.55), "w": 0.26, "h": 0.38, "fc": "#E8F5E9", "ec": "#388E3C"
    },
    {
        "title": "3. Intelligence Layer\n• Heuristic Deduplication\n• Live NIST/CIRCL CVE\n• OWASP/CWE/PCI-DSS\n• Delta Analysis",
        "xy": (0.70, 0.55), "w": 0.26, "h": 0.38, "fc": "#FFF3E0", "ec": "#F57C00"
    },
    {
        "title": "4. Delivery, CI/CD Policy Gating & Monitoring\n• Exit-Code Gating (--fail-on)  • Webhooks (Slack/Discord)  • Real-Time SSE Dashboard",
        "xy": (0.04, 0.08), "w": 0.92, "h": 0.32, "fc": "#F3E5F5", "ec": "#7B1FA2"
    }
]

for b in boxes:
    patch = FancyBboxPatch(b["xy"], b["w"], b["h"],
                           boxstyle="round,pad=0.02,rounding_size=0.03",
                           facecolor=b["fc"], edgecolor=b["ec"], linewidth=2, zorder=2)
    ax.add_patch(patch)
    ax.text(b["xy"][0] + b["w"]/2, b["xy"][1] + b["h"]/2, b["title"],
            ha="center", va="center", fontsize=9.5, fontweight="medium", color="#212121", zorder=3)

# Draw connecting arrows
arrow_props = dict(facecolor='#424242', edgecolor='#424242', width=1.5, headwidth=6, shrink=0.02)
ax.annotate('', xy=(0.37, 0.74), xytext=(0.30, 0.74), arrowprops=arrow_props)
ax.annotate('', xy=(0.70, 0.74), xytext=(0.63, 0.74), arrowprops=arrow_props)
ax.annotate('', xy=(0.50, 0.40), xytext=(0.83, 0.55), arrowprops=dict(facecolor='#424242', edgecolor='#424242', width=1.5, headwidth=6, shrink=0.02))

plt.title("AutoSecAudit 2.0 Architectural Pipeline and Data Flow", pad=12, fontweight="bold")
plt.savefig("paper/figures/fig1_architecture.pdf")
plt.savefig("paper/figures/fig1_architecture.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 2: Scan Latency vs. Concurrency Threads
# ---------------------------------------------------------------------------
threads = [1, 2, 4, 8, 16]
latency = [184.2, 102.5, 71.4, 64.8, 66.1]
speedup = [1.0, 1.80, 2.58, 2.84, 2.79]

fig, ax1 = plt.subplots(figsize=(6.5, 4.0))

color = '#1976D2'
ax1.set_xlabel('Concurrency Worker Threads ($k$)', fontweight='bold')
ax1.set_ylabel('Scan Execution Latency (seconds)', color=color, fontweight='bold')
line1 = ax1.plot(threads, latency, marker='o', color=color, linewidth=2.4, markersize=7, label='Scan Latency (s)')
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_xticks(threads)
ax1.grid(True, linestyle='--', alpha=0.5)

ax1.annotate('Optimal Latency\n(64.8s at k=8)', xy=(8, 64.8), xytext=(8.5, 110),
             arrowprops=dict(arrowstyle="->", color='#D32F2F', lw=1.5),
             bbox=dict(boxstyle="round,pad=0.3", fc="#FFEBEE", ec="#D32F2F", lw=1),
             fontweight='bold', fontsize=9, color='#B71C1C')

ax2 = ax1.twinx()
color = '#388E3C'
ax2.set_ylabel('Speedup Factor vs. Sequential ($\\times$)', color=color, fontweight='bold')
line2 = ax2.plot(threads, speedup, marker='s', color=color, linewidth=2.4, linestyle='--', markersize=7, label='Speedup Factor ($\\times$)')
ax2.tick_params(axis='y', labelcolor=color)

lines = line1 + line2
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='center right', framealpha=0.9)

plt.title('Audit Execution Latency & Speedup vs. Thread Concurrency', fontweight='bold', pad=10)
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

fig, ax = plt.subplots(figsize=(7.0, 3.8))
rects1 = ax.bar(x - width/2, raw_alerts, width, label='Raw Tool Alerts (76 Total)', color='#EF5350', edgecolor='#C62828')
rects2 = ax.bar(x + width/2, correlated, width, label='Correlated Findings (46 Total)', color='#42A5F5', edgecolor='#1565C0')

ax.set_ylabel('Number of Findings', fontweight='bold')
ax.set_title('Raw Tool Alerts vs. Correlated Findings (-39.5% Alert Noise)', fontweight='bold', pad=10)
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=9)
ax.legend(loc='upper right', framealpha=0.95)
ax.grid(axis='y', linestyle='--', alpha=0.5)

def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

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

fig, ax = plt.subplots(figsize=(6.5, 3.8))

bar1 = ax.bar(builds, unchanged, label=r'Unchanged ($\Delta_{\mathrm{UNCHANGED}}$)', color='#B0BEC5', edgecolor='#455A64')
bar2 = ax.bar(builds, new_issues, bottom=unchanged, label=r'New Issues ($\Delta_{\mathrm{NEW}}$)', color='#EF5350', edgecolor='#B71C1C')
bar3 = ax.bar(builds, fixed_issues, label=r'Fixed Issues ($\Delta_{\mathrm{FIXED}}$)', color='#66BB6A', edgecolor='#2E7D32', alpha=0.85)

ax.set_ylabel('Vulnerability Count', fontweight='bold')
ax.set_title('Delta Vulnerability Tracking across Build Iterations', fontweight='bold', pad=10)
ax.legend(loc='upper right', framealpha=0.95)
ax.grid(axis='y', linestyle='--', alpha=0.5)

for i, total in enumerate([46, 39, 25]):
    ax.text(i, total + 1.0, f'Active: {total}', ha='center', fontweight='bold', fontsize=9.5)

plt.savefig("paper/figures/fig4_delta_diff.pdf")
plt.savefig("paper/figures/fig4_delta_diff.png")
plt.close()

print("Successfully generated all 4 publication-grade figures in paper/figures/")
