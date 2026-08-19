import os
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
import numpy as np

# Ensure output directory exists
os.makedirs("paper/figures", exist_ok=True)

# Standardized publication typography and styling
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Helvetica', 'Arial', 'DejaVu Sans'],
    'font.size': 9.5,
    'axes.labelsize': 10.5,
    'axes.titlesize': 11,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 8.5,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight'
})

# ---------------------------------------------------------------------------
# Figure 1: Architecture Pipeline (Clean Academic Style)
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(9.2, 3.8))
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

stages = [
    {
        "header": "1. Surface Discovery",
        "body": "• BFS Web Crawler\n• OpenAPI/Swagger 3.0\n• Parameter Extraction",
        "xy": (0.02, 0.50), "w": 0.29, "h": 0.44, "bg": "#F8FAFC", "border": "#475569"
    },
    {
        "header": "2. Multi-Scanner Engine",
        "body": "• 14 Specialized Plugins\n• ThreadPool ($k=8$)\n• Baseline Response Cache",
        "xy": (0.355, 0.50), "w": 0.29, "h": 0.44, "bg": "#F8FAFC", "border": "#475569"
    },
    {
        "header": "3. Intelligence Layer",
        "body": "• Compound-Key Deduplication\n• NIST/CIRCL CVE Enrichment\n• OWASP/CWE/PCI Mapping\n• Delta Regression Diffing",
        "xy": (0.69, 0.50), "w": 0.29, "h": 0.44, "bg": "#F8FAFC", "border": "#475569"
    },
    {
        "header": "4. Delivery, CI/CD Policy Gating & Real-Time Monitoring",
        "body": "• Native Exit-Code Gating (--fail-on)     • Webhooks (Slack / Discord)     • Interactive Real-Time Dashboard (SSE)",
        "xy": (0.02, 0.08), "w": 0.96, "h": 0.32, "bg": "#F1F5F9", "border": "#334155"
    }
]

for s in stages:
    # Outer box
    rect = FancyBboxPatch(s["xy"], s["w"], s["h"],
                          boxstyle="round,pad=0.012,rounding_size=0.015",
                          facecolor=s["bg"], edgecolor=s["border"], linewidth=1.2, zorder=2)
    ax.add_patch(rect)
    
    # Header text
    ax.text(s["xy"][0] + s["w"]/2, s["xy"][1] + s["h"] - 0.07, s["header"],
            ha="center", va="center", fontsize=9.5, fontweight="bold", color="#0F172A", zorder=3)
    
    # Body text
    ax.text(s["xy"][0] + s["w"]/2, s["xy"][1] + (s["h"] - 0.07)/2, s["body"],
            ha="center", va="center", fontsize=8.5, color="#334155", zorder=3, linespacing=1.35)

# Connecting arrows
arrow_props = dict(facecolor='#334155', edgecolor='#334155', width=1.1, headwidth=4.5, shrink=0.02)
ax.annotate('', xy=(0.355, 0.72), xytext=(0.31, 0.72), arrowprops=arrow_props)
ax.annotate('', xy=(0.69, 0.72), xytext=(0.645, 0.72), arrowprops=arrow_props)
ax.annotate('', xy=(0.50, 0.40), xytext=(0.835, 0.50), arrowprops=dict(facecolor='#334155', edgecolor='#334155', width=1.1, headwidth=4.5, shrink=0.02))

plt.savefig("paper/figures/fig1_architecture.pdf")
plt.savefig("paper/figures/fig1_architecture.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 2: Scan Latency & Speedup
# ---------------------------------------------------------------------------
threads = [1, 2, 4, 8, 16]
latency = [184.2, 102.5, 71.4, 64.8, 66.1]
speedup = [1.0, 1.80, 2.58, 2.84, 2.79]

fig, ax1 = plt.subplots(figsize=(5.2, 3.2))

c_lat = '#1E3A8A'
ax1.set_xlabel('Concurrency Worker Threads ($k$)', fontweight='bold')
ax1.set_ylabel('Scan Duration (s)', color=c_lat, fontweight='bold')
line1 = ax1.plot(threads, latency, marker='o', color=c_lat, linewidth=1.8, markersize=5.5, label='Scan Latency (s)')
ax1.tick_params(axis='y', labelcolor=c_lat)
ax1.set_xticks(threads)
ax1.set_ylim(40, 205)
ax1.grid(True, linestyle=':', alpha=0.6)

# Subtle highlight at k=8
ax1.plot(8, 64.8, marker='o', markersize=8, color='#DC2626', zorder=5)
ax1.annotate(r'$k=8 \rightarrow 64.8\,\mathrm{s}\ (2.84\times)$', xy=(8, 64.8), xytext=(8.3, 115),
             arrowprops=dict(arrowstyle="->", color='#DC2626', lw=1.1),
             bbox=dict(boxstyle="round,pad=0.2", fc="#FEF2F2", ec="#DC2626", lw=0.7),
             fontsize=8, fontweight='bold', color='#991B1B')

ax2 = ax1.twinx()
c_spd = '#0D9488'
ax2.set_ylabel('Speedup Factor ($\\times$)', color=c_spd, fontweight='bold')
line2 = ax2.plot(threads, speedup, marker='s', color=c_spd, linewidth=1.8, linestyle='--', markersize=5.5, label='Speedup ($\\times$)')
ax2.tick_params(axis='y', labelcolor=c_spd)
ax2.set_ylim(0.8, 3.2)

lines = line1 + line2
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='center right', framealpha=0.92)

plt.savefig("paper/figures/fig2_latency.pdf")
plt.savefig("paper/figures/fig2_latency.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 3: Alert Noise Reduction
# ---------------------------------------------------------------------------
categories = ['SQLi\n(A03)', 'XSS\n(A03)', 'Misconfig\n(A05)', 'Access\n(A01)', 'API/JWT\n(A07)', 'Adv Expl\n(A03/10)']
raw_alerts = [14, 19, 26, 9, 8, 4]
correlated = [8, 12, 15, 6, 5, 4]

x = np.arange(len(categories))
width = 0.35

fig, ax = plt.subplots(figsize=(5.4, 3.2))
rects1 = ax.bar(x - width/2, raw_alerts, width, label='Raw Alerts (76 Total)', color='#64748B', edgecolor='#334155', linewidth=0.7)
rects2 = ax.bar(x + width/2, correlated, width, label='Correlated (46 Total)', color='#1E3A8A', edgecolor='#0F172A', linewidth=0.7)

ax.set_ylabel('Finding Count', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=8)
ax.set_ylim(0, 31)
ax.legend(loc='upper right', framealpha=0.92)
ax.grid(axis='y', linestyle=':', alpha=0.6)

def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, fontweight='bold')

autolabel(rects1)
autolabel(rects2)

plt.savefig("paper/figures/fig3_noise_reduction.pdf")
plt.savefig("paper/figures/fig3_noise_reduction.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 4: Delta Lifecycle Tracking
# ---------------------------------------------------------------------------
builds = ['Build v1.0\n(Baseline)', 'Build v1.1\n(Patch & New)', 'Build v1.2\n(Hardened)']
unchanged = [46, 36, 25]
new_issues = [0, 3, 0]
fixed_issues = [0, 10, 14]

fig, ax = plt.subplots(figsize=(5.2, 3.2))

bar1 = ax.bar(builds, unchanged, label=r'Unchanged ($\Delta_{\mathrm{UNCHANGED}}$)', color='#94A3B8', edgecolor='#475569', linewidth=0.7)
bar2 = ax.bar(builds, new_issues, bottom=unchanged, label=r'New ($\Delta_{\mathrm{NEW}}$)', color='#DC2626', edgecolor='#991B1B', linewidth=0.7)
bar3 = ax.bar(builds, fixed_issues, label=r'Resolved ($\Delta_{\mathrm{FIXED}}$)', color='#059669', edgecolor='#065F46', linewidth=0.7, alpha=0.9)

ax.set_ylabel('Vulnerability Count', fontweight='bold')
ax.set_ylim(0, 58)
ax.legend(loc='upper right', framealpha=0.92)
ax.grid(axis='y', linestyle=':', alpha=0.6)

for i, total in enumerate([46, 39, 25]):
    ax.text(i, total + 1.5, f'Active: {total}', ha='center', fontweight='bold', fontsize=8.5, color='#0F172A')

plt.savefig("paper/figures/fig4_delta_diff.pdf")
plt.savefig("paper/figures/fig4_delta_diff.png")
plt.close()

print("Successfully regenerated all 4 cohesive, publication-grade figures in paper/figures/")
