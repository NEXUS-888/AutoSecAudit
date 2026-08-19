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
# Figure 1: Hand-Crafted Layered System Architecture
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(9.8, 4.4))
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis('off')

# Background container canvas
main_bg = FancyBboxPatch((0.5, 0.5), 99, 99, boxstyle="round,pad=0.2,rounding_size=1.0",
                         facecolor="#FAFAFA", edgecolor="#E2E8F0", linewidth=1.0, zorder=1)
ax.add_patch(main_bg)

# Stage 1: Ingestion & Surface Discovery
ax.add_patch(FancyBboxPatch((2, 48), 21, 47, boxstyle="round,pad=0.2,rounding_size=1.2", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.2, zorder=2))
ax.add_patch(Rectangle((2, 87), 21, 8, facecolor="#1E293B", edgecolor="none", zorder=3))
ax.text(12.5, 91, "1. Surface Discovery", ha="center", va="center", color="#FFFFFF", fontsize=8.5, fontweight="bold", zorder=4)
ax.text(12.5, 80, "BFS Web Crawler", ha="center", va="center", color="#0F172A", fontsize=8.0, fontweight="bold", zorder=4)
ax.text(12.5, 73, "• Link & Form Extractor\n• Query String Parsing\n• Depth Bounded ($D_{max}$)", ha="center", va="center", color="#475569", fontsize=7.2, zorder=4)
ax.text(12.5, 60, "OpenAPI / Swagger", ha="center", va="center", color="#0F172A", fontsize=8.0, fontweight="bold", zorder=4)
ax.text(12.5, 53, "• v2.0 / v3.0 Spec Parser\n• Schema & Path Variables\n• HTTP Verb Registration", ha="center", va="center", color="#475569", fontsize=7.2, zorder=4)

# Stage 2: Concurrent Multi-Scanner Engine
ax.add_patch(FancyBboxPatch((26, 48), 35, 47, boxstyle="round,pad=0.2,rounding_size=1.2", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.2, zorder=2))
ax.add_patch(Rectangle((26, 87), 35, 8, facecolor="#0F766E", edgecolor="none", zorder=3))
ax.text(43.5, 91, "2. Scanner Engine (14 Plugins)", ha="center", va="center", color="#FFFFFF", fontsize=8.5, fontweight="bold", zorder=4)

sub_scanners = [
    ("Reconnaissance", "Nmap, Nikto, DirBrute", 28, 68),
    ("Web Injections", "SQLi, XSS, CORS, Misconfig", 44, 68),
    ("API & Auth", "APIAbuse, Auth, JWT", 28, 51),
    ("Exploit Vectors", "CmdInj, SSRF, PathTrav, SSTI", 44, 51),
]
for title, items, px, py in sub_scanners:
    ax.add_patch(FancyBboxPatch((px, py), 15, 14, boxstyle="round,pad=0.1,rounding_size=0.6", facecolor="#FFFFFF", edgecolor="#94A3B8", linewidth=0.8, zorder=3))
    ax.text(px + 7.5, py + 10.5, title, ha="center", va="center", color="#0F766E", fontsize=7.2, fontweight="bold", zorder=4)
    ax.text(px + 7.5, py + 5.0, items, ha="center", va="center", color="#334155", fontsize=6.3, zorder=4)

ax.text(43.5, 84, "ThreadPoolExecutor ($k=8$)  |  Baseline Differential Cache", ha="center", va="center", color="#047857", fontsize=7.0, fontweight="bold", zorder=4)

# Stage 3: Post-Processing Intelligence Layer
ax.add_patch(FancyBboxPatch((64, 48), 34, 47, boxstyle="round,pad=0.2,rounding_size=1.2", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.2, zorder=2))
ax.add_patch(Rectangle((64, 87), 34, 8, facecolor="#1D4ED8", edgecolor="none", zorder=3))
ax.text(81, 91, "3. Intelligence & Correlation Layer", ha="center", va="center", color="#FFFFFF", fontsize=8.5, fontweight="bold", zorder=4)

intel_steps = [
    ("Heuristic Deduplication", "Compound key: host+port+URI+weakness", 66, 75),
    ("Threat Enrichment", "Live queries to NIST NVD & CIRCL APIs", 66, 64),
    ("Taxonomy Mapping", "Deterministic OWASP, CWE & PCI-DSS tags", 66, 53),
]
for title, desc, px, py in intel_steps:
    ax.add_patch(FancyBboxPatch((px, py), 30, 9.5, boxstyle="round,pad=0.1,rounding_size=0.5", facecolor="#FFFFFF", edgecolor="#93C5FD", linewidth=0.8, zorder=3))
    ax.text(px + 15, py + 6.2, title, ha="center", va="center", color="#1E3A8A", fontsize=7.2, fontweight="bold", zorder=4)
    ax.text(px + 15, py + 2.5, desc, ha="center", va="center", color="#475569", fontsize=6.4, zorder=4)

# Stage 4: Delivery, CI/CD Policy Gating & Real-Time Monitoring
ax.add_patch(FancyBboxPatch((2, 5), 96, 37, boxstyle="round,pad=0.2,rounding_size=1.2", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.2, zorder=2))
ax.add_patch(Rectangle((2, 34), 96, 8, facecolor="#475569", edgecolor="none", zorder=3))
ax.text(50, 38, "4. Delivery, CI/CD Policy Gating & Multi-Channel Reporting", ha="center", va="center", color="#FFFFFF", fontsize=8.5, fontweight="bold", zorder=4)

deliv_blocks = [
    ("CI/CD Build Gating", "Exit 1 on threshold (>= threshold)\nNon-zero exit on criticals", 6, 9, 26, 21),
    ("Set-Theoretic Delta", "Partitions Delta_NEW, Delta_FIXED\nTracks regressions vs baseline", 37, 9, 26, 21),
    ("Multi-Channel Output", "Real-Time SSE Web Dashboard\nPDF / HTML Reports & Webhooks", 68, 9, 26, 21)
]
for title, desc, px, py, pw, ph in deliv_blocks:
    ax.add_patch(FancyBboxPatch((px, py), pw, ph, boxstyle="round,pad=0.1,rounding_size=0.6", facecolor="#FFFFFF", edgecolor="#94A3B8", linewidth=0.8, zorder=3))
    ax.text(px + pw/2, py + ph - 4.5, title, ha="center", va="center", color="#1E293B", fontsize=7.6, fontweight="bold", zorder=4)
    ax.text(px + pw/2, py + 6.0, desc, ha="center", va="center", color="#475569", fontsize=6.8, zorder=4)

# Clean connecting arrows
arrow_props = dict(facecolor='#334155', edgecolor='#334155', width=1.2, headwidth=5.0, shrink=0.01)
ax.annotate('', xy=(26, 71.5), xytext=(23, 71.5), arrowprops=arrow_props)
ax.annotate('', xy=(64, 71.5), xytext=(61, 71.5), arrowprops=arrow_props)
ax.annotate('', xy=(81, 42), xytext=(81, 48), arrowprops=arrow_props)

plt.savefig("paper/figures/fig1_architecture.pdf")
plt.savefig("paper/figures/fig1_architecture.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 2: Scan Latency & Speedup (Clean Palette, No Clashing Box)
# ---------------------------------------------------------------------------
threads = [1, 2, 4, 8, 16]
latency = [184.2, 102.5, 71.4, 64.8, 66.1]
speedup = [1.0, 1.80, 2.58, 2.84, 2.79]

fig, ax1 = plt.subplots(figsize=(4.8, 2.9))

c_lat = '#1E3A8A'
ax1.set_xlabel('Worker Threads ($k$)', fontweight='bold')
ax1.set_ylabel('Scan Latency (s)', color=c_lat, fontweight='bold')
line1 = ax1.plot(threads, latency, marker='o', color=c_lat, linewidth=1.6, markersize=5, label='Latency (s)')
ax1.tick_params(axis='y', labelcolor=c_lat)
ax1.set_xticks(threads)
ax1.set_ylim(40, 205)
ax1.grid(True, linestyle=':', alpha=0.5)

# Subtle guide line at k=8
ax1.axvline(x=8, color='#94A3B8', linestyle='--', linewidth=0.9, zorder=2)
ax1.text(8.3, 130, 'Optimal $k=8$\n64.8 s ($2.84\\times$)', fontsize=7.5, color='#1E3A8A', fontweight='bold',
         bbox=dict(boxstyle='round,pad=0.2', facecolor='#F1F5F9', edgecolor='#94A3B8', linewidth=0.6))

ax2 = ax1.twinx()
c_spd = '#0F766E'
ax2.set_ylabel('Speedup ($\\times$)', color=c_spd, fontweight='bold')
line2 = ax2.plot(threads, speedup, marker='s', color=c_spd, linewidth=1.6, linestyle='--', markersize=5, label='Speedup ($\\times$)')
ax2.tick_params(axis='y', labelcolor=c_spd)
ax2.set_ylim(0.8, 3.2)

lines = line1 + line2
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='center right', framealpha=0.9)

plt.savefig("paper/figures/fig2_latency.pdf")
plt.savefig("paper/figures/fig2_latency.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 3: Alert Noise Reduction (Distinct Clean Visual Language)
# ---------------------------------------------------------------------------
categories = ['SQLi\n(A03)', 'XSS\n(A03)', 'Misconfig\n(A05)', 'Access\n(A01)', 'API/JWT\n(A07)', 'Adv Expl\n(A03/10)']
raw_alerts = [14, 19, 26, 9, 8, 4]
correlated = [8, 12, 15, 6, 5, 4]

x = np.arange(len(categories))
width = 0.36

fig, ax = plt.subplots(figsize=(5.0, 2.9))
rects1 = ax.bar(x - width/2, raw_alerts, width, label='Raw Alerts (76)', color='#64748B', edgecolor='#334155', linewidth=0.7)
rects2 = ax.bar(x + width/2, correlated, width, label='Correlated (46)', color='#1D4ED8', edgecolor='#1E3A8A', linewidth=0.7)

ax.set_ylabel('Finding Count', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=7.5)
ax.set_ylim(0, 31)
ax.legend(loc='upper right', framealpha=0.9)
ax.grid(axis='y', linestyle=':', alpha=0.5)

for rect in rects1:
    h = rect.get_height()
    ax.annotate(f'{h}', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 2),
                textcoords="offset points", ha='center', va='bottom', fontsize=7.5)

for rect in rects2:
    h = rect.get_height()
    ax.annotate(f'{h}', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 2),
                textcoords="offset points", ha='center', va='bottom', fontsize=7.5, fontweight='bold', color='#1D4ED8')

plt.savefig("paper/figures/fig3_noise_reduction.pdf")
plt.savefig("paper/figures/fig3_noise_reduction.png")
plt.close()

# ---------------------------------------------------------------------------
# Figure 4: Delta Lifecycle Tracking (Refined Progression)
# ---------------------------------------------------------------------------
builds = ['Build v1.0\n(Baseline)', 'Build v1.1\n(Patch & New)', 'Build v1.2\n(Hardened)']
unchanged = [46, 36, 25]
new_issues = [0, 3, 0]
fixed_issues = [0, 10, 14]

fig, ax = plt.subplots(figsize=(4.8, 2.9))

bar1 = ax.bar(builds, unchanged, label=r'Unchanged ($\Delta_{\mathrm{UNCHANGED}}$)', color='#94A3B8', edgecolor='#475569', linewidth=0.7)
bar2 = ax.bar(builds, new_issues, bottom=unchanged, label=r'New ($\Delta_{\mathrm{NEW}}$)', color='#DC2626', edgecolor='#991B1B', linewidth=0.7)
bar3 = ax.bar(builds, fixed_issues, label=r'Resolved ($\Delta_{\mathrm{FIXED}}$)', color='#059669', edgecolor='#065F46', linewidth=0.7, alpha=0.9)

ax.set_ylabel('Vulnerability Count', fontweight='bold')
ax.set_ylim(0, 58)
ax.legend(loc='upper right', framealpha=0.9)
ax.grid(axis='y', linestyle=':', alpha=0.5)

for i, total in enumerate([46, 39, 25]):
    ax.text(i, total + 1.5, f'Active: {total}', ha='center', fontweight='bold', fontsize=8, color='#0F172A')

plt.savefig("paper/figures/fig4_delta_diff.pdf")
plt.savefig("paper/figures/fig4_delta_diff.png")
plt.close()

print("Successfully regenerated all publication-grade figures in paper/figures/")
