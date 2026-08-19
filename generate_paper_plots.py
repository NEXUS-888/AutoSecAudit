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
ax.text(12, 60, "BFS Web Crawler\n• Form / Link Ingestion\n• Query Parameter Parser\n• Max Depth Bounded ($D_{max}$)", ha="center", va="center", color="#334155", fontsize=6.8, zorder=4)
ax.text(12, 26, "OpenAPI / Swagger\n• v2.0 / v3.0 Parser\n• Endpoint Schema Seeding\n• HTTP Verb Registration", ha="center", va="center", color="#334155", fontsize=6.8, zorder=4)

# Stage 2: Concurrent Multi-Scanner Engine
ax.add_patch(FancyBboxPatch((25.5, 4), 23.5, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((25.5, 78), 23.5, 18, facecolor="#0F766E", edgecolor="none", zorder=3))
ax.text(37.25, 87, "2. Scanner Engine (14)", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(37.25, 68, "Recon: Nmap, Nikto, DirBrute\nWeb: SQLi, XSS, CORS, Misconfig", ha="center", va="center", color="#0F766E", fontsize=6.7, fontweight="bold", zorder=4)
ax.text(37.25, 44, "API/Auth: APIAbuse, Auth, JWT\nExploit: CmdInj, SSRF, PathTrav", ha="center", va="center", color="#0F766E", fontsize=6.7, fontweight="bold", zorder=4)
ax.text(37.25, 18, "ThreadPool ($k=8$ Workers)\nDifferential Baseline Cache", ha="center", va="center", color="#047857", fontsize=6.7, zorder=4)

# Stage 3: Post-Processing Intelligence Layer
ax.add_patch(FancyBboxPatch((51.5, 4), 22.5, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((51.5, 78), 22.5, 18, facecolor="#1D4ED8", edgecolor="none", zorder=3))
ax.text(62.75, 87, "3. Intelligence Layer", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(62.75, 62, "Compound Deduplication\n• Key: host+port+URI+CWE\n• Multi-alert merging (-39.5%)", ha="center", va="center", color="#1E3A8A", fontsize=6.7, zorder=4)
ax.text(62.75, 28, "Enrichment & Compliance\n• NIST NVD & CIRCL CVEs\n• OWASP '21, CWE, PCI-DSS", ha="center", va="center", color="#1E3A8A", fontsize=6.7, zorder=4)

# Stage 4: Delivery, CI/CD Policy Gating & Real-Time Monitoring
ax.add_patch(FancyBboxPatch((76.5, 4), 22.5, 92, boxstyle="round,pad=0.1,rounding_size=1.0", facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.1, zorder=2))
ax.add_patch(Rectangle((76.5, 78), 22.5, 18, facecolor="#475569", edgecolor="none", zorder=3))
ax.text(87.75, 87, "4. Policy & Delivery", ha="center", va="center", color="#FFFFFF", fontsize=8.2, fontweight="bold", zorder=4)
ax.text(87.75, 62, "CI/CD Policy Gating\n• Native exit code (--fail-on)\n• Set-Theoretic Delta Diffing", ha="center", va="center", color="#334155", fontsize=6.7, zorder=4)
ax.text(87.75, 28, "Multi-Channel Reporting\n• Real-Time SSE Dashboard\n• PDF / HTML & Webhooks", ha="center", va="center", color="#334155", fontsize=6.7, zorder=4)

# Horizontal arrows
arrow_props = dict(facecolor='#334155', edgecolor='#334155', width=1.1, headwidth=4.5, shrink=0.01)
ax.annotate('', xy=(25.5, 50), xytext=(23.0, 50), arrowprops=arrow_props)
ax.annotate('', xy=(51.5, 50), xytext=(49.0, 50), arrowprops=arrow_props)
ax.annotate('', xy=(76.5, 50), xytext=(74.0, 50), arrowprops=arrow_props)

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
