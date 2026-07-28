# AutoSecAudit 2.0 🛡️

> **An Intelligent, Extensible Security Auditing Engine & Multi-Scanner Orchestrator**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Build](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](#-testing--quality-assurance)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-blue.svg)](#-quick-start)

---

## ❓ What Problem Does AutoSecAudit Solve?

### The Security Tooling Dilemma
In modern software engineering, auditing a web application or API for security vulnerabilities usually requires running multiple fragmented CLI tools:
- `nmap` in Terminal 1 for open ports.
- `nikto` in Terminal 2 for web server misconfigurations.
- Custom scripts or manual browser testing for SQLi, XSS, CORS, and Auth flaws.

This manual workflow causes **four critical pain points**:
1. **Tool Output Overload & Noise**: Security engineers waste hours sifting through raw text logs, duplicating findings across tools, and manually verifying false positives.
2. **Lack of CVE & Compliance Context**: Raw scanner outputs don't automatically map vulnerabilities to industry standards (**OWASP Top 10**, **CWE**, **PCI-DSS v4.0**) or lookup live **CVSS risk scores**.
3. **No Automated CI/CD Gating**: Security testing is often done *after* code reaches production because traditional scanners cannot be embedded into fast GitHub/GitLab build pipelines to block unsafe code.
4. **Poor Reporting & Delta Tracking**: Traditional tools output messy text logs rather than interactive dashboards, and cannot automatically answer: *"What new vulnerabilities were introduced in today's release compared to last week's build?"*

---

## 💡 The Solution: AutoSecAudit 2.0

**AutoSecAudit 2.0** unifies web crawling, multi-scanner orchestration, intelligence post-processing, differential scan analysis, and interactive reporting into a single, lightweight Python framework.

```
                  ┌─────────────────────────────────────────┐
                  │          TARGET (URL / IP / API)        │
                  └────────────────────┬────────────────────┘
                                       │
                         ┌─────────────▼─────────────┐
                         │   AutoSecAudit Crawler    │
                         └─────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
 ┌────────▼────────┐          ┌────────▼────────┐          ┌────────▼────────┐
 │ Network & Ports │          │ Web Injections  │          │  API & Auth     │
 │ Nmap, Nikto,    │          │ SQLi, XSS, CORS,│          │ Auth, JWT,      │
 │ DirBrute        │          │ RCE, SSRF, SSTI │          │ API Abuse       │
 └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
          │                            │                            │
          └────────────────────────────┼────────────────────────────┘
                                       │
                         ┌─────────────▼─────────────┐
                         │    Intelligence Engine    │
                         │ Correlate • Enrich (NVD)  │
                         │ OWASP • CWE • PCI-DSS     │
                         │ Delta Diff • Remediation  │
                         └─────────────┬─────────────┘
                                       │
          ┌────────────────────────────┴────────────────────────────┐
          │                                                         │
 ┌────────▼────────┐                                       ┌────────▼────────┐
 │ Interactive UI  │                                       │ CI/CD & Reports │
 │ Real-time SSE   │                                       │ Build Gating    │
 │ HTML Dashboard  │                                       │ Webhook Alerts  │
 │ History Tracker │                                       │ JSON & PDF      │
 └─────────────────┘                                       └─────────────────┘
```

---

## ✨ Key Capabilities

### 1. 🔌 14 Built-in Security Scanner Plugins
AutoSecAudit auto-discovers and executes 14 specialized scanner plugins:
- **Infrastructure & Recon**: `NmapPlugin` (Port scanning), `NiktoPlugin` (Server auditing), `DirBruteScanner` (50+ path discovery).
- **Web Application Injections**: `SQLiScanner` (SQL Injection), `XSSScanner` (Cross-Site Scripting), `CORSScanner` (CORS Misconfigurations), `MisconfigScanner` (Header security).
- **API & Authentication**: `APIAbuseScanner` (Mass assignment, data leaks), `AuthScanner` (Default creds, IDOR, enumeration), `JWTScanner` (JWT token flaws).
- **Advanced Attack Vectors**: `CommandInjectionScanner` (RCE), `SSRFScanner` (Server-Side Request Forgery), `PathTraversalScanner` (LFI), `SSTIScanner` (Template injection).

### 2. 🧠 Post-Processing Intelligence Layer
- **Deduplication Correlator**: Merges overlapping findings from multiple tools for the same endpoint.
- **Live CVE Enrichment**: Queries NVD and CIRCL APIs for real-time CVSS scoring.
- **Multi-Compliance Mapping**: Auto-tags findings with **OWASP Top 10 (2021)**, **CWE IDs** (e.g. `CWE-89`), and **PCI-DSS v4.0** requirements (e.g. `PCI-DSS 6.2.4`).
- **Delta Analysis Engine**: Compares current scans against past baselines to highlight `NEW`, `FIXED`, and `UNCHANGED` issues.
- **Actionable Remediation**: Generates concrete code snippets and server configuration lines to fix each finding.

### 3. 🚀 Enterprise CI/CD & Automation Features
- **Build Pipeline Gating (`--fail-on`)**: Exits status code `1` if findings meet or exceed your severity threshold (`critical`, `high`, `medium`, `low`).
- **Slack & Discord Webhook Alerts (`--webhook`)**: Sends formatted alert notifications upon scan completion.
- **OpenAPI / Swagger Spec Importer (`--openapi`)**: Parses local files or remote URLs (`swagger.json`) to pre-fill API endpoints.
- **Custom Authentication Headers (`--headers`)**: Supports `--headers "Authorization: Bearer <token>"` for authenticated route scanning.

### 4. 📊 Modern Web UI & Printable Exports
- **Real-Time Progress Streaming**: SSE (Server-Sent Events) live scan progress bar and console log output.
- **Interactive HTML Dashboard**: Filter by severity, search findings, toggle dark/light mode, and inspect pop-up detail modals.
- **Executive PDF Summaries**: Generate printable PDF security summary reports with a single click.

---

## ⚡ Quick Start & Installation

### Option A: Local Python Setup (Recommended for Dev)

```bash
# 1. Clone the repository
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run a CLI security scan against a local target
python main.py scan http://localhost:3000

# 4. Start the Web UI
python main.py server
# Open http://localhost:5000 in your browser!
```

### Option B: Docker Compose (Includes OWASP Juice Shop Target)

Launch AutoSecAudit alongside an intentionally vulnerable benchmark application (**OWASP Juice Shop**):

```bash
docker-compose up -d

# Open the AutoSecAudit Web UI at http://localhost:5000
# The OWASP Juice Shop benchmark target runs at http://localhost:3000
```

---

## 💻 CLI Command Reference

```bash
# ── Basic Scan ────────────────────────────────────────────────────────────
python main.py scan http://localhost:3000

# ── CI/CD Build Gating ───────────────────────────────────────────────────
# Fails build (exit status 1) if CRITICAL or HIGH findings exist
python main.py scan http://localhost:3000 --fail-on high

# ── OpenAPI / Swagger Specification Import ──────────────────────────────
python main.py scan http://localhost:3000 --openapi ./swagger.json

# ── Slack / Discord Webhook Notifications ─────────────────────────────────
python main.py scan http://localhost:3000 --webhook https://discord.com/api/webhooks/YOUR_HOOK

# ── Authenticated Scanning with Custom Headers ───────────────────────────
python main.py scan http://localhost:3000 --headers "Authorization: Bearer my_token; X-API-Key: 12345"

# ── Delta Comparison with Previous Scan ─────────────────────────────────
python main.py scan http://localhost:3000 --previous data/reports/scan_20260728.json

# ── Plugin Directory & Unified Test Runner ────────────────────────────────
python main.py plugins
python run_tests.py
```

---

## 🎯 Primary Use Cases

1. **DevSecOps & Release Gating**: Embed AutoSecAudit in GitHub Actions or GitLab CI to prevent security regressions before shipping code to production.
2. **API & Web Application Auditing**: Conduct automated vulnerability assessments across REST APIs and web servers in minutes.
3. **Security Health & Delta Tracking**: Run weekly automated scans against staging environments to monitor fixed vs newly introduced vulnerabilities.
4. **Client Deliverables**: Generate interactive HTML dashboards and executive PDF reports for clients and technical leads.

---

## 🧪 Testing & Quality Assurance

AutoSecAudit includes a unified test runner executing 80 unit and integration tests across all 14 scanner plugins, crawler logic, intelligence mapping, and CLI gating:

```bash
python run_tests.py
```

The project includes an automated **GitHub Actions CI workflow** ([.github/workflows/ci.yml](file:///.github/workflows/ci.yml)) that runs `python run_tests.py` on every commit and pull request.

---

## 🤝 License

Distributed under the MIT License. See `LICENSE` for more information.
