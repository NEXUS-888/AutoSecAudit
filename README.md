# AutoSecAudit 2.0 🛡️

> **An Intelligent Security Auditing Framework, Multi-Attack Simulator & Autonomous AI Remediation Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Build](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](#-testing--quality-assurance)
[![MCP Ready](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple.svg)](#-model-context-protocol-mcp-server)
[![Tests: 111 Passed](https://img.shields.io/badge/Tests-111%20Passed-success.svg)](#-testing--quality-assurance)

---

## ❓ What Problem Does AutoSecAudit Solve?

### The Security Tooling Dilemma
In modern software engineering, assessing a web application or API for vulnerabilities has traditionally suffered from major roadblocks:
1. **Tool Fragmentation & Noise**: Running `nmap`, `nikto`, and disparate scripts generates cluttered logs with duplicate findings and high false positives.
2. **Overwhelming for Non-Technical Stakeholders**: Traditional reports show raw CVE numbers, CVSS scores, and hexadecimal traces, leaving executives and product owners wondering: *"What is the actual business danger? What can an attacker actually do?"*
3. **No Direct Code Fixes**: Scanners identify what is broken but leave developers to figure out framework-specific patches or WAF rules on their own.
4. **Disconnection from AI Development Workflows**: Modern developers write code in **Cursor**, **Claude Code**, or **VS Code**, but security scanners remain locked in separate CLI terminals.

---

## 💡 The Solution: AutoSecAudit 2.0

**AutoSecAudit 2.0** unifies web crawling, multi-attack simulation, plain-English business risk classification, drop-in multi-framework code patches, differential scan analysis, and native **Model Context Protocol (MCP)** autonomous code repair into a single Python framework.

```
                  ┌─────────────────────────────────────────┐
                  │          TARGET (URL / IP / API)        │
                  │   Live Web • REST API • Local Testbed   │
                  └────────────────────┬────────────────────┘
                                       │
                         ┌─────────────▼─────────────┐
                         │   AutoSecAudit Crawler    │
                         └─────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
 ┌────────▼────────┐          ┌────────▼────────┐          ┌────────▼────────┐
 │ Network & Recon │          │ Web Injections  │          │  API & Access   │
 │ Nmap, Nikto,    │          │ SQLi, XSS, CSRF,│          │ BOLA/IDOR, Auth,│
 │ DirBrute, TLS   │          │ RCE, SSRF, SSTI │          │ JWT, Secret Leak│
 └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
          │                            │                            │
          └────────────────────────────┼────────────────────────────┘
                                       │
                         ┌─────────────▼─────────────┐
                         │    Intelligence Engine    │
                         │ Correlate • Enrich (NVD)  │
                         │ Threat Matrix • Danger    │
                         │ Multi-Framework Recipes   │
                         └─────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
 ┌────────▼────────┐          ┌────────▼────────┐          ┌────────▼────────┐
 │ Interactive UI  │          │   MCP Server    │          │ CI/CD & Reports │
 │ Real-time SSE   │          │ Cursor & Claude │          │ Build Gating    │
 │ Dual-View Lens  │          │ Auto Code Fixes │          │ JSON, WAF & PDF │
 └─────────────────┘          └─────────────────┘          └─────────────────┘
```

---

## ✨ Key Capabilities

### 1. 🔌 19 Dynamic Vulnerability Scanner Plugins
AutoSecAudit automatically discovers and executes 19 specialized attack simulation scanners:
- **Web Application Injections**: `SQLiScanner` (SQL Injection), `XSSScanner` (Reflected & Stored XSS), `CSRFScanner` (Cross-Site Request Forgery), `OpenRedirectScanner` (Unvalidated Redirections), `MisconfigScanner` (Security headers).
- **API & Access Control**: `BOLAIdorScanner` (Broken Object-Level Authorization / IDOR), `APIAbuseScanner` (Mass assignment, rate limiting), `AuthScanner` (Default credentials, account enumeration), `JWTScanner` (JWT signing and algorithm flaws).
- **Advanced Attack Vectors**: `CommandInjectionScanner` (RCE), `SSRFScanner` (Server-Side Request Forgery), `PathTraversalScanner` (LFI/Directory Traversal), `SSTIScanner` (Server-Side Template Injection).
- **Infrastructure & Secrets**: `SecretExposureScanner` (Public `.env`, `.git`, backups), `SSLTLSScanner` (Weak TLS & missing HSTS), `DirBruteScanner` (50+ curated hidden paths), `NiktoPlugin` (Web server misconfiguration), `NmapPlugin` (Port scanning).

### 2. 🎯 Selectable Scan Profiles
Tailor your security audit to specific contexts using predefined scan profiles:
- 🌐 **`full` (Full Spectrum DAST)**: Executes all 19 scanner plugins concurrently.
- 🛡️ **`owasp` (OWASP Top 10 Suite)**: Focuses on core injection, auth, CSRF, SSRF, and misconfigurations.
- ⚡ **`api` (API & Microservice Suite)**: Tailored for headless JSON REST APIs (BOLA/IDOR, JWT, CORS, rate limits).
- 🔍 **`recon` (Passive Reconnaissance)**: Non-intrusive scanning (SSL/TLS, security headers, directory discovery, port scans).

### 3. 🚨 Plain-English "Real Danger" Engine
Automatically classifies technical findings into **4 Business Risk Categories**:
- 🚨 **Customer & Database Theft** (*SQLi, Directory Listing, `.git`/`.env` credential leaks*)
- 💳 **Account Hijacking & Auth Bypass** (*JWT weaknesses, brute-force, missing cookie flags*)
- 🌐 **Phishing, XSS & Brand Defacement** (*CORS wildcard, XSS, Clickjacking/CSP, Open Redirects*)
- 🛑 **Full Server Takeover & RCE** (*Remote command injection*)

Provides non-technical executive summaries:
- **Executive Security Posture Grade**: Letter grade (`A+` to `F`, score out of 100).
- **What is Broken**: Simple plain-English technical explanation.
- **What an Attacker Can Actually Do**: Real-world threat exploitation scenario.
- **Business Impact**: Direct financial, compliance, and reputational liabilities.
- **Estimated Fix Time**: Practical resolution timeline (e.g. `5-15 min`).

### 4. ⚡ Multi-Framework Drop-in Fix Recipes & Dev Tickets
- **Instant Code Patches**: Copy-pasteable code snippets generated for:
  - 🟢 **Node.js / Express** (Parameterized queries, Helmet.js, CSRF middleware)
  - 🐍 **Python / Flask / FastAPI / Django** (SQLAlchemy ORM, Talisman headers, Bleach sanitization)
  - ⚙️ **Nginx Hardening** (Header injection, rate limiting, dotfile blocking)
  - 🛡️ **Cloudflare / AWS WAF** (JSON virtual patching rules)
- **1-Click Dev Ticket Export**: Generates pre-formatted Markdown tickets ready for Jira, Linear, GitHub Issues, and Slack.

### 5. 🤖 Autonomous AI Remediation via Model Context Protocol (MCP)
AutoSecAudit includes an official standard **JSON-RPC 2.0 stdio MCP Server** (`mcp_server.py`) for **Cursor**, **Claude Code**, and **VS Code**:
- `autosec_scan(target, profile, mock)`: Trigger automated scans and receive structured summaries.
- `autosec_get_findings(report_id, view)`: Retrieve findings enriched with Plain-English Danger assessments.
- `autosec_get_fix_recipe(finding_title, framework)`: Fetch drop-in code patches for AI agents to edit source code directly.
- `autosec_verify_fix(target, vulnerability_type)`: Run targeted verification to confirm whether an AI code fix resolved the vulnerability.

### 6. 🧪 Embedded Vulnerable Sandbox Testbed
Includes a local test application (`testbed/app.py`) containing intentional, safe test vectors (SQLi, XSS, CSRF, Open Redirect, BOLA, SSRF, SSTI, Secret Exposure) to safely test attack simulations locally.

---

## ⚡ Quick Start & Installation

### Option A: Local Python Setup (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the Web Dashboard
python main.py server
# Open http://localhost:5000 in your browser!
```

### Option B: Local Vulnerable Sandbox Testing

```bash
# 1. Launch the local vulnerable testbed app on port 8080
python main.py testbed --port 8080

# 2. In another terminal, run an active attack scan against the testbed
python main.py scan http://127.0.0.1:8080 --real --profile owasp
```

---

## 🔌 Model Context Protocol (MCP) Server Setup

Connect AutoSecAudit directly to **Cursor** or **Claude Desktop** to enable autonomous AI code repair:

Add the following to your `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "autosecaudit": {
      "command": "python",
      "args": [
        "D:\\Projects\\AutoSec\\AutoSecAudit\\mcp_server.py"
      ]
    }
  }
}
```

### Autonomous AI Workflow in Cursor / Claude:
1. **Scan**: *"Scan `http://localhost:3000` with AutoSec using the OWASP profile."*
2. **Review**: *"List the critical vulnerabilities in plain English."*
3. **Fix**: *"Fetch the fix recipe for the SQL Injection finding and apply the patch to `server.js`."*
4. **Verify**: *"Run AutoSec verification to confirm if the SQL Injection is resolved."*

---

## 💻 CLI Command Reference

```bash
# ── Basic Scan ────────────────────────────────────────────────────────────
python main.py scan http://localhost:3000

# ── Scan with Specific Profile (full | owasp | api | recon) ───────────────
python main.py scan http://localhost:3000 --profile owasp

# ── Live Active Scan (Sends real HTTP payloads) ──────────────────────────
python main.py scan http://localhost:3000 --real --profile api

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
python main.py scan http://localhost:3000 --previous data/reports/scan_20260831.json

# ── Launch Vulnerable Target Sandbox ─────────────────────────────────────
python main.py testbed --port 8080

# ── Start Web Dashboard ──────────────────────────────────────────────────
python main.py server --port 5000
```

---

## 📊 Dual-View Interactive Web Dashboard

The AutoSecAudit Web Dashboard (`http://localhost:5000`) features:
- **Dual-View Switcher**:
  - `[ 👔 Business / Threat Lens ]`: High-level executive threat matrix, risk grades, and business impact summaries.
  - `[ 💻 Technical Deep-Dive ]`: Raw scanner traces, request/response headers, CVSS scores, and CVE links.
- **Finding Modals**: Multi-framework code tabs (`Node.js`, `Python`, `Nginx`, `WAF JSON`), `[ 📋 Copy Code ]`, and `[ 📤 Copy Dev Ticket ]`.
- **Export Formats**: Interactive HTML, Executive ReportLab PDF summaries, JSON data, and WAF rule bundles.

---

## 🧪 Testing & Quality Assurance

AutoSecAudit includes a comprehensive automated test suite verifying all 19 scanner plugins, crawler logic, intelligence mapping, posture scoring, fix recipes, MCP JSON-RPC protocol, and CLI gating:

```bash
python run_tests.py
```

```
============================================================
                  TEST RESULTS SUMMARY
============================================================
Total Tests Executed : 111
Total Failures       : 0
Total Errors         : 0
Total Skipped        : 0
Execution Time       : 11.56 seconds
============================================================
SUCCESS: All tests passed successfully!
```

---

## 🤝 License

Distributed under the MIT License. See `LICENSE` for more information.
