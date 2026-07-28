# AutoSecAudit 2.0 🛡️

An intelligent, extensible, multi-plugin security auditing framework that scans web applications and APIs, aggregates findings across 14 security scanners, enriches vulnerabilities with external CVE intelligence, maps findings to OWASP Top 10, CWE, and PCI-DSS v4.0 compliance standards, performs differential delta analysis, and presents interactive HTML and PDF reports.

---

## 🌟 Key Features

- **Modular Plugin Architecture** – Includes 14 security scanner plugins:
  - **Infrastructure**: `NmapPlugin`, `NiktoPlugin`, `DirBruteScanner`
  - **Web Vulnerabilities**: `SQLiScanner`, `XSSScanner`, `CORSScanner`, `MisconfigScanner`
  - **API & Auth Auditing**: `APIAbuseScanner`, `AuthScanner`, `JWTScanner`
  - **Advanced Vectors**: `CommandInjectionScanner`, `SSRFScanner`, `PathTraversalScanner`, `SSTIScanner`
- **Intelligence Layer** – CVE NVD/CIRCL API enrichment, finding de-duplication correlator, and remediation fix guidance.
- **Multi-Compliance Mapping** – Auto-tags vulnerabilities with **OWASP Top 10 (2021)**, **CWE IDs**, and **PCI-DSS v4.0** requirements.
- **Enterprise CI/CD Gating (`--fail-on`)** – Break build pipelines automatically if scan findings equal or exceed severity thresholds (`critical`, `high`, `medium`, `low`).
- **Slack & Discord Webhook Alerts (`--webhook`)** – Instant notification dispatches upon scan completion.
- **OpenAPI / Swagger Spec Importer (`--openapi`)** – Parse local or remote `openapi.json` / `swagger.json` specs to automatically extract routes and parameters for scanning.
- **PDF & HTML Reporting** – Generates interactive HTML dashboards with live search, severity filters, detail modals, dark/light theme, and printable executive PDF summaries.
- **Real-Time Web UI** – Flask interface with Server-Sent Events (SSE) progress streaming, drag-and-drop OpenAPI upload, and historical scan tracking (`/history`).
- **Resilient Mock Mode** – Fallback execution mode for offline testing and fast CI/CD validation.

---

## 📁 Repository Architecture

```
AutoSecAudit/
├── main.py                     # CLI entry point (scan, plugins, server)
├── run_tests.py                # Unified test runner (80 passing tests)
├── config.py                   # Global configuration & environment settings
├── core/
│   ├── engine.py             # Multi-threaded scanner engine
│   ├── crawler.py            # Web endpoint & form crawler
│   ├── openapi.py            # OpenAPI / Swagger specification importer
│   ├── notifications.py      # Slack/Discord webhook alert dispatcher
│   ├── models.py             # Dataclasses (Finding, ScanResult, Report)
│   └── utils.py              # Target validation & helper functions
├── plugins/                    # 14 Scanner plugins
│   ├── base_plugin.py        # Abstract BaseScanner contract & baseline engine
│   ├── command_injection_plugin.py
│   ├── ssrf_plugin.py
│   ├── path_traversal_plugin.py
│   ├── ssti_plugin.py
│   ├── jwt_plugin.py
│   ├── sqli_plugin.py
│   ├── xss_plugin.py
│   ├── cors_plugin.py
│   ├── dirbuster_plugin.py
│   ├── misconfig_plugin.py
│   ├── api_abuse_plugin.py
│   ├── auth_plugin.py
│   ├── nikto_plugin.py
│   └── nmap_plugin.py
├── intelligence/               # Post-processing intelligence
│   ├── correlator.py         # Cross-tool finding deduplication
│   ├── enricher.py           # CVE CVSS enrichment via NVD/CIRCL
│   ├── compliance.py         # OWASP, CWE, & PCI-DSS v4.0 mapping
│   ├── delta.py              # Differential scan analysis
│   └── remediation.py        # Remediation fix recommendations
├── reports/                    # Report generation
│   ├── generator.py          # HTML & PDF generator
│   └── templates/            # Jinja2 templates (report.html)
├── ui/                         # Flask web application
│   ├── app.py                # Web server, SSE progress streaming, PDF downloads
│   └── templates/            # History dashboard (history.html)
└── .github/workflows/
    └── ci.yml                # GitHub Actions Continuous Integration
```

---

## 🚀 Quick Start

### 1. Local Python Setup

```bash
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit
pip install -r requirements.txt

# Run a CLI scan
python main.py scan http://localhost:3000

# Start the Web UI
python main.py server
# Open http://localhost:5000 in your browser
```

### 2. Docker & Local Benchmark Target (OWASP Juice Shop)

```bash
# Start Web UI, CLI worker, and local OWASP Juice Shop test target
docker-compose up -d

# Open Web UI at http://localhost:5000
# OWASP Juice Shop benchmark target runs at http://localhost:3000
```

---

## 🛠️ CLI Usage & Examples

```bash
# Basic scan
python main.py scan http://localhost:3000

# CI/CD Gating (Fails build exit code 1 if CRITICAL vulnerabilities exist)
python main.py scan http://localhost:3000 --fail-on critical

# Scan with OpenAPI / Swagger spec import
python main.py scan http://localhost:3000 --openapi ./swagger.json

# Send Slack/Discord webhook alerts on scan completion
python main.py scan http://localhost:3000 --webhook https://discord.com/api/webhooks/YOUR_HOOK

# Authenticated scanning with custom headers
python main.py scan http://localhost:3000 --headers "Authorization: Bearer my_token; X-API-Key: 12345"

# Delta comparison with previous report
python main.py scan http://localhost:3000 --previous data/reports/scan_20260728.json

# List all 14 active scanner plugins
python main.py plugins

# Run unified test suite
python run_tests.py
```

---

## 🧪 Testing & CI/CD

AutoSecAudit includes a unified test runner covering all 14 scanner plugins, crawler verification, intelligence mapping, SSE streaming, and enterprise CLI gating:

```bash
python run_tests.py
```

The repository includes a **GitHub Actions CI workflow** ([.github/workflows/ci.yml](file:///.github/workflows/ci.yml)) that automatically triggers `python run_tests.py` on every push or pull request.

---

## 📜 License

MIT License
