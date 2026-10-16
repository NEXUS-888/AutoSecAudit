# AutoSecAudit 2.0 🛡️

> **An Intelligent Security Auditing Framework, Multi-Attack Simulator & Autonomous AI Remediation Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Build](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](#-testing--quality-assurance)
[![MCP Ready](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple.svg)](#-model-context-protocol-mcp-server)
[![Tests: 400+ Passed](https://img.shields.io/badge/Tests-400%2B%20Passed-success.svg)](#-testing--quality-assurance)
[![Standards: OWASP Top 10 • CWE • PCI-DSS](https://img.shields.io/badge/Standards-OWASP%20%7C%20CWE%20%7C%20PCI--DSS-orange.svg)](#-standards--compliance-mapping)

---

## ❓ What Problem Does AutoSecAudit Solve?

### The Modern Security Tooling Dilemma
In modern software engineering, assessing a web application or API for vulnerabilities has traditionally suffered from four major roadblocks:

1. **Tool Fragmentation & Noise**: Running `nmap`, `nikto`, and disparate scripts generates cluttered logs with duplicate findings and high false positives.
2. **Overwhelming for Non-Technical Stakeholders**: Traditional scanners display raw CVE numbers, CVSS scores, and hexadecimal traces, leaving executives and product owners wondering: *"What is the actual business danger? What can an attacker actually do?"*
3. **No Direct Code Fixes**: Scanners identify what is broken but leave developers to figure out framework-specific patches, input sanitization, or WAF rules on their own.
4. **Disconnection from AI Development Workflows**: Modern developers write code in **Cursor**, **Claude Code**, or **VS Code**, but security scanners remain locked in isolated CLI terminals with no agentic bridge.

---

## 💡 The Solution: AutoSecAudit 2.0

**AutoSecAudit 2.0** bridges dynamic penetration testing and modern developer workflows into a unified Python platform:

```
                  ┌──────────────────────────────────────────────────────────┐
                  │                 TARGET (URL / IP / API)                  │
                  │         Live Web • REST / GraphQL API • Local Testbed    │
                  └─────────────────────────────┬────────────────────────────┘
                                                │
                                  ┌─────────────▼─────────────┐
                                  │   Target Safety Gate      │
                                  │  RFC1918 • Localhost Only │
                                  └─────────────┬─────────────┘
                                                │
                                  ┌─────────────▼─────────────┐
                                  │ Pre-Flight Liveness Probe │
                                  │ HTTP / TCP Port Reachable │
                                  └─────────────┬─────────────┘
                                                │
                                  ┌─────────────▼─────────────┐
                                  │  Web Crawler & JS Parser  │
                                  │ Forms • Links • JS Routes │
                                  └─────────────┬─────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │            Engine Orchestration (ThreadPool)         │
                     │  Baseline Calibration • Adaptive Politeness & Jitter│
                     │  Statistical Timing Verifier • Deep JSON Body Fuzzer │
                     └──────────────────────────┬──────────────────────────┘
                                                │
            ┌───────────────────────────────────┼───────────────────────────────────┐
            │                                   │                                   │
   ┌────────▼────────┐                 ┌────────▼────────┐                 ┌────────▼────────┐
   │ Web Injections  │                 │  API & Access   │                 │ Recon & Infra   │
   │ SQLi, XSS, CSRF,│                 │ BOLA/IDOR, Auth,│                 │ Nmap, Nikto, TLS│
   │ RCE, SSRF, SSTI,│                 │ JWT, CORS, API  │                 │ DirBrute (50+), │
   │ Path Traversal  │                 │ Abuse Scanners  │                 │ Secret Exposure │
   └────────┬────────┘                 └────────┬────────┘                 └────────┬────────┘
            │                                   │                                   │
            └───────────────────────────────────┼───────────────────────────────────┘
                                                │
                                  ┌─────────────▼─────────────┐
                                  │    Intelligence Engine    │
                                  │ Correlate • NVD / CIRCL   │
                                  │ OWASP • CWE • PCI-DSS v4  │
                                  │ Plain-English Real Danger │
                                  │ Multi-Framework Recipes   │
                                  │ Delta Differential Scan   │
                                  └─────────────┬─────────────┘
                                                │
            ┌───────────────────────────────────┼───────────────────────────────────┐
            │                                   │                                   │
   ┌────────▼────────┐                 ┌────────▼────────┐                 ┌────────▼────────┐
   │ Interactive UI  │                 │   MCP Server    │                 │ CI/CD & Reports │
   │ Real-time SSE   │                 │ Cursor & Claude │                 │ Build Gating    │
   │ Dual-View Lens  │                 │ Auto Code Fixes │                 │ JSON, WAF rules │
   │ Search & Modals │                 │ In-Editor Verif │                 │ ReportLab PDF   │
   └─────────────────┘                 └─────────────────┘                 └─────────────────┘
```

---

## ✨ Key Capabilities

### 1. 🔌 19 Dynamic Vulnerability Scanner Plugins
AutoSecAudit automatically discovers and executes 19 attack simulation scanner plugins:

- **Web Application Injections**:
  - `SQLiScanner`: Error-based, boolean-based, and statistical time-based blind SQL injection.
  - `XSSScanner`: Reflected and stored Cross-Site Scripting with context-aware payload injection.
  - `CSRFScanner`: Cross-Site Request Forgery, anti-CSRF token verification, and SameSite cookie flags.
  - `OpenRedirectScanner`: Unvalidated redirect parameters (`next`, `redirect`, `url`, `return`).
  - `MisconfigScanner`: Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) and cookie hygiene.
- **API & Access Control**:
  - `BOLAIdorScanner`: Broken Object-Level Authorization (IDOR) with numeric/UUID parameter manipulation.
  - `APIAbuseScanner`: Mass assignment, excessive data exposure, rate limiting, and HTTP verb tampering.
  - `AuthScanner`: Default credentials, weak password policies, and account enumeration.
  - `JWTScanner`: Alg=None bypass, weak HMAC secrets, and unverified signature acceptance.
  - `CORSScanner`: Insecure CORS origin reflections, wildcard origins, and credentials exposure.
- **Advanced Attack Vectors**:
  - `CommandInjectionScanner`: OS Remote Command Execution (RCE) via shell metacharacters and timing verification.
  - `SSRFScanner`: Server-Side Request Forgery against cloud metadata endpoints (`169.254.169.254`, loopback, internal subnets).
  - `PathTraversalScanner`: Local File Inclusion (LFI) and directory traversal (`../../../../etc/passwd`).
  - `SSTIScanner`: Server-Side Template Injection across Jinja2, Twig, and ERB syntax.
- **Infrastructure & Secrets**:
  - `SecretExposureScanner`: Leaked API keys, AWS tokens, private keys, and git traces in HTML comments and `.env`.
  - `SSLTLSScanner`: Weak TLS protocols, cipher suite validation, certificate expiry, and missing HSTS.
  - `DirBruteScanner`: Fast directory discovery against 50+ curated sensitive paths (`.git`, `.env`, `/admin`, backups).
  - `NiktoPlugin`: Web server misconfiguration and outdated software analysis.
  - `NmapPlugin`: Open port discovery and service identification.

---

### 2. 🎯 Selectable Scan Profiles
Tailor your security audit to specific contexts using predefined scan profiles:

- 🌐 **`full` (Full Spectrum DAST)**: Executes all 19 scanner plugins concurrently.
- 🛡️ **`owasp` (OWASP Top 10 Suite)**: Focuses on core injection, auth, CSRF, SSRF, and misconfigurations (11 plugins).
- ⚡ **`api` (API & Microservices Suite)**: Tailored for headless JSON REST APIs — BOLA/IDOR, JWT, CORS, rate limits (7 plugins).
- 🔍 **`recon` (Passive Reconnaissance)**: Non-intrusive scanning — SSL/TLS, security headers, directory discovery, port scans (6 plugins).

---

### 3. 🛡️ Precision Engine: Zero-Noise & False-Positive Elimination

AutoSecAudit includes five architectural mechanisms to guarantee reliable, high-signal results:

1. **Baseline Differential Verification**: Before asserting an injection finding, `BaseScanner` fetches a benign baseline response. Probes are only flagged if the malicious payload causes a confirmed behavioral deviation (status change or >20% response length delta).
2. **Statistical Timing Engine (`core/timing.py`)**: Eliminates false alarms in blind time-based attacks (`SLEEP(3)`, `sleep 3`). Calibrates the server's baseline latency mean and standard deviation, requiring two-phase verification before reporting high confidence.
3. **Adaptive Politeness & Rate-Limit Backoff (`core/politeness.py`)**: Applies randomized jitter between probes and automatically executes exponential backoff if the target responds with HTTP 429 or 503.
4. **Deep Recursive JSON Body Fuzzer (`core/fuzzer.py`)**: Recursively extracts leaf keys and mutates nested JSON objects without invalidating surrounding request schemas.
5. **JavaScript Route & Endpoint Extraction (`core/crawler.py`)**: Discovers hidden client-side API endpoints embedded in inline `<script>` tags and frontend bundles.

---

### 4. 🚨 Plain-English "Real Danger" & Executive Posture Engine

Automatically translates technical scanner findings into **4 Real-World Business Threat Categories**:

- 🚨 **Customer & Database Theft** (*SQLi, Directory Listing, `.git`/`.env` credential leaks*)
- 💳 **Account Hijacking & Auth Bypass** (*JWT weaknesses, brute-force, missing cookie flags*)
- 🌐 **Phishing, XSS & Brand Defacement** (*CORS wildcard, XSS, Clickjacking/CSP, Open Redirects*)
- 🛑 **Full Server Takeover & RCE** (*Remote command injection*)

Provides non-technical executive assessments:
- **Executive Security Posture Grade**: Letter grade (`A+` to `F`, score out of 100).
- **What is Broken**: Plain-English technical explanation.
- **What an Attacker Can Actually Do**: Real-world threat exploitation scenario.
- **Business Impact**: Direct financial, compliance, and reputational liabilities.
- **Estimated Fix Time**: Practical resolution timeline (e.g. `5-15 min`).

---

### 5. ⚡ Multi-Framework Drop-in Fix Recipes & Dev Tickets

- **Instant Code Patches**: Ready-to-paste code snippets generated for:
  - 🟢 **Node.js / Express** (Parameterized queries, Helmet.js, CSRF middleware, express-validator)
  - 🐍 **Python / Flask / FastAPI / Django** (SQLAlchemy ORM, Pydantic schemas, Talisman headers, Bleach sanitization)
  - ⚙️ **Nginx Hardening** (Header injection, rate limiting, dotfile blocking)
  - 🛡️ **Cloudflare / AWS WAF** (JSON virtual patching rules)
- **1-Click Dev Ticket Export**: Generates pre-formatted Markdown tickets ready for Jira, Linear, GitHub Issues, and Slack.

---

### 6. 📊 Dual-View Interactive Web Dashboard & Real-Time SSE

The AutoSecAudit Web Dashboard (`http://localhost:5000`) provides:
- **Real-Time Server-Sent Events (SSE)**: Live 14-stage non-decreasing progress streaming (`/scan/async`, `/scan/progress/<id>`).
- **Dual-View Lens**:
  - `[ 👔 Business / Threat Lens ]`: High-level executive threat matrix, risk grades, and business impact summaries.
  - `[ 💻 Technical Deep-Dive ]`: Raw scanner traces, request/response headers, CVSS scores, and CVE links.
- **Interactive Search & Severity Filtering**: Sticky filter bar with real-time text search, severity badges, and tool filtering.
- **Finding Detail Modals**: Accessible popups with keyboard navigation (Esc, Prev/Next), remediation tabs, and raw evidence.
- **Dark & Light Mode**: Persistent theme toggle with seamless CSS variable theming.
- **Scan History & Trends (`/history`)**: Historical scan repository with visual severity distributions.
- **Executive PDF Export**: Generates formal, publication-ready PDF reports via ReportLab with numbered canvas and confidentiality headers.

---

### 7. 🤖 Autonomous AI Remediation via Model Context Protocol (MCP)

AutoSecAudit includes an official standard **JSON-RPC 2.0 stdio MCP Server** (`mcp_server.py`) for **Cursor**, **Claude Code**, and **Antigravity**:

| MCP Tool | Description |
| :--- | :--- |
| `autosec_scan` | Trigger automated scans and receive structured summaries and threat grades. |
| `autosec_get_findings` | Retrieve findings enriched with Plain-English Danger assessments (`business`, `technical`, or `both`). |
| `autosec_get_fix_recipe` | Fetch drop-in code patches for AI agents to edit source code directly (`nodejs`, `python`, `nginx`, `waf`). |
| `autosec_verify_fix` | Run targeted re-verification to confirm if an AI code fix resolved the vulnerability. |
| `autosec_list_scanners` | List all 19 available dynamic scanner plugins and their descriptions. |

---

### 8. 🧪 Embedded Vulnerable Sandbox Testbed

Includes a local, self-contained vulnerable application (`testbed/app.py` or `python main.py testbed --port 8080`) containing intentional, safe test vectors (SQLi, XSS, CSRF, Open Redirect, BOLA, SSRF, SSTI, Secret Exposure) for safe local practice and verification.

---

### 9. 🔒 Target Safety & Ethical Scanning Boundaries

AutoSecAudit enforces built-in target boundary verification (`core/utils.py:is_target_allowed()`):
- **Permitted**: `localhost`, `127.0.0.1`, RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and authorized local practice targets (Juice Shop, DVWA, WebGoat).
- **Blocked**: Unauthorized public domains are rejected immediately to protect against accidental unauthorized scanning.

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
python main.py server --real
# Open http://localhost:5000 in your browser!
```

### Option B: Local Vulnerable Sandbox Testing

```bash
# 1. Launch the local vulnerable testbed app on port 8080
python main.py testbed --port 8080

# 2. In another terminal, run an active attack scan against the testbed
python main.py scan http://127.0.0.1:8080 --real --profile owasp
```

### Option C: Docker & Docker Compose

`docker-compose.yml` binds published ports to host loopback (`127.0.0.1:5000:5000` and `127.0.0.1:3000:3000`), runs AutoSecAudit as a non-root container user (`autosec`), and requires `AUTOSEC_ADMIN_PASSWORD` to be set explicitly before startup:

```bash
# Set the initial admin password and start AutoSecAudit Web UI (127.0.0.1:5000) + Juice Shop (127.0.0.1:3000)
AUTOSEC_ADMIN_PASSWORD="your-strong-admin-password" docker-compose up -d autosec

# View live logs
docker-compose logs -f autosec
```

---

## 🔐 First-Run & Dashboard Authentication

All Web Dashboard routes (`/`, `/scan`, `/scan/async`, `/scan/progress/<id>`, `/report/<id>`, `/history`, `/api/report/<id>`, `/api/reports`, `/api/stats`) require authentication (`/login`). Only `/login`, `/register`, `/health`, and static assets are accessible without an active session.

- **Initial Admin Password**: On first startup (when `users.db` has no users), AutoSecAudit creates the `admin` account using the `AUTOSEC_ADMIN_PASSWORD` environment variable if set. If `AUTOSEC_ADMIN_PASSWORD` is unset or empty, a random password is generated once via `secrets.token_urlsafe(16)` and printed to `stderr`. AutoSecAudit never uses a hardcoded default password.
- **Self-Registration**: User self-registration at `/register` is **disabled by default** (`AUTOSEC_ALLOW_REGISTRATION=false`). Set `AUTOSEC_ALLOW_REGISTRATION=true` to allow new users to register; self-registered accounts are always assigned the `developer` role.
- **Scan & Report Ownership**: Every scan job and saved report records the authenticated user's `owner_id`. Non-admin users can only view, export, or generate dev tickets for their own scans and reports, while `admin` users have full visibility across all reports.

---

## 🔑 Authenticated Target Scanning

AutoSecAudit can authenticate against a target web application before crawling and running attack plugins so authenticated routes and forms are covered:

```bash
# Pass target credentials via CLI flags (or set AUTOSEC_LOGIN_PASS in the environment)
export AUTOSEC_LOGIN_PASS="target-secret-password"
python main.py scan http://127.0.0.1:8080 --real \
  --login-user admin \
  --login-url /login/

# Or provide --login-pass explicitly on the command line:
python main.py scan http://127.0.0.1:8080 --real \
  --login-user admin \
  --login-pass "target-secret-password" \
  --login-url /login/
```

> **Windows Git Bash Note (`MSYS_NO_PATHCONV`)**: Git Bash (MSYS2) automatically rewrites leading-slash arguments like `--login-url /login/` into Windows filesystem paths (e.g. `C:/Program Files/Git/login/`). When running on Windows Git Bash, prefix the command with `MSYS_NO_PATHCONV=1` or double the leading slash (`//login/`):
> ```bash
> MSYS_NO_PATHCONV=1 python main.py scan http://127.0.0.1:8080 --real --login-user admin --login-url /login/
> ```

---

## ⚙️ Configuration Reference

All runtime behavior can be configured via `AUTOSEC_*` environment variables (defined in `config.py`, `core/`, `ui/`, `plugins/`, `main.py`, and `mcp_server.py`):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AUTOSEC_HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | Network interface address the Flask dashboard server binds to. |
| `AUTOSEC_DEBUG` | `false` | Enables Flask debug mode when set to `true` (disabled in production). |
| `AUTOSEC_LOG_LEVEL` | `INFO` | Logging verbosity level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |
| `AUTOSEC_MOCK_MODE` | `true` (`false` in Docker image) | Runs scanners in simulated mock mode when `true`; live HTTP probing when `false`. |
| `AUTOSEC_DATA_DIR` | `./data` | Base directory for SQLite databases (`users.db`), persisted secret key, and scan reports. |
| `AUTOSEC_SECRET_KEY` | Auto-generated in `<DATA_DIR>/.secret_key` | Flask session signing secret key (persisted across restarts with `0600` permissions). |
| `AUTOSEC_COOKIE_SECURE` | Auto-detected (`true` on HTTPS) | Controls the `Secure` attribute on session cookies (`true` / `false`). |
| `AUTOSEC_ADMIN_PASSWORD` | Generated via `secrets.token_urlsafe(16)` | Initial password for the seeded `admin` account on first database initialization. |
| `AUTOSEC_ALLOW_REGISTRATION` | `false` | Enables user self-registration at `/register` when set to `true`. |
| `AUTOSEC_LOGIN_PASS` | *(unset)* | Fallback password for authenticated target scanning when `--login-user` is used without `--login-pass`. |
| `AUTOSEC_HTTP_TIMEOUT` | `10` | Per-request connect/read timeout in seconds for scanner HTTP probes. |
| `AUTOSEC_SCAN_TIMEOUT` | `300` | Maximum overall wall-clock timeout in seconds for a single plugin execution. |
| `AUTOSEC_SCAN_DEADLINE_SECONDS` | `300` | Overall wall-clock deadline in seconds for the entire scan execution (range `30`–`3600`). |
| `AUTOSEC_THREAD_COUNT` | `4` | Number of concurrent worker threads used by the scan engine `ThreadPoolExecutor`. |
| `AUTOSEC_MAX_RESPONSE_BYTES` | `5242880` (5 MiB) | Maximum HTTP response body size read by `core/http_client.py` before truncation. |
| `AUTOSEC_MAX_REQUEST_SECONDS` | `30` | Hard wall-clock deadline in seconds for streaming an individual HTTP response. |
| `AUTOSEC_CRAWL_MAX_PAGES` | `100` | Maximum number of pages visited by `WebCrawler` per crawl session (range `1`–`500`). |
| `AUTOSEC_CRAWL_MAX_DEPTH` | `4` | Maximum link traversal depth for `WebCrawler` BFS discovery (range `1`–`8`). |
| `AUTOSEC_CRAWL_MAX_SECONDS` | `60` | Maximum wall-clock time in seconds for a `WebCrawler` session before stopping (range `5`–`600`). |
| `AUTOSEC_MAX_FORMS_PER_PLUGIN` | `20` | Maximum number of discovered forms an injection plugin will probe per scan (range `1`–`100`). |
| `AUTOSEC_MAX_FIELDS_PER_FORM` | `6` | Maximum number of fields probed per form, most promising first (range `1`–`30`). |
| `AUTOSEC_MAX_LOGIN_PROBE_REQUESTS` | `25` | Maximum number of candidate login probe requests sent per scan. |
| `AUTOSEC_MAX_CONCURRENT_SCANS` | `2` | Maximum number of simultaneous active dashboard background scans (`HTTP 429` when exceeded). |
| `AUTOSEC_SCAN_JOB_TTL` | `3600` | Time-to-live in seconds for completed/failed async scan jobs before eviction. |
| `AUTOSEC_NMAP_PATH` | `nmap` (or Windows Nmap path) | Path to the `nmap` executable used by `NmapPlugin`. |
| `AUTOSEC_NMAP_FULL_SCAN` | `false` | Enables `-sV -O --script vuln` full Nmap scanning when `true` (uses fast `-F` scan by default). |
| `AUTOSEC_NIKTO_PATH` | `nikto` | Path to the `nikto` executable used by `NiktoPlugin`. |
| `AUTOSEC_ENABLE_METADATA_PROBES` | `false` | Opt-in flag allowing `SSRFScanner` to probe cloud metadata endpoints (`169.254.169.254`, etc.). |

*Internal Scanner Probe Markers*: `CommandInjectionScanner` (`plugins/command_injection_plugin.py`) uses the benign verification tokens `AUTOSEC_RCE_TEST`, `AUTOSEC_42_RCE`, and `AUTOSEC_INERT_PROBE` to confirm OS command execution without destructive side effects.

---

## 🔌 Model Context Protocol (MCP) Server Setup

Connect AutoSecAudit directly to **Cursor**, **Claude Code**, or **Antigravity** to enable autonomous AI code repair:

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
2. **Review**: *"List the critical vulnerabilities in plain English using autosec_get_findings."*
3. **Fix**: *"Fetch the fix recipe for the SQL Injection finding and apply the patch to `routes/search.js`."*
4. **Verify**: *"Run autosec_verify_fix to confirm if the SQL Injection is resolved."*

---

## 💻 CLI Command Reference

### Interactive Console Menu
Running `main.py` with no arguments launches an interactive terminal dashboard:
```bash
python main.py
```
```
============================================================
    AutoSecAudit 2.0 — Interactive Security Console
============================================================
  [1] Start Web Dashboard Server (http://localhost:5000)
  [2] Run CLI Target Security Scan
  [3] List Discovered Scanner Plugins (19 Plugins)
  [4] Run Automated Verification Proof (verify_proof.py)
  [5] Run Full Test Suite (run_tests.py)
  [6] Exit
============================================================
```

### CLI Commands

```bash
# ── Basic Scan ────────────────────────────────────────────────────────────
python main.py scan http://localhost:3000

# ── Scan with Specific Profile (full | owasp | api | recon) ───────────────
python main.py scan http://localhost:3000 --profile owasp

# ── Live Active Scan (Sends real HTTP payloads) ──────────────────────────
python main.py scan http://localhost:3000 --real --profile api

# ── Authenticated Form Login Scan ─────────────────────────────────────────
python main.py scan http://localhost:3000 --real --login-user admin --login-pass secret --login-url /login

# ── CI/CD Build Gating (Fails build if severity exceeds threshold) ───────
python main.py scan http://localhost:3000 --fail-on high

# ── CI/CD SARIF and JUnit Outputs (GitHub Code Scanning & Test Runners) ───
# Exports SARIF 2.1.0 for GitHub Security tab and JUnit XML for test dashboards:
python main.py scan http://localhost:3000 --real --sarif autosec-report.sarif --junit autosec-junit.xml --fail-on high

# ── OpenAPI / Swagger Specification Import ──────────────────────────────
python main.py scan http://localhost:3000 --openapi ./swagger.json

# ── Slack / Discord Webhook Notifications ─────────────────────────────────
python main.py scan http://localhost:3000 --webhook https://discord.com/api/webhooks/YOUR_HOOK

# ── Authenticated Scanning with Custom Headers ───────────────────────────
python main.py scan http://localhost:3000 --headers "Authorization: Bearer my_token; X-API-Key: 12345"

# ── Delta Comparison with Previous Scan ─────────────────────────────────
python main.py scan http://localhost:3000 --previous data/reports/scan_20260831.json

# ── Pre-Flight Target Liveness Verification ──────────────────────────────
# By default, AutoSecAudit verifies that the target is online before scanning.
# To bypass reachability check for an offline mock demonstration or pipeline test:
python main.py scan http://localhost:3000 --mock --skip-reachability-check

# ── Launch Vulnerable Target Sandbox ─────────────────────────────────────
python main.py testbed --port 8080

# ── Start Web Dashboard ──────────────────────────────────────────────────
python main.py server --real
```

---

## 📋 Standards & Compliance Mapping

AutoSecAudit cross-references all discovered vulnerabilities against leading industry security baselines:
- **OWASP Top 10 (2021)**: Injection (A03), Broken Access Control (A01), Cryptographic Failures (A02), Security Misconfiguration (A05), Vulnerable Components (A06), SSRF (A10), etc.
- **CWE (Common Weakness Enumeration)**: CWE-89 (SQLi), CWE-79 (XSS), CWE-352 (CSRF), CWE-78 (OS Command Injection), CWE-22 (Path Traversal), CWE-200 (Information Disclosure), etc.
- **PCI-DSS v4.0**: Requirement 6.4 (protecting web applications against attacks), Requirement 8.3 (strong authentication), and Requirement 3.4 (protecting stored cardholder data).
- **NIST NVD / CIRCL CVE API**: Automated online enrichment attaching CVSS scores and CVE identifiers.

---

## 🧪 Testing & Quality Assurance

AutoSecAudit maintains an automated test suite covering all 19 plugins, the crawler, pre-flight target reachability, statistical timing, deep JSON fuzzing, rate limiter backoff, danger assessments, fix recipes, ReportLab PDF generation, and SSE streaming:

```bash
python run_tests.py
```

```
============================================================
                  TEST RESULTS SUMMARY
============================================================
Total Tests Executed : 427
Total Failures       : 0
Total Errors         : 0
Total Skipped        : 0
Execution Time       : 18.50 seconds
============================================================
SUCCESS: All tests passed successfully!
```

---

## 🤝 License

Distributed under the MIT License. See `LICENSE` for more information.
