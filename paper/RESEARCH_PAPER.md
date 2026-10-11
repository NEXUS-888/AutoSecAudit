# AutoSecAudit: An Extensible Multi-Scanner Orchestration Framework with Autonomous AI Remediation, Precision Fuzzing, and Delta Auditing in DevSecOps

**Authors:** Kodi Vishruth Aithal\textsuperscript{1}, Thilak N\textsuperscript{2}, Vinaya Kumar B\textsuperscript{3}, Vishal Gowda B\textsuperscript{4}, and Ms.~Ranjitha R\textsuperscript{5,*} (Faculty Mentor & Corresponding Author)  
**Affiliation:** Department of Computer Science and Engineering, Don Bosco Institute of Technology, Bangalore, Karnataka, India  
**Emails:** \textsuperscript{1}aithalvishruth@gmail.com, \textsuperscript{2}gowdathilakn@gmail.com, \textsuperscript{3}bvinaykumar70@gmail.com, \textsuperscript{4}vishalgb2005@gmail.com, \textsuperscript{5,*}ranjitha.r@dbit.co.in  
**Target Publication Format:** International Journal of Advanced Research in Computer and Communication Engineering (IJARCCE) / IEEE 2-Column Standard  

---

## Abstract
Continuous deployment workflows require continuous, automated security verification. However, engineering teams face significant friction when integrating traditional vulnerability assessment tools into fast Continuous Integration/Continuous Deployment (CI/CD) pipelines. Existing tools suffer from tool fragmentation, uncoordinated duplicate alerts, lack of actionable business risk context for non-technical stakeholders, absent automated code remediation recipes, and an inability to bridge dynamic findings into modern AI-assisted engineering environments.

This paper introduces **AutoSecAudit**, an extensible vulnerability auditing framework and autonomous remediation platform designed for modern DevSecOps pipelines. AutoSecAudit unifies:
1. **Automated Attack Surface Discovery**: Breadth-first web crawling, client-side JavaScript route regex extraction, OpenAPI 2.0/3.0 schema parsing, and pre-flight target reachability validation.
2. **High-Precision Multi-Scanner Orchestration**: Concurrent execution across **19 specialized attack scanner plugins** spanning web injections, API/access control, exploit vectors, and infrastructure reconnaissance. False alarms are eliminated through a multi-tiered precision engine featuring a **Statistical Timing Engine** (dual-baseline latency calibration to prevent network jitter false positives in blind time-based attacks), **Adaptive Politeness & Jitter Backoff** (HTTP 429/503 exponential backoff), and a **Deep Recursive JSON Body Fuzzer**.
3. **Post-Processing Intelligence & Executive Posture**: Compound-key deduplication, live CVSS/CVE enrichment via NIST NVD and CIRCL APIs, deterministic compliance taxonomy mapping across OWASP Top 10 (2021), MITRE CWE, and PCI-DSS v4.0, and a **Plain-English "Real Danger" Engine** that translates technical vulnerabilities into four business risk categories with executive posture letter grades ($A^+$ to $F$).
4. **Autonomous AI Remediation & DevSecOps Delivery**: Multi-framework drop-in code fix recipes (Node.js/Express, Python/FastAPI/Django, Nginx, WAF rules), 1-click Markdown tickets (Jira, Linear, GitHub), set-theoretic delta differential regression auditing across software builds, and a standard **Model Context Protocol (MCP)** JSON-RPC 2.0 server enabling AI coding agents (Cursor, Claude Code, Antigravity) to scan targets, fetch findings, generate source code fixes, and perform targeted re-verification.

We evaluate AutoSecAudit across an expanded suite of 165 automated unit and integration tests, as well as dynamic execution against the OWASP Juice Shop benchmark. Empirical results demonstrate that bounded multi-threaded plugin execution ($k=8$) yields a 64.8% decrease in scan latency ($2.84\times$ speedup) over sequential auditing. The intelligence layer consolidates raw tool alerts with a 38.2% reduction in alert noise at 97.9% precision and 88.5% recall, while the delta analyzer tracks vulnerability lifecycles across build transitions with 100% classification fidelity.

**Keywords:** Vulnerability Assessment, DevSecOps, Scanner Orchestration, Model Context Protocol (MCP), AI Remediation, Statistical Timing Verification, Compliance Mapping, Delta Auditing, Web Security, API Security.

---

## 1. Introduction
Modern web applications and REST APIs represent heterogeneous software stacks that evolve rapidly under continuous delivery models. Ensuring software security within fast release cycles demands "shift-left" testing, where dynamic security analysis is integrated directly into automated build steps.

However, incorporating Dynamic Application Security Testing (DAST) into continuous integration and continuous deployment (CI/CD) pipelines routinely frustrates software engineering organizations. Empirical studies by Johnson et al. and Bau et al. show that developers frequently ignore or disable automated security scanners when reports are noisy, full of duplicates, or disconnected from practical bug fixes. In production environments, this breakdown stems from four recurring dilemmas:

1. **Heterogeneous Tool Fragmentation and Format Sprawl**: Identifying vulnerabilities across network services, web application endpoints, and API contracts requires orchestrating distinct utilities (such as port scanners, server misconfiguration checkers, and injection analyzers). Each tool outputs disparate, unstandardized formats (XML, raw text streams, non-uniform JSON), forcing engineering teams to write and maintain brittle glue scripts.
2. **Alert Fatigue from Redundant Findings**: Independent scanners frequently identify overlapping symptoms on the same URI and parameter. In the absence of cross-tool correlation, developers receive duplicate alerts for a single root cause, drowning out critical flaws.
3. **The Communication Gap with Non-Technical Stakeholders**: Traditional scanners display raw CVE numbers, CVSS vectors, and hexadecimal traces, leaving executives and product owners unable to answer: *"What is the actual business danger? What can an attacker actually do?"*
4. **No Direct Code Fixes & AI Workflow Disconnection**: Traditional scanners identify what is broken but leave developers to write framework-specific patches, input validation, or WAF rules from scratch. Furthermore, while modern engineers increasingly write and refactor code using AI-assisted environments (Cursor, Claude Code, Antigravity), existing scanners remain trapped in legacy CLI terminals with no agentic integration.
5. **Stateless Scans Lacking Regression Awareness**: Traditional scanners evaluate targets in isolation without tracking historical state. Consequently, engineering teams cannot distinguish newly introduced vulnerabilities from pre-existing technical debt or verify whether a committed patch successfully resolved an open issue.

To address these challenges, we present **AutoSecAudit**, an extensible multi-scanner security orchestration framework and autonomous AI remediation platform. AutoSecAudit unifies automated attack surface reconnaissance, concurrent execution of 19 specialized scanner plugins, statistical false-positive elimination, plain-English business risk translation, multi-framework code fix generation, set-theoretic delta regression diffing, and native Model Context Protocol (MCP) tool integration into a cohesive DevSecOps engine.

---

## 2. Related Work & Comparative Analysis
Security testing tools generally fit into four architectural paradigms: standalone point scanners, interactive DAST proxies, fast template matchers, and centralized vulnerability management portals. Table I provides a comprehensive capability comparison between these systems and AutoSecAudit.

### 2.1 Point Scanners & Specialized Utilities
Network scanners like Nmap handle port discovery and service fingerprinting, while web server checkers like Nikto scan for server misconfigurations and outdated defaults. Template-driven scanners like Nuclei run fast YAML pattern matches over HTTP. However, these utilities execute as standalone binaries and lack built-in multi-plugin correlation, automated compliance tagging, historical regression diffing, and autonomous AI remediation interfaces.

### 2.2 Stateful DAST Proxies & API Fuzzers
State-aware scanners, explored by Doupé et al., track application navigation states to uncover deeper injection points. In API fuzzing, Atlidakis et al. demonstrated with RESTler that effective testing requires parsing OpenAPI structures. Comprehensive proxies like OWASP ZAP and PortSwigger Burp Suite provide thorough coverage, but their heavy resource consumption, complex daemon lifecycles, and extended scan runtimes make them difficult to run on fast pull-request merge checks.

### 2.3 Vulnerability Management Aggregation Hubs
Platforms like OWASP DefectDojo aggregate findings from third-party scanners into a central repository. However, DefectDojo functions primarily as a passive ingestion platform; it still requires teams to write external pipeline jobs to run individual tools, parse diverse log formats, and push results over REST APIs.

### 2.4 Autonomous AI Remediation & Agentic Interfaces
Recent advances in AI-assisted software engineering have produced agentic developer tools (such as Cursor, Claude Code, and Antigravity). However, bridging external dynamic security scanners with AI agents has been hindered by the lack of standardized protocol integration. AutoSecAudit addresses this gap by implementing the standard JSON-RPC 2.0 Model Context Protocol (MCP), enabling AI agents to programmatically initiate scans, inspect enriched findings, obtain ready-to-paste code patches, and verify remediation directly in the developer's workspace.

### TABLE I: Architectural Comparison Across Security Testing Paradigms

| Dimension / Capability | Point Scanners (Nmap / Nikto) | Interactive Proxies (OWASP ZAP) | Fast Matchers (Nuclei) | Aggregation Hubs (DefectDojo) | **AutoSecAudit (Ours)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scan Orchestration Scope** | Single Layer (Host / Web) | Deep Stateful Web Application | Template Matching | Passive Ingestion Hub | **Unified Multi-Vector (Host + Web + API)** |
| **Concurrency Model** | Process / Thread | Engine Threads | Goroutines | Non-scanning Hub | **ThreadPool ($k=8$) with Dynamic Profiles** |
| **Automated Surface Discovery**| None | Crawler + Spider | None (Input URLs) | None | **BFS Crawler + JS Regex + OpenAPI 2.0/3.0** |
| **Active Scanner Plugins** | Fixed / Single Purpose | Modular Add-ons | YAML Templates | None | **19 Built-in Attack Simulation Plugins** |
| **False-Positive Elimination** | None | Heuristic Filters | Pattern Checks | Manual Triage | **Statistical Timing Engine + Baseline Delta** |
| **JSON API Deep Fuzzing** | None | Partial / Plugin | Header / Query | None | **Deep Recursive JSON Body Mutation** |
| **Threat Intelligence Feeds** | None / Manual | Add-on Scripts | Static Tags | Rule Matching | **Live NIST NVD & CIRCL API Lookups** |
| **Compliance Taxonomies** | None | Alert Tags | User Templates | Database Tags | **Deterministic OWASP, CWE, PCI-DSS v4.0** |
| **Executive Danger Translation**| None (Raw Logs) | Technical CVSS | Raw Match Logs | CVSS Charts | **Plain-English Danger Engine (Grades $A^+$ to $F$)** |
| **Automated Code Fix Recipes** | None | Generic Text | Remediation Hints | Generic Advisory | **Drop-in Recipes (Node, Python, Nginx, WAF)** |
| **AI Agent Interface (MCP)** | None | None | None | REST API | **Native JSON-RPC 2.0 MCP Server** |
| **Historical Delta Auditing** | None | Session-bound | None | DB Queries | **Native Set-Theoretic JSON Diffing** |
| **CI/CD Policy Gating** | Exit 0 regardless | Custom Scripts | Exit Codes | Async Webhooks | **Native `--fail-on` Policy Exit Code** |
| **Deployment Footprint** | CLI Binaries | Java Daemon | Go Binary | Django + PostgreSQL | **Lightweight Python & Docker** |

---

## 3. System Architecture & Methodology
AutoSecAudit is structured into four decoupled subsystems (Fig. 1):
1. **Input Ingestion, Surface Discovery & Pre-flight Validation** (`WebCrawler`, `OpenAPIImporter`, `Authenticator`, Target Safety Gate, Pre-Flight Liveness Probe)
2. **Concurrent Multi-Scanner Engine & Precision Subsystem** (`Engine`, `BaseScanner`, 19 specialized attack plugins, `TimingEngine`, `PolitenessEngine`, `JSONFuzzer`)
3. **Post-Processing Intelligence Layer** (`Correlator`, `Enricher`, `ComplianceMapper`, `DangerEngine`, `RecipeEngine`, `DeltaAnalyzer`)
4. **Autonomous AI Remediation & DevSecOps Delivery** (`MCPServer`, CI/CD Gating, SSE Dashboard, PDF Generator)

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
                    │  Statistical Timing Verifier • Deep JSON Body Fuzzer│
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
*Fig. 1: AutoSecAudit System Architecture.*

### 3.1 Attack Surface Discovery & Pre-flight Validation
Given a hostname, IP address, or URL, the discovery subsystem seeds an endpoint pool $\mathcal{E}$ before triggering active scans:

1. **Target Safety Gate**: Validates the target against safety boundaries (`core/utils.py`). Targets restricted to `localhost`, `127.0.0.1`, RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or explicitly authorized test environments (OWASP Juice Shop, WebGoat). Unauthorized public IP addresses are blocked automatically.
2. **Pre-Flight Liveness Probe**: Executes pre-flight HTTP and TCP reachability tests before initializing worker threads, preventing dead-target pipeline stalls.
3. **Breadth-First Web Crawler (`WebCrawler`)**: Recursively traverses HTML endpoints starting from the root URL up to a depth limit $D_{\max}$. Parses HTML responses to isolate form structures (`<form action method>`), form input fields, query-string parameters, and hyperlinks.
4. **Client-Side JavaScript Route Extraction**: Parses inline `<script>` tags and referenced `.js` files using specialized regular expressions to uncover hidden client-side REST API endpoints (e.g., `/api/v1/...`, `/rest/...`) that lack HTML hyperlinks.
5. **OpenAPI / Swagger Ingestion (`OpenAPIImporter`)**: For REST APIs, automatically ingests OpenAPI 2.0 and 3.0 JSON/YAML specifications, extracting HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`), URL path parameters, and request payload schemas.
6. **Automated Multi-Strategy Authenticator (`Authenticator`)**: Detects login forms, injects authentication credentials, captures session cookies and JWT Bearer tokens, and injects session headers into the scanner thread pool.

```
Algorithm 1: Attack Surface Discovery, JS Parsing, and Endpoint Seeding
---------------------------------------------------------------------------------
Input: Target URL u0, Max Depth D_max, OpenAPI Path Omega, Auth Credentials A
Output: Discovered Parameterized Endpoint Pool E
1: If not IsTargetAllowed(u0) or not CheckLiveness(u0):
2:    Abort("Target rejected by safety gate or unreachable")
3: Session S = InitializeSession()
4: If A is provided:
5:    S = AutoAuthenticate(u0, A)
6: Initialize FIFO queue Q = {(u0, 0)}, Visited Set V = {}, E = {}
7: If Omega is provided:
8:    S_api = ParseOpenAPISpec(Omega)
9:    E = E U S_api
10: While Q is not empty:
11:    (u, d) = Dequeue(Q)
12:    If u in V or d > D_max: Continue
13:    V = V U {u}
14:    Response R = S.GET(u)
15:    Forms F = ExtractForms(R.body)
16:    E = E U Forms
17:    JS_Routes J = ExtractJSRoutes(R.body)
18:    E = E U J
19:    Links L = ExtractHyperlinks(R.body)
20:    For each link l in L matching target host:
21:       If HasQueryParams(l): E = E U {ParamEndpoint(l)}
22:       Enqueue (l, d+1) into Q
23: Return E
```

### 3.2 Core Concurrency Engine & 19 Scanner Plugins
Each scanner module extends the abstract `BaseScanner` interface. Standardized findings use the tuple model:
$$\mathcal{F} = \langle \text{id}, \text{title}, \text{severity}, \text{host}, \text{port}, \text{endpoint}, \text{evidence}, \mathcal{C}, \mathcal{M} \rangle$$
where $\mathcal{C} \in \{\text{Low}, \text{Medium}, \text{High}\}$ reflects baseline differential confidence and $\mathcal{M}$ contains compliance and remediation metadata.

AutoSecAudit organizes **19 specialized scanner plugins** across four operational domains:
1. **Web Application Injections**:
   - `SQLiScanner`: Error-based, boolean-based, and statistical time-based blind SQL injection.
   - `XSSScanner`: Reflected and stored Cross-Site Scripting with context-aware payload injection.
   - `CSRFScanner`: Cross-Site Request Forgery, anti-CSRF token verification, and SameSite cookie hygiene.
   - `OpenRedirectScanner`: Unvalidated redirect parameters (`next`, `redirect`, `url`, `return`).
   - `MisconfigScanner`: Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) and cookie attributes.
2. **API & Access Control**:
   - `BOLAIdorScanner`: Broken Object-Level Authorization (IDOR) with numeric and UUID parameter manipulation.
   - `APIAbuseScanner`: Mass assignment, excessive data exposure, rate limiting, and HTTP verb tampering.
   - `AuthScanner`: Default credentials, weak password policies, and account enumeration.
   - `JWTScanner`: Alg=None bypass, weak HMAC secrets, and unverified signature acceptance.
   - `CORSScanner`: Insecure CORS origin reflections, wildcard origins, and credentials exposure.
3. **Advanced Exploit Vectors**:
   - `CommandInjectionScanner`: OS Remote Command Execution (RCE) via shell metacharacters and timing verification.
   - `SSRFScanner`: Server-Side Request Forgery against cloud metadata endpoints (`169.254.169.254`, loopback, internal subnets).
   - `PathTraversalScanner`: Local File Inclusion (LFI) and directory traversal (`../../../../etc/passwd`).
   - `SSTIScanner`: Server-Side Template Injection across Jinja2, Twig, and ERB syntax.
4. **Reconnaissance & Infrastructure**:
   - `SecretExposureScanner`: Leaked API keys, AWS tokens, private keys, and git traces in HTML comments and `.env`.
   - `SSLTLSScanner`: Weak TLS protocols, cipher suite validation, certificate expiry, and missing HSTS.
   - `DirBruteScanner`: Fast directory discovery against 50+ curated sensitive paths (`.git`, `.env`, `/admin`, backups).
   - `NiktoPlugin`: Web server misconfiguration and outdated software analysis.
   - `NmapPlugin`: Open port discovery and service identification.

#### Dynamic Scan Profiles
The engine supports selectable scan profiles to tailor execution to target constraints:
- **`full` (Full Spectrum DAST)**: Executes all 19 scanner plugins concurrently.
- **`owasp` (OWASP Top 10 Suite)**: Focuses on core injection, auth, CSRF, SSRF, and misconfigurations (11 plugins).
- **`api` (API & Microservices Suite)**: Tailored for headless JSON REST APIs — BOLA/IDOR, JWT, CORS, rate limits (7 plugins).
- **`recon` (Passive Reconnaissance)**: Non-intrusive scanning — SSL/TLS, security headers, directory discovery, port scans (6 plugins).

#### Precision Engine: False-Positive Elimination Architecture
To guarantee high-signal results in automated pipelines, AutoSecAudit incorporates five precision mechanisms:
1. **Differential Baseline Verification**: Before asserting an injection finding, `BaseScanner` fetches a benign baseline response. Probes are only flagged if the malicious payload causes a confirmed behavioral deviation (HTTP status change or $>20\%$ response body length delta).
2. **Statistical Timing Engine (`core/timing.py`)**: Eliminates false positives in blind time-based attacks (`SLEEP(3)`, `sleep 3`). Network latency variance frequently mimics time-based injection. The engine measures baseline round-trip latency across $m$ benign requests to compute mean $\mu_{\text{base}}$ and standard deviation $\sigma_{\text{base}}$. A time-based payload introducing sleep duration $\tau$ is only confirmed if:
   $$T_{\text{probe}} \ge \mu_{\text{base}} + 3\sigma_{\text{base}} + \alpha \tau \quad (\alpha \ge 0.8)$$
   and successfully passes a second-phase verification probe.
3. **Adaptive Politeness & Jitter Backoff (`core/politeness.py`)**: Applies randomized inter-request delay (jitter) and automatically triggers exponential backoff if the target responds with HTTP 429 (Too Many Requests) or HTTP 503 (Service Unavailable).
4. **Deep Recursive JSON Body Fuzzer (`core/fuzzer.py`)**: Recursively traverses nested JSON request payloads, identifying leaf keys and injecting attack payloads without corrupting surrounding schema types or JSON syntax.

### 3.3 Post-Processing Intelligence Layer
Following raw plugin execution, the intelligence layer processes the finding set through six deterministic steps (Algorithm 2):

```
Algorithm 2: Post-Processing Intelligence Correlation and Delta Auditing
---------------------------------------------------------------------------------
Input: Raw Finding Set F_raw, Historical Baseline Report S_{t-1}
Output: Correlated Enriched Report S_t, Delta Partition Delta
1: Group map G = {}
2: For each finding f in F_raw:
3:    k = <f.host, f.port, f.endpoint, f.cwe_id>
4:    G[k] = G[k] U {f}
5: Consolidated Set S_t = {}
6: For each group in G:
7:    f_p = MergeFindings(group)
8:    If f_p.cve_id:
9:       f_p.cvss = QueryNVD_CIRCL(f_p.cve_id)
10:   f_p.owasp, f_p.pci_dss = ComplianceMapper(f_p)
11:   f_p.danger = EvaluateRealDanger(f_p)
12:   f_p.recipes = GenerateFixRecipes(f_p)
13:   S_t = S_t U {f_p}
14: If S_{t-1} is provided:
15:   Delta_NEW = { f in S_t | Hash(f) not in Hash(S_{t-1}) }
16:   Delta_FIXED = { f in S_{t-1} | Hash(f) not in Hash(S_t) }
17:   Delta_UNCHANGED = { f in S_t | Hash(f) in Hash(S_{t-1}) }
18: Return S_t, <Delta_NEW, Delta_FIXED, Delta_UNCHANGED>
```

#### Heuristic Deduplication & Correlation
To combat alert fatigue, raw findings are grouped by compound key:
$$\mathcal{K} = \langle \text{host}, \text{port}, \text{endpoint}, \text{cwe\_id} \rangle$$
Multiple alerts sharing $\mathcal{K}$ are consolidated into a single parent finding with merged evidence traces.

#### Threat Intelligence Enrichment & Compliance Mapping
Findings are enriched via live REST calls to the NIST National Vulnerability Database (NVD) and CIRCL CVE endpoints, attaching CVSS v3.1 base scores and vulnerability vectors. Findings are mapped deterministically to OWASP Top 10 (2021), MITRE CWE, and PCI-DSS v4.0 regulatory mandates.

#### Plain-English "Real Danger" & Executive Posture Engine
To bridge the gap between technical metrics and executive comprehension, the `DangerEngine` maps findings into four Real-World Business Threat Categories:
1. 🚨 **Customer & Database Theft** (*SQLi, Directory Listing, Credential Leaks*)
2. 💳 **Account Hijacking & Auth Bypass** (*JWT Flaws, Brute-Force, Missing Cookie Flags*)
3. 🌐 **Phishing, XSS & Brand Defacement** (*CORS Wildcard, XSS, Clickjacking/CSP, Open Redirects*)
4. 🛑 **Full Server Takeover & RCE** (*Remote Command Injection, File Inclusion*)

The engine calculates an **Executive Security Posture Grade** ($A^+$ to $F$) based on a normalized risk penalty score:
$$\text{Score} = 100 - \sum_{f \in S_t} w_{\text{severity}}(f)$$
and outputs plain-English explanations answering: (1) *What is Broken*, (2) *What an Attacker Can Actually Do*, (3) *Business Impact*, and (4) *Estimated Fix Time*.

#### Multi-Framework Drop-in Fix Recipes & Dev Tickets
The `RecipeEngine` automatically generates framework-specific code snippets to accelerate remediation:
- **Node.js / Express**: Parameterized queries, Helmet.js headers, CSRF middleware, express-validator schemas.
- **Python / FastAPI / Flask / Django**: SQLAlchemy ORM bindings, Pydantic input models, Talisman security headers, Bleach sanitization.
- **Nginx Hardening**: Security header directives, rate-limiting blocks, dotfile access denial.
- **WAF Virtual Patching**: Cloudflare and AWS WAF JSON virtual patching rules.
- **1-Click Dev Tickets**: Markdown-formatted issue tickets pre-populated for Jira, Linear, GitHub Issues, and Slack.

#### Set-Theoretic Delta Differential Auditing
To track security regressions across continuous builds, the `DeltaAnalyzer` computes a cryptographic identity hash $\mathcal{H}(f)$ over each finding. By comparing current scan $S_t$ against historical baseline $S_{t-1}$, findings are partitioned into three disjoint sets:
$$\Delta_{\text{NEW}} = \{\, f \in S_t \mid \mathcal{H}(f) \notin \mathcal{H}(S_{t-1}) \,\}$$
$$\Delta_{\text{FIXED}} = \{\, f \in S_{t-1} \mid \mathcal{H}(f) \notin \mathcal{H}(S_t) \,\}$$
$$\Delta_{\text{UNCHANGED}} = \{\, f \in S_t \mid \mathcal{H}(f) \in \mathcal{H}(S_{t-1}) \,\}$$

### 3.4 Autonomous AI Remediation via Model Context Protocol (MCP)
AutoSecAudit includes a standard JSON-RPC 2.0 stdio MCP Server (`mcp_server.py`), bridging DAST scanning directly into AI-assisted development environments (Cursor, Claude Code, Antigravity). The MCP server exposes five specialized security tools:

### TABLE II: AutoSecAudit MCP Tools for Autonomous AI Remediation

| MCP Tool Name | Arguments | Description & AI Capability |
| :--- | :--- | :--- |
| `autosec_scan` | `target_url`, `profile`, `crawl` | Initiates dynamic security scan; returns executive threat summary, posture grade, and finding counts. |
| `autosec_get_findings` | `scan_id`, `severity`, `lens` | Retrieves enriched findings with Plain-English Danger assessments and raw technical evidence. |
| `autosec_get_fix_recipe`| `finding_id`, `framework` | Returns drop-in code fix patches (`nodejs`, `python`, `nginx`, `waf`) for automated file editing. |
| `autosec_verify_fix` | `target_url`, `scanner_name`, `param` | Triggers targeted single-scanner re-verification to confirm whether an AI code fix resolved the vulnerability. |
| `autosec_list_scanners`| none | Lists all 19 dynamic scanner plugins, supported attack types, and description metadata. |

Through these tools, an AI coding assistant can run an automated scan upon build failure, inspect the exact vulnerability, apply the corresponding fix recipe directly to the source codebase, and run `autosec_verify_fix` to confirm remediation without leaving the development environment.

---

## 4. Experimental Evaluation & Results
Our evaluation addresses four central research questions:
- **RQ1 (Latency & Concurrency)**: How effectively does bounded multi-threaded plugin execution reduce overall scan time?
- **RQ2 (Detection Quality & Noise Reduction)**: What detection precision, recall, and alert reduction are achieved against benchmark targets across the 19 scanner plugins?
- **RQ3 (Delta Regression Fidelity)**: Does set-theoretic delta diffing reliably classify vulnerability lifecycles across continuous software builds?
- **RQ4 (System Reliability & Test Coverage)**: How does the framework maintain stability across unit and integration testing?

### 4.1 Concurrency & Execution Latency (RQ1)
We evaluated scan execution latency across worker thread counts ($k \in \{1, 2, 4, 8, 16\}$) on an 8-core host (16 GB RAM) auditing the OWASP Juice Shop benchmark. As presented in Table III, increasing concurrency from sequential execution ($k=1$) to $k=8$ reduced scan latency from 184.2 s to 64.8 s—representing a **64.8% reduction in execution time** ($2.84\times$ speedup). Beyond $k=8$, latency stabilized due to network socket serialization and target HTTP connection limits.

### TABLE III: Audit Latency and Speedup Across Concurrency Configurations

| Worker Threads ($k$) | Scan Latency (s) | Relative Speedup | Host CPU Utilization (%) |
| :---: | :---: | :---: | :---: |
| 1 (Sequential) | 184.2 s | $1.00\times$ | 14.2% |
| 2 | 102.5 s | $1.80\times$ | 27.8% |
| 4 | 71.4 s | $2.58\times$ | 51.3% |
| **8 (Optimal)** | **64.8 s** | **$2.84\times$** | **78.4%** |
| 16 | 66.1 s | $2.79\times$ | 82.1% |

### 4.2 Detection Performance & Noise Reduction (RQ2)
To evaluate detection accuracy, we audited the benchmark target and verified findings against ground-truth challenge specifications. Table IV details the results across all 19 plugins grouped into major vulnerability classifications.

### TABLE IV: Vulnerability Detection and Correlation Across 19 Scanner Plugins

| Vulnerability Classification (Active Plugins) | True Positives (TP) | False Positives (FP) | Raw Tool Alerts | Correlated Findings |
| :--- | :---: | :---: | :---: | :---: |
| **Web Injections** (`SQLi`, `CmdInj`, `SSTI`, `OpenRedirect`) | 8 | 0 | 14 | 8 |
| **Cross-Site Scripting** (`XSSScanner`, `CSRFScanner`) | 12 | 1 | 19 | 13 |
| **Misconfiguration & Recon** (`Misconfig`, `DirBrute`, `Nikto`, `Nmap`, `SSLTLS`, `SecretExp`) | 15 | 0 | 26 | 15 |
| **Access Control & Traversal** (`BOLAIdor`, `Auth`, `PathTrav`, `SSRF`) | 6 | 0 | 9 | 6 |
| **API Abuse & Tokens** (`APIAbuse`, `JWT`, `CORS`) | 5 | 0 | 8 | 5 |
| **Total / Summary** | **46** | **1** | **76** | **47 (-38.2% Noise)** |

Across 76 raw tool alerts, the intelligence layer consolidated findings into 47 distinct issues ($46\,\text{TP} + 1\,\text{FP}$), achieving a **38.2% reduction in duplicate alert volume**. Evaluated against 52 verified dynamic challenge vulnerabilities in benchmark scope, AutoSecAudit achieved **97.9% precision** ($46/47$), **88.5% recall** ($46/52$), and an **$F_1$-score of 92.9%**. The single false positive was retained for human verification rather than silently suppressed.

### 4.3 Delta Regression Tracking Fidelity (RQ3)
We evaluated regression tracking across a three-phase synthetic release sequence:
- **Build v1.0 (Baseline)**: Initial scan identified 47 correlated vulnerabilities.
- **Build v1.1 (Patch & New Flaws)**: 10 misconfigurations were patched and 3 new API access-control flaws were introduced. The delta analyzer correctly reported $3\,\Delta_{\text{NEW}}$, $10\,\Delta_{\text{FIXED}}$, and $37\,\Delta_{\text{UNCHANGED}}$ issues ($47 - 10 + 3 = 40$ active issues).
- **Build v1.2 (Hardened Release)**: 14 vulnerabilities (8 injection flaws + 6 access control/traversal flaws) were resolved. The delta analyzer classified $0\,\Delta_{\text{NEW}}$, $14\,\Delta_{\text{FIXED}}$, and $26\,\Delta_{\text{UNCHANGED}}$ issues ($40 - 14 = 26$ active issues).

Across all transitions, the delta engine achieved **100% classification fidelity** against ground-truth commit diffs.

### 4.4 System Reliability & Test Suite Coverage (RQ4)
AutoSecAudit is validated through an extensive test suite expanded to **165 automated unit and integration tests** (164 passed, 1 environment re-init). The test suite exercises:
- All 19 dynamic attack scanner plugins.
- The Statistical Timing Engine and dual-baseline calibration.
- Deep recursive JSON fuzzing and adaptive politeness backoff.
- The Plain-English Danger Engine and multi-framework code fix recipes.
- The Model Context Protocol (MCP) server tools.
- Set-theoretic delta regression diffing and CI/CD exit-code gating.

---

## 5. Discussion & Deployment Considerations
Practical deployment across production CI/CD workflows introduces several engineering considerations:
1. **Dynamic Client-Side Single Page Applications (SPAs)**: The built-in crawler parses static DOM structures and employs regex parsing for client-side JavaScript routes. For heavy JavaScript applications requiring deep client-side state execution, pairing the crawler with headless browser drivers (e.g., Playwright) provides expanded endpoint discovery.
2. **Offline & Air-Gapped Deployments**: In air-gapped environments where outbound network access to the NIST NVD or CIRCL APIs is restricted, AutoSecAudit seamlessly falls back to an embedded offline CVE/CWE dictionary to prevent pipeline timeouts.
3. **Enterprise Authentication**: While the built-in authenticator handles standard HTML form logins, session cookies, and JWT Bearer tokens, complex enterprise authentication flows (e.g., SAML 2.0, mTLS) require pre-authenticated session tokens passed via environment configuration.

---

## 6. Conclusion
AutoSecAudit provides an extensible, low-latency vulnerability auditing framework and autonomous AI remediation platform tailored for modern DevSecOps pipelines. By orchestrating concurrent execution across 19 specialized scanner plugins, the system reduces scan latency by 64.8% ($2.84\times$ speedup) over sequential auditing. The intelligence layer eliminates 38.2% of duplicate alerts, translates findings into plain-English business risk categories with executive posture grades, generates drop-in multi-framework code patches, and tracks vulnerability regressions across builds with 100% classification fidelity. Furthermore, through native Model Context Protocol (MCP) integration, AutoSecAudit bridges dynamic security auditing directly into AI coding workflows, closing the gap between vulnerability detection and automated source code remediation.

---

## References
1. G. F. Lyon, *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Vulnerability Scanning*, Insecure.Com LLC, 2009.
2. C. Sullo and D. Lodge, "Nikto Web Server Scanner," Open Source Security Tool, 2023. [Online]. Available: https://cirt.net/Nikto2
3. ProjectDiscovery, "Nuclei: Fast and Customizable Vulnerability Scanner Based on Simple YAML DSL," 2024. [Online]. Available: https://github.com/projectdiscovery/nuclei
4. OWASP Foundation, "OWASP Zed Attack Proxy (ZAP)," 2024. [Online]. Available: https://www.zaproxy.org/
5. OWASP Foundation, "OWASP DefectDojo: Vulnerability Management Orchestration," 2024. [Online]. Available: https://www.defectdojo.org/
6. OWASP Top 10 Team, "OWASP Top 10: 2021 The Ten Most Critical Web Application Security Risks," OWASP Foundation, 2021.
7. PCI Security Standards Council, *Payment Card Industry Data Security Standard (PCI-DSS): Requirements and Testing Procedures, Version 4.0*, 2022.
8. National Institute of Standards and Technology (NIST), "National Vulnerability Database (NVD) REST API v2.0," U.S. Department of Commerce, 2023.
9. M. Myrbakken and R. Colomo-Palacios, "DevSecOps: A Multivocal Literature Review," in *Communications in Computer and Information Science*, vol. 770, Springer, 2017, pp. 17–29.
10. B. Bau, F. Bursztein, D. Gupta, and J. C. Mitchell, "State of the Art: Automated Black-Box Web Application Vulnerability Testing," in *Proc. IEEE Symposium on Security and Privacy (S&P)*, 2010, pp. 332–345.
11. A. Doupé, M. Cova, and G. Vigna, "Enemy of the State: A State-Aware Black-Box Web Vulnerability Scanner," in *Proc. USENIX Security Symposium*, 2012, pp. 523–538.
12. V. Atlidakis, P. Godefroid, and M. Polishchuk, "RESTler: State-ful REST API Fuzzing," in *Proc. IEEE/ACM 41st International Conference on Software Engineering (ICSE)*, 2019, pp. 748–758.
13. B. Johnson, Y. Song, E. Murphy-Hill, and R. Bowdidge, "Why Don't Software Developers Use Static Analysis Tools to Find Bugs?" in *Proc. IEEE/ACM 35th International Conference on Software Engineering (ICSE)*, 2013, pp. 672–681.
14. C. Vassallo, F. Zampetti, D. Romano, M. Beller, A. Panichella, M. Di Penta, and A. Zaidman, "Continuous Code Quality: Are We (Really) There Yet?" *IEEE Transactions on Software Engineering*, vol. 46, no. 4, pp. 396–413, 2020.
15. Anthropic, "Model Context Protocol (MCP) Specification: Open Protocol for Seamless AI Application Integration," 2024. [Online]. Available: https://modelcontextprotocol.io
