# AutoSecAudit: An Extensible Multi-Scanner Orchestration Engine with Automated Compliance Mapping and Delta Auditing for DevSecOps

**Authors:** Kodi Vishruth Aithal\textsuperscript{1}, Thilak N\textsuperscript{2}, Vinaya Kumar B\textsuperscript{3}, Vishal Gowda B\textsuperscript{4}, and Ms.~Ranjitha R\textsuperscript{5,*} (Faculty Mentor)  
**Affiliation:** Department of Computer Science and Engineering, Don Bosco Institute of Technology, Bangalore, Karnataka, India  
**Emails:** \textsuperscript{1}aithalvishruth@gmail.com, \textsuperscript{2}gowdathilakn@gmail.com, \textsuperscript{3}bvinaykumar70@gmail.com, \textsuperscript{4}vishalgb2005@gmail.com, \textsuperscript{5,*}ranjitha.r@dbit.co.in  
**Target Publication Format:** IEEE Standard 2-Column Full Research Paper (`IEEEtran`, 6–8 Pages)  

---

## Abstract
Continuous deployment workflows require continuous, automated security verification. However, engineering teams face significant friction when integrating traditional vulnerability assessment tools into fast Continuous Integration/Continuous Deployment (CI/CD) pipelines. Existing tools exhibit fragmented execution interfaces, inconsistent output formats, uncoordinated duplicate alerts, absence of standardized compliance metadata, and an inability to track vulnerability state changes across consecutive software builds.

This paper introduces **AutoSecAudit**, a modular vulnerability assessment and scanner orchestration framework designed specifically for DevSecOps pipelines. AutoSecAudit integrates automated attack surface discovery via breadth-first web crawling and OpenAPI/Swagger schema ingestion, concurrent execution across 14 specialized scanner plugins, and a post-processing intelligence layer. The intelligence layer executes heuristic deduplication, live Common Vulnerabilities and Exposures (CVE) and Common Vulnerability Scoring System (CVSS) enrichment via NIST and CIRCL endpoints, deterministic compliance taxonomy mapping across OWASP Top 10 (2021), MITRE CWE, and PCI-DSS v4.0, and set-theoretic delta differential auditing across historical scan states.

We validate AutoSecAudit across 80 automated unit and integration tests, as well as dynamic execution against the OWASP Juice Shop benchmark. Empirical results indicate that multi-threaded plugin execution yields a 64.8% decrease in scan latency relative to sequential execution. The post-processing correlator consolidates raw tool outputs with a 39.5% reduction in redundant alert volume, while the delta engine achieves 100% classification accuracy in identifying introduced, resolved, and persistent vulnerabilities across software build transitions.

**Keywords:** *Vulnerability Assessment, DevSecOps, Scanner Orchestration, Compliance Mapping, Delta Analysis, Web Security, API Security.*

---

## 1. Introduction
Modern web applications and REST APIs represent heterogeneous software stacks that evolve rapidly under continuous delivery models. Ensuring software security within such pipelines requires shift-left testing, where dynamic security analysis is integrated directly into automated build steps. 

Dynamic Application Security Testing (DAST) in continuous pipelines remains constrained by several architectural and operational deficiencies:
1. **Heterogeneous Tool Friction and Incoherent Outputs**: Identifying vulnerabilities across network services, web application endpoints, and API contracts requires orchestrating distinct utilities (such as port scanners, server misconfiguration checkers, and injection analyzers). Each tool outputs disparate, unstandardized formats (XML, raw text streams, non-uniform JSON).
2. **Alert Fatigue from Redundant Findings**: Independent scanners frequently identify overlapping symptoms on the same URI and parameter. In the absence of cross-tool correlation, developers receive duplicate alerts for a single root cause.
3. **Absence of Compliance Taxonomy Context**: Raw scanner outputs rarely provide contextual mapping to regulatory mandates, such as Payment Card Industry Data Security Standard (PCI-DSS v4.0), Common Weakness Enumeration (CWE), or OWASP Top 10 categories, necessitating manual risk classification.
4. **Stateless Execution and Missing Regression Tracking**: Traditional vulnerability scanners execute in a stateless manner, evaluating each build target in isolation. Consequently, developers cannot distinguish newly introduced vulnerabilities from pre-existing technical debt or verify whether a committed patch successfully resolved an open issue.

To address these limitations, we present **AutoSecAudit**, an extensible, concurrent vulnerability auditing engine. AutoSecAudit provides an end-to-end pipeline that unifies surface reconnaissance, multi-plugin execution, post-scan intelligence correlation, compliance labeling, differential regression tracking, and CI/CD gating.

---

## 2. Related Work & Comparative Analysis

| Dimension / Capability | Point Scanners (Nmap/Nikto) | Interactive Proxies (ZAP/Burp) | Aggregation Portals (DefectDojo) | **AutoSecAudit (Ours)** |
| :--- | :--- | :--- | :--- | :--- |
| **Scan Orchestration Scope** | Single Layer (Host / Web) | Deep Stateful Web Application | Passive Ingestion Hub | Unified Multi-Vector (Network + Web + API) |
| **Concurrency Model** | Thread/Process | Engine Threads | Non-scanning Hub | ThreadPool Executor ($k=8$) |
| **Automated Surface Discovery**| None | Crawler + Spider | None (Input URLs) | BFS Crawler + OpenAPI 3.0 Ingestion |
| **Threat Intelligence Feed** | ❌ None / Manual | ⚠️ Extension-based | ⚠️ Static Rule Lookup | ✅ Live NIST NVD & CIRCL API Lookup |
| **Historical Delta Diffing** | ❌ None | ❌ Session-bound | ⚠️ Complex Database Queries | ✅ Native Set-Theoretic JSON Diffing |
| **Compliance Taxonomies** | ❌ None | ⚠️ Basic Alerts | ⚠️ User-defined Tags | ✅ OWASP Top 10, CWE, PCI-DSS v4.0 |
| **CI/CD Native Policy Gating**| ❌ Exit 0 regardless | ⚠️ Requires Custom Scripts | ⚠️ Async API Webhooks | ✅ Built-in `--fail-on` Policy Exit Code |
| **Deployment Model** | CLI Binaries | Heavy Java GUI / Daemon | Django + PostgreSQL | Lightweight Python & Docker |

---

## 3. System Architecture & Methodology

AutoSecAudit is structured into four decoupled functional subsystems:
1. **Input Ingestion & Surface Discovery** (`WebCrawler`, `OpenAPIImporter`)
2. **Core Engine & Plugin Subsystem** (`Engine`, `BaseScanner` interface, 14 specialized plugins)
3. **Intelligence Layer** (`Correlator`, `Enricher`, `ComplianceMapper`, `remediation.py`, `DeltaAnalyzer`)
4. **Delivery & CI/CD Gating** (Exit code evaluator, Webhook dispatcher, SSE streaming, Flask UI)

### 3.1 Attack Surface Discovery
- **Breadth-First Web Crawler (`WebCrawler`)**: Recursively traverses web targets starting from the root URL. Parses HTML responses, isolates forms, extracts parameter-bearing query strings, and identifies injectable endpoints.
- **OpenAPI / Swagger Ingestion (`OpenAPIImporter`)**: Automatically parses OpenAPI 3.0 / Swagger 2.0 schemas to register parameterized REST API endpoints.

```
Algorithm 1: Dynamic Attack Surface Discovery and Seeding
-----------------------------------------------------------------------------
Input: Target URL u0, Max Depth D_max, OpenAPI Path Omega
Output: Discovered Injectable Endpoints E
1: Initialize FIFO queue Q = {(u0, 0)}, Visited Set V = {}, E = {}
2: If Omega is provided:
3:    S_api = ParseOpenAPISpec(Omega)
4:    E = E U S_api
5: While Q is not empty:
6:    (u, d) = Dequeue(Q)
7:    If u in V or d > D_max: Continue
8:    V = V U {u}
9:    Response R = HTTP_GET(u)
10:   Forms F = ExtractForms(R.body)
11:   E = E U Forms
12:   Links L = ExtractHyperlinks(R.body)
13:   For each link l in L with same host:
14:      If HasQueryParams(l): E = E U {ParamEndpoint(l)}
15:      Enqueue (l, d+1) into Q
16: Return E
```

### 3.2 Core Concurrency Engine & 14 Scanner Plugins
The engine executes 14 plugins concurrently using `ThreadPoolExecutor`:
$$\text{Scan Latency} = \max_{1 \le i \le N}(T_i) + \delta_{\text{sync}}$$

The 14 built-in plugins:
- **Infrastructure**: `NmapPlugin`, `NiktoPlugin`, `DirBruteScanner` (50-path curated wordlist).
- **Web Injections**: `SQLiScanner` (error/time/union SQLi), `XSSScanner`, `CORSScanner`, `MisconfigScanner`.
- **API & Auth**: `APIAbuseScanner` (mass assignment), `AuthScanner` (credential brute-force, IDOR), `JWTScanner` (`none` algorithm, weak secrets).
- **Advanced Vectors**: `CommandInjectionScanner`, `SSRFScanner`, `PathTraversalScanner`, `SSTIScanner`.

### 3.3 Post-Processing Intelligence Layer
```
Algorithm 2: Post-Processing Intelligence Correlation and Delta Auditing
-----------------------------------------------------------------------------
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
11:   f_p.remediation = GetRemediation(f_p)
12:   S_t = S_t U {f_p}
13: If S_{t-1} is provided:
14:   Delta_NEW = { f in S_t | Hash(f) not in Hash(S_{t-1}) }
15:   Delta_FIXED = { f in S_{t-1} | Hash(f) not in Hash(S_t) }
16:   Delta_UNCHANGED = { f in S_t | Hash(f) in Hash(S_{t-1}) }
17: Return S_t, <Delta_NEW, Delta_FIXED, Delta_UNCHANGED>
```

---

## 4. Experimental Evaluation & Results

### 4.1 Concurrency & Execution Latency Benchmark
Evaluated across worker thread counts ($k \in \{1, 2, 4, 8, 16\}$):

| Thread Workers ($k$) | Scan Duration (s) | Relative Speedup | CPU Utilization (%) |
| :--- | :--- | :--- | :--- |
| **1 (Sequential)** | 184.2 s | 1.00x | 14.2% |
| **2** | 102.5 s | 1.80x | 27.8% |
| **4** | 71.4 s | 2.58x | 51.3% |
| **8** | **64.8 s** | **2.84x** | 78.4% |
| **16** | 66.1 s | 2.79x | 82.1% |

*Finding:* 8 worker threads deliver optimal performance, reducing execution latency by 64.8%.

### 4.2 Detection Performance & Noise Reduction (OWASP Juice Shop)

| Vulnerability Class | True Positives (TP) | False Positives (FP) | Raw Tool Alerts | Correlated Findings |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection (A03)** | 8 | 0 | 14 | 8 |
| **Cross-Site Scripting (A03)** | 12 | 1 | 19 | 12 |
| **Security Misconfiguration (A05)** | 15 | 0 | 26 | 15 |
| **Broken Access Control (A01)** | 6 | 0 | 9 | 6 |
| **API & Authentication (A07)** | 5 | 0 | 8 | 5 |
| **Total / Summary** | **46** | **1 (97.8% Precision)** | **76** | **46 (-39.5% Alert Noise)** |

### 4.3 Delta Regression Tracking Fidelity
- **Build v1.0 (Baseline)**: 46 vulnerabilities identified.
- **Build v1.1**: 10 resolved, 3 introduced $\to$ Output: 3 NEW, 10 FIXED, 36 UNCHANGED (100% classification accuracy).
- **Build v1.2**: 14 resolved, 0 introduced $\to$ Output: 0 NEW, 14 FIXED, 25 UNCHANGED (100% classification accuracy).

---

## 5. Discussion & Limitations
- **Dynamic JavaScript SPAs**: Heavy client-side JavaScript execution benefits from headless browser integration (e.g., Playwright/Puppeteer).
- **API Rate Limiting**: Local fallback rulebases mitigate external NIST NVD API latency when scanning without API keys.

---

## 6. Conclusion & Future Work
AutoSecAudit provides an extensible, modular vulnerability assessment framework tailored for DevSecOps workflows. Future work includes integrating local Large Language Model (LLM) agents for automated remediation patch synthesis, contextual false-positive validation, and distributed multi-node scanning architectures.

---

## References
1. G. F. Lyon, *Nmap Network Scanning*, Insecure.Com LLC, 2009.
2. C. Sullo and D. Lodge, *Nikto Web Server Scanner*, 2023.
3. ProjectDiscovery, *Nuclei: Fast and Customizable Vulnerability Scanner*, 2024.
4. OWASP Foundation, *OWASP Zed Attack Proxy (ZAP)*, 2024.
5. OWASP Foundation, *OWASP DefectDojo: Vulnerability Management Orchestration*, 2024.
6. OWASP Top 10 Team, *OWASP Top 10: 2021 The Ten Most Critical Web Application Security Risks*, 2021.
7. PCI Security Standards Council, *Payment Card Industry Data Security Standard (PCI-DSS) v4.0*, 2022.
8. NIST, *National Vulnerability Database (NVD) REST API v2.0*, 2023.
9. M. Myrbakken and R. Colomo-Palacios, *DevSecOps: A Multivocal Literature Review*, Springer, 2017.
10. B. Bau et al., *State of the Art: Automated Black-Box Web Application Vulnerability Testing*, IEEE S&P, 2010.
