# Graph Report - D:\Projects\AutoSec\AutoSecAudit  (2026-07-28)

## Corpus Check
- Corpus is ~41,963 words - fits in a single context window. You may not need a graph.

## Summary
- 596 nodes · 1238 edges · 47 communities (40 shown, 7 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 150 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Community 0: Core Modules (abc)
- Community 1: Security Scanners
- Community 2: Core Engine & Crawler
- Community 3: Security Scanners
- Community 4: Core Engine & Crawler
- Community 5: Security Scanners
- Community 6: Core Modules (after_request)
- Community 7: Core Engine & Crawler
- Community 8: Security Scanners
- Community 9: Security Scanners
- Community 10: Post-Processing Intelligence
- Community 11: Security Scanners
- Community 12: Core Engine & Crawler
- Community 13: Core Engine & Crawler
- Community 14: Security Scanners
- Community 15: Security Scanners
- Community 16: Core Engine & Crawler
- Community 17: Core Engine & Crawler
- Community 18: Security Scanners
- Community 19: Security Scanners
- Community 20: Core Modules (reports_generator_py_any)
- Community 21: Core Engine & Crawler
- Community 22: Security Scanners
- Community 23: Security Scanners
- Community 24: Security Scanners
- Community 25: Security Scanners
- Community 26: Integration Test Suite
- Community 27: Security Scanners
- Community 28: Security Scanners
- Community 29: Post-Processing Intelligence
- Community 30: Post-Processing Intelligence
- Community 31: Security Scanners
- Community 32: Core Engine & Crawler
- Community 33: Core Engine & Crawler
- Community 34: Core Engine & Crawler
- Community 36: Security Scanners
- Community 37: Security Scanners
- Community 38: Security Scanners
- Community 39: Security Scanners
- Community 40: Security Scanners
- Community 41: Security Scanners

## God Nodes (most connected - your core abstractions)
1. `BaseScanner` - 50 edges
2. `Engine` - 41 edges
3. `Finding` - 39 edges
4. `APIAbuseScanner` - 36 edges
5. `format_severity()` - 35 edges
6. `MisconfigScanner` - 30 edges
7. `PluginTestBase` - 30 edges
8. `AuthScanner` - 29 edges
9. `XSSScanner` - 27 edges
10. `SQLiScanner` - 26 edges

## Surprising Connections (you probably didn't know these)
- `Engine` --uses--> `BaseScanner`  [INFERRED]
  core/engine.py → plugins/base_plugin.py
- `TestFullPipeline` --uses--> `Engine`  [INFERRED]
  test_full_pipeline.py → core/engine.py
- `DummyScanner` --uses--> `Engine`  [INFERRED]
  test_verification.py → core/engine.py
- `Correlator` --uses--> `Finding`  [INFERRED]
  intelligence/correlator.py → core/models.py
- `DeltaAnalyzer` --uses--> `Finding`  [INFERRED]
  intelligence/delta.py → core/models.py

## Import Cycles
- None detected.

## Communities (47 total, 7 thin omitted)

### Community 0 - "Community 0: Core Modules (abc)"
Cohesion: 0.06
Nodes (24): ABC, format_severity(), get_severity_order(), Return numeric value for severity sorting., Normalize severity to standard values., BaseScanner, Any, Response (+16 more)

### Community 1 - "Community 1: Security Scanners"
Cohesion: 0.10
Nodes (17): APIAbuseScanner, Any, Response, Execute all API-abuse checks against the configured target., GET with blanket exception handling., POST with blanket exception handling., PUT with blanket exception handling., Return (host, port) from the target string. (+9 more)

### Community 2 - "Community 2: Core Engine & Crawler"
Cohesion: 0.11
Nodes (20): CrawlResult, DiscoveredEndpoint, _extract_path(), _extract_query_params(), _normalize_url(), Any, Web Crawler for AutoSecAudit. Discovers pages, links, forms, and URL parameters…, Resolve a relative href against a base URL. Returns None if off-domain. (+12 more)

### Community 3 - "Community 3: Security Scanners"
Cohesion: 0.13
Nodes (12): MisconfigScanner, Any, Execute all misconfiguration checks., Fetch the main page and verify required security headers., Security Misconfiguration vulnerability scanner. Tests for: - Missing HTTP…, Send a cross-origin request and inspect CORS headers., Probe for common sensitive files that should not be public., Probe common directories for enabled directory listing. (+4 more)

### Community 4 - "Community 4: Core Engine & Crawler"
Cohesion: 0.09
Nodes (15): Engine, Any, Execute a single plugin and return results., Generate the final aggregated report., Core scanning engine that orchestrates plugin execution., Generate summary statistics from findings., Dynamically load all plugins from the plugins directory., Check if class is a subclass of BaseScanner but not BaseScanner itself. (+7 more)

### Community 5 - "Community 5: Security Scanners"
Cohesion: 0.13
Nodes (11): AuthScanner, Any, Access sequential resource IDs without authentication., Authentication & Access Control vulnerability scanner. Tests for: -…, Attempt to register accounts with weak passwords., Probe for admin panels that are publicly reachable., Check if the password-reset endpoint leaks user existence., Fire rapid login requests to detect missing rate limiting. (+3 more)

### Community 6 - "Community 6: Core Modules (after_request)"
Cohesion: 0.13
Nodes (19): after_request, Load a previous scan report for delta comparison., load_json(), route, Test scan history dashboard feature., Test dark/light mode toggle feature., add_security_headers(), download_pdf_report() (+11 more)

### Community 7 - "Community 7: Core Engine & Crawler"
Cohesion: 0.11
Nodes (11): Any, Format and send notification payload., Sends scan summary alerts to Slack, Discord, or generic webhooks., WebhookNotifier, OpenAPIImporter, Any, Parses OpenAPI 2.0 (Swagger) and 3.0+ specifications into endpoint structures., Load spec from local file path or remote URL. (+3 more)

### Community 8 - "Community 8: Security Scanners"
Cohesion: 0.13
Nodes (10): CORSScanner, Any, Check if the server reflects back an arbitrary Origin header., Check if a subdomain-like origin is accepted., Check for credentials: true with wildcard (browser blocks but indicates…, Convert results to standardized findings., Return realistic mock findings., CORS misconfiguration scanner. (+2 more)

### Community 9 - "Community 9: Security Scanners"
Cohesion: 0.14
Nodes (9): Any, Return (base_url, host, port) from a target string., Check if the payload string appears un-encoded in the response body., Inject XSS payloads into GET parameters and check for reflection., Fetch the root page and look for DOM-XSS sinks in JavaScript., Check for missing XSS-related security headers on the root page., Test Angular/SPA hash-fragment based endpoints for reflection. Hash fragments…, HTTP-based Cross-Site Scripting (XSS) vulnerability scanner. (+1 more)

### Community 10 - "Community 10: Post-Processing Intelligence"
Cohesion: 0.15
Nodes (6): Enricher, Any, Enrich findings with CVE data from external APIs., Enrich findings with CVE data., Test the complete scan-to-report pipeline in mock mode., TestFullPipeline

### Community 11 - "Community 11: Security Scanners"
Cohesion: 0.17
Nodes (8): Any, Return (base_url, host, port) from a target string., Return the first matching SQL error signature found in *text*., Inject payloads into a single GET endpoint with baseline verification., POST common login forms with SQL injection payloads., Try path-based injection on REST-style numeric IDs., HTTP-based SQL Injection vulnerability scanner., SQLiScanner

### Community 12 - "Community 12: Core Engine & Crawler"
Cohesion: 0.19
Nodes (12): Represents the final aggregated report., Report, Validate target is a valid URL or IP address., validate_target(), DeltaAnalyzer, Any, Compare current scan with previous scan for delta analysis., Compare current findings with previous findings. (+4 more)

### Community 13 - "Community 13: Core Engine & Crawler"
Cohesion: 0.22
Nodes (9): Finding, Represents a single security finding., ComplianceMapper, Any, Generate compliance summary for all findings., Map findings to compliance frameworks like OWASP Top 10, CWE, and PCI-DSS v4.0., Map each finding to OWASP, CWE, and PCI-DSS categories., Test the intelligence layer components. (+1 more)

### Community 14 - "Community 14: Security Scanners"
Cohesion: 0.18
Nodes (6): DirBruteScanner, Any, Probe each path in the wordlist against the target., Convert results to standardized findings., Return realistic mock findings., Directory bruteforce scanner — discovers hidden paths and files.

### Community 15 - "Community 15: Security Scanners"
Cohesion: 0.24
Nodes (3): NiktoPlugin, Any, Nikto scanner plugin for web vulnerability scanning.

### Community 16 - "Community 16: Core Engine & Crawler"
Cohesion: 0.31
Nodes (4): Quick demo: full scan pipeline on any target., Test confidence scores feature., End-to-end pipeline test. Validates the full scan pipeline: Engine ->…, Test Step 4: Intelligence Layer

### Community 17 - "Community 17: Core Engine & Crawler"
Cohesion: 0.18
Nodes (7): Convert dictionary data to Finding objects., Execute all loaded plugins in parallel using threading., Any, Represents results from a single scanner., ScanResult, get_timestamp(), Get current timestamp in configured format.

### Community 18 - "Community 18: Security Scanners"
Cohesion: 0.24
Nodes (4): CommandInjectionScanner, Any, Response, Probe parameters and selected headers for shell command execution.

### Community 19 - "Community 19: Security Scanners"
Cohesion: 0.24
Nodes (3): JWTScanner, Any, Inspect exposed JWTs for unsafe algorithm and lifecycle claims.

### Community 20 - "Community 20: Core Modules (reports_generator_py_any)"
Cohesion: 0.20
Nodes (7): Any, Generate full report with optional delta comparison., Generate HTML reports from scan results., Generate HTML report from Report object., Generate HTML report from dictionary., Generate printable text PDF audit summary report., ReportGenerator

### Community 21 - "Community 21: Core Engine & Crawler"
Cohesion: 0.20
Nodes (10): is_target_allowed(), Check if the target is allowed for scanning. Returns: (allowed: bool, reason:…, enrich_with_remediation(), Populate the `remediation` field on each finding that doesn't already have one.…, Test SSE scan progress feature., Run a scan in a background thread, pushing progress events to the queue., Start a scan in the background, return a scan_id for SSE streaming., _run_scan_background() (+2 more)

### Community 22 - "Community 22: Security Scanners"
Cohesion: 0.27
Nodes (3): NmapPlugin, Any, Nmap scanner plugin for port scanning and service detection.

### Community 23 - "Community 23: Security Scanners"
Cohesion: 0.29
Nodes (3): PathTraversalScanner, Any, Detect local file inclusion and path traversal indicators.

### Community 24 - "Community 24: Security Scanners"
Cohesion: 0.29
Nodes (3): Any, Detect server-side URL fetching using safe loopback probes by default., SSRFScanner

### Community 25 - "Community 25: Security Scanners"
Cohesion: 0.29
Nodes (3): Any, Detect server-side template evaluation without executing arbitrary code., SSTIScanner

### Community 26 - "Community 26: Integration Test Suite"
Cohesion: 0.24
Nodes (5): Any, Test implementation of BaseScanner., Test the BaseScanner abstract class., test_base_scanner(), TestScanner

### Community 27 - "Community 27: Security Scanners"
Cohesion: 0.20
Nodes (5): Tests for all new vulnerability scanner plugins. Runs every plugin in MOCK_MODE…, TestAPIAbusePlugin, TestCommandInjectionPlugin, TestJWTPlugin, TestPathTraversalPlugin

### Community 29 - "Community 29: Post-Processing Intelligence"
Cohesion: 0.25
Nodes (5): Correlator, Any, Correlate related findings across different scanners., Group related findings by host and port., Link related findings and add correlation metadata.

### Community 30 - "Community 30: Post-Processing Intelligence"
Cohesion: 0.32
Nodes (6): _extract_finding_type(), get_remediation(), Remediation knowledge base for AutoSecAudit. Maps vulnerability types (by OWASP…, Look up remediation advice for a finding. Priority: 1. Tool-specific + finding-…, Extract the 'Type: xxx' value from a finding description., Test remediation suggestions feature.

### Community 31 - "Community 31: Security Scanners"
Cohesion: 0.32
Nodes (3): MockPlugin, Any, Mock scanner plugin for testing.

### Community 32 - "Community 32: Core Engine & Crawler"
Cohesion: 0.29
Nodes (3): _LinkFormParser, Extract links, forms, and their inputs from HTML., HTMLParser

### Community 33 - "Community 33: Core Engine & Crawler"
Cohesion: 0.40
Nodes (4): Save report to JSON file., Any, Save data to JSON file., save_json()

### Community 34 - "Community 34: Core Engine & Crawler"
Cohesion: 0.50
Nodes (3): Set and validate the target., normalize_target(), Normalize target to a consistent format.

## Knowledge Gaps
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `BaseScanner` connect `Community 0: Core Modules (abc)` to `Community 1: Security Scanners`, `Community 3: Security Scanners`, `Community 4: Core Engine & Crawler`, `Community 5: Security Scanners`, `Community 8: Security Scanners`, `Community 9: Security Scanners`, `Community 11: Security Scanners`, `Community 14: Security Scanners`, `Community 15: Security Scanners`, `Community 16: Core Engine & Crawler`, `Community 18: Security Scanners`, `Community 19: Security Scanners`, `Community 22: Security Scanners`, `Community 23: Security Scanners`, `Community 24: Security Scanners`, `Community 25: Security Scanners`, `Community 26: Integration Test Suite`, `Community 31: Security Scanners`?**
  _High betweenness centrality (0.545) - this node is a cross-community bridge._
- **Why does `Engine` connect `Community 4: Core Engine & Crawler` to `Community 0: Core Modules (abc)`, `Community 33: Core Engine & Crawler`, `Community 2: Core Engine & Crawler`, `Community 34: Core Engine & Crawler`, `Community 6: Core Modules (after_request)`, `Community 10: Post-Processing Intelligence`, `Community 12: Core Engine & Crawler`, `Community 13: Core Engine & Crawler`, `Community 16: Core Engine & Crawler`, `Community 17: Core Engine & Crawler`, `Community 21: Core Engine & Crawler`, `Community 30: Post-Processing Intelligence`?**
  _High betweenness centrality (0.260) - this node is a cross-community bridge._
- **Why does `APIAbuseScanner` connect `Community 1: Security Scanners` to `Community 0: Core Modules (abc)`, `Community 36: Security Scanners`, `Community 37: Security Scanners`, `Community 38: Security Scanners`, `Community 39: Security Scanners`, `Community 40: Security Scanners`, `Community 41: Security Scanners`, `Community 27: Security Scanners`, `Community 28: Security Scanners`?**
  _High betweenness centrality (0.116) - this node is a cross-community bridge._
- **Are the 18 inferred relationships involving `BaseScanner` (e.g. with `Engine` and `APIAbuseScanner`) actually correct?**
  _`BaseScanner` has 18 INFERRED edges - model-reasoned connections that need verification._
- **Are the 7 inferred relationships involving `Engine` (e.g. with `WebCrawler` and `Finding`) actually correct?**
  _`Engine` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 6 inferred relationships involving `Finding` (e.g. with `Engine` and `ComplianceMapper`) actually correct?**
  _`Finding` has 6 INFERRED edges - model-reasoned connections that need verification._
- **Are the 12 inferred relationships involving `APIAbuseScanner` (e.g. with `BaseScanner` and `PluginTestBase`) actually correct?**
  _`APIAbuseScanner` has 12 INFERRED edges - model-reasoned connections that need verification._