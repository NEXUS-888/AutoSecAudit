# Changelog

## v2.1.0 — 2026-10-20

### Features
- self-iterating UI/UX batches with a headless-Chrome checker
- mark demo reports, label form fields, readable bad-target error
- autopilot (fix -> discover -> explore -> release), release gate and docs
- proof-by-failing-test for explorer findings
- tool-based discovery that generates mechanical backlog batches
- metered diff-only review, mechanical verification and a Claude budget
- add pre-flight target reachability check across CLI, Web UI, Engine, and MCP
- add statistical timing engine, deep JSON body fuzzer, WAF politeness, and JS route extraction
- add 5 new attack scanner plugins, dynamic scan profiles, and local vulnerable sandbox testbed
- add Plain-English Danger Engine, Multi-Framework Fix Recipes, and AutoSecAudit MCP Server
- enhance 3D parallax depth/glare and add instant value proposition pillars
- implement 3D scroll depth, living telemetry animation, and interactive threat graph
- redesign website into authentic cybersecurity engineering platform with live telemetry console, attack path graph, and verified finding records
- implement Stitch-inspired cybersecurity cockpit UI with live radar canvas HUD and interactive telemetry
- track landing and auth html templates in git
- add creative animated landing page with terminal demo, SAST vs DAST showdown, and user auth system
- complete AutoSecAudit 2.0 with interactive mode, research paper, figures & bugfixes
- add OpenAPI spec file upload and PDF executive report download
- add CI/CD gating, webhook alerts, OpenAPI importer, CWE and PCI-DSS compliance mapping
- add CORS Misconfiguration Scanner
- add Directory Bruteforcer (DirBrute) scanner plugin
- add finding detail modals with navigation
- add dark/light mode toggle with localStorage persistence
- add interactive report filtering with severity buttons and search
- add scan history dashboard with severity charts
- add real-time scan progress streaming via Server-Sent Events
- add baseline comparison to eliminate false positives
- add web crawler for endpoint discovery before scanning
- wire remediation into pipeline and report UI
- add remediation field to Finding and knowledge base
- add confidence scores to Finding model
- 7-plugin scanner suite, UI redesign, and interactive scan waiting animations

### Fixes
- hide the per-row select label and theme checkboxes on the history page
- resolve batch B31 (AUD-79, AUD-80, AUD-81)
- resolve batch B30 (AUD-76, AUD-77, AUD-78)
- resolve batch B29 (AUD-75)
- resolve batch B28 (AUD-73, AUD-74)
- resolve batch B27 (AUD-71, AUD-72)
- resolve batch B26 (AUD-69, AUD-70)
- GET the login form before probing it (browser-like warm-up)
- raise form-probe cap so promising forms past position 8 are covered
- don't report documentation example emails as a data leak
- respect state-changing deny rules in GET probes; harden SSTI marker
- resolve batch B25 (AUD-60, AUD-61)
- resolve batch B24 (AUD-57, AUD-58, AUD-59)
- resolve batch B23 (AUD-54, AUD-55, AUD-56)
- resolve batch B22 (AUD-51, AUD-52, AUD-53)
- resolve batch B21 (AUD-67, AUD-68)
- resolve batch B20 (AUD-65, AUD-66)
- resolve batch B19 (AUD-62, AUD-63, AUD-64)
- resolve end-to-end retest findings
- resolve batch B18 (AUD-48, AUD-49, AUD-50)
- resolve batch B17 (AUD-46, AUD-47)
- resolve batch B16 (AUD-43, AUD-44, AUD-45)
- resolve batch B15 (AUD-40, AUD-41, AUD-42)
- resolve batch B14 (AUD-37, AUD-38, AUD-39)
- resolve batch B13 (AUD-34, AUD-35, AUD-36)
- resolve batch B12 (AUD-32, AUD-33)
- resolve batch B11 (AUD-29, AUD-30, AUD-31)
- resolve batch B10 (AUD-27, AUD-28)
- resolve batch B09 (AUD-25, AUD-26)
- resolve batch B08 (AUD-22, AUD-23, AUD-24)
- resolve batch B07 (AUD-19, AUD-20, AUD-21)
- resolve batch B06 (AUD-16, AUD-17, AUD-18)
- resolve batch B05 (AUD-13, AUD-14, AUD-15)
- resolve batch B04 (AUD-10, AUD-11, AUD-12)
- resolve batch B03 (AUD-07, AUD-08, AUD-09)
- resolve batch B02 (AUD-04, AUD-05, AUD-06)
- resolve batch B01 (AUD-01, AUD-02, AUD-03)
- enrich reports with code fix recipes and fix unclosed @media print CSS
- clean duplicate markup and ensure auth modal centers with high contrast and overlay dismiss
- enforce login/signup authentication gate on scan actions and dashboard routes
- rectify Table III FP/Correlated bookkeeping, add recall (88.5%), and synchronize delta arithmetic with Table III
- compact Fig 1 to sleek horizontal 4-stage pipeline and tighten spacing to lock strict 5-page budget
- group Fig 3 and Fig 4 into a top-spanning two-column block to prevent LaTeX float overflow after references
- place Fig 4 directly in Section V-D adjacent to delta diff discussion and ensure unbroken text flow around Algorithm 2
- eliminate Page 5 float collision, explicitly unbold abstract via renewenvironment, and straighten Fig 1 arrow
- address all peer review issues - normalize typography, clean abstract, restyle figures, clarify 14-plugin evaluation, and balance 5-page layout
- replace plain text stub with ReportLab binary PDF generator with executive summary and numbered canvas
- ensure robust report_name emission and auto-resolve latest report
- ensure internal python-requests tools and tuple timeouts work properly in real active scans
- polish light theme contrast, fix post-scan redirection and report fallback
- upgrade web form to live SSE real-time streaming with polling fallback and retry handling
- improve request timeouts in BaseScanner and trailing slash normalization in Correlator
- patch critical vulnerabilities across project

### Performance
- eliminate continuous canvas loop and throttle 3D parallax to prevent high laptop fan/GPU usage

### Refactoring
- redesign Fig 1 architecture, clean Fig 2 annotations, refine visual styles, and balance Page 5 content
- enforce atomic tempfiles in app.py and tuple timeouts across all scanner plugins

### Documentation
- add post-audit status of code defects and the measurement plan
- update README.md with 19 attack plugins, scan profiles, danger engine, MCP server, and testbed sandbox
- update phase 3 presentation deck
- add official online doc-coauthoring skill from anthropics/skills repository
- add readme-crafter skill and rewrite README.md with problem statements, architecture diagrams, and comprehensive setup guide
- update README.md with 14 scanner plugins, enterprise features, CLI usage, architecture, and CI testing

### Tests
- run the suite in parallel and remove load-sensitive assertions

### Other
- merge: post-audit status of the paper's code defects and measurement plan
- merge: metered audit loop with discovery, proof-by-test exploration and release gate
- updated light mode ui
- style(paper): apply humanized, authentic engineering writing style across the full manuscript
- style(paper): refine Algorithm 2 placement and ensure seamless sentence continuity in Section III-C
- style(paper): fix figure 4 text collision, polish vector plots, and update Overleaf package
- ci: add unified test runner run_tests.py and GitHub Actions workflow for automated test execution
- Add new security scanners: Command Injection, SSRF, Path Traversal, SSTI, JWT and update integration tests
- Disable mock plugin auto-load
- Fix Docker: install nikto from GitHub
- Default to mock mode for easy use without nmap/nikto
- Set default MOCK_MODE to false for real scans
- Add speaker notes and flowchart for presentation
- Add presentation outline
- Add README and setup instructions
- Initial commit: AutoSecAudit 2.0 - Intelligent Security Auditing Framework

