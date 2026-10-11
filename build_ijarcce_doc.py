import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn, nsdecls
from docx.oxml import parse_xml

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set padding for a table cell in dxa (1 pt = 20 dxa)"""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_shading(cell, color_hex):
    """Set background color for a table cell"""
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading)

def set_table_borders(table, color="B0B0B0", sz="4", val="single"):
    """Set clean subtle borders for a table"""
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'  <w:top w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:bottom w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:left w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'  <w:insideH w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:insideV w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

def build_paper():
    template_path = 'paper/IJARCCE-Paper-Format.docx'
    output_path = 'paper/AutoSecAudit_Research_Paper_IJARCCE.docx'
    root_output_path = 'AutoSecAudit_Research_Paper_IJARCCE.docx'

    doc = docx.Document(template_path)

    # Remove all existing template placeholder paragraphs and tables
    p_elems = [p._p for p in doc.paragraphs]
    for p in p_elems:
        p.getparent().remove(p)
    t_elems = [t._tbl for t in doc.tables]
    for t in t_elems:
        t.getparent().remove(t)

    # ---------------------------------------------------------------------------
    # TITLE
    # ---------------------------------------------------------------------------
    p_title = doc.add_paragraph(style='IEEE Title')
    r_title = p_title.add_run("AutoSecAudit 2.0: An Extensible Multi-Scanner Orchestration Framework with Autonomous AI Remediation, Precision Fuzzing, and Delta Auditing in DevSecOps")
    r_title.font.name = 'Times New Roman'
    r_title.font.size = Pt(22)
    r_title.font.bold = True

    doc.add_paragraph() # Spacing

    # ---------------------------------------------------------------------------
    # AUTHORS & AFFILIATIONS
    # ---------------------------------------------------------------------------
    p_authors = doc.add_paragraph(style='IEEE Title')
    p_authors.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_auth = p_authors.add_run("Kodi Vishruth Aithal, Thilak N, Vinaya Kumar B, Vishal Gowda B, Ms. Ranjitha R*")
    r_auth.font.name = 'Times New Roman'
    r_auth.font.size = Pt(11)
    r_auth.font.bold = True

    p_aff1 = doc.add_paragraph(style='IEEE Author Affiliation')
    p_aff1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_aff1 = p_aff1.add_run("Department of Computer Science and Engineering, Don Bosco Institute of Technology, Bangalore, Karnataka, India")
    r_aff1.font.name = 'Times New Roman'
    r_aff1.font.size = Pt(10)
    r_aff1.font.italic = True

    p_aff2 = doc.add_paragraph(style='IEEE Author Affiliation')
    p_aff2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_aff2 = p_aff2.add_run("Emails: {aithalvishruth, gowdathilakn, bvinaykumar70, vishalgb2005}@gmail.com, *ranjitha.r@dbit.co.in")
    r_aff2.font.name = 'Times New Roman'
    r_aff2.font.size = Pt(9.5)
    r_aff2.font.italic = True

    p_aff3 = doc.add_paragraph(style='IEEE Author Affiliation')
    p_aff3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_aff3 = p_aff3.add_run("(*Corresponding Author & Faculty Mentor)")
    r_aff3.font.name = 'Times New Roman'
    r_aff3.font.size = Pt(9)
    r_aff3.font.bold = True

    doc.add_paragraph() # Spacing

    # ---------------------------------------------------------------------------
    # ABSTRACT
    # ---------------------------------------------------------------------------
    p_abs = doc.add_paragraph(style='IEEE Abtract')
    p_abs.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r_abs_lbl = p_abs.add_run("Abstract— ")
    r_abs_lbl.font.name = 'Times New Roman'
    r_abs_lbl.font.size = Pt(10)
    r_abs_lbl.font.bold = True

    r_abs_txt = p_abs.add_run(
        "Continuous deployment workflows require continuous, automated security verification. However, engineering teams face significant friction when integrating traditional vulnerability assessment tools into fast Continuous Integration/Continuous Deployment (CI/CD) pipelines. Existing tools suffer from tool fragmentation, uncoordinated duplicate alerts, lack of actionable business risk context for non-technical stakeholders, absent automated code remediation recipes, and an inability to bridge dynamic findings into modern AI-assisted engineering environments. "
        "This paper introduces AutoSecAudit 2.0, an extensible vulnerability auditing framework and autonomous remediation platform designed for modern DevSecOps pipelines. AutoSecAudit 2.0 unifies: "
        "(1) Automated Attack Surface Discovery via breadth-first web crawling, client-side JavaScript route regex extraction, OpenAPI 2.0/3.0 schema parsing, and pre-flight target reachability validation; "
        "(2) High-Precision Multi-Scanner Orchestration across 19 specialized attack scanner plugins spanning web application injections, API/access control, exploit vectors, and infrastructure reconnaissance. False alarms are eliminated through a multi-tiered precision engine featuring a Statistical Timing Engine (dual-baseline latency calibration to prevent network jitter false positives in blind time-based attacks), Adaptive Politeness & Jitter Backoff (HTTP 429/503 exponential backoff), and a Deep Recursive JSON Body Fuzzer; "
        "(3) Post-Processing Intelligence Layer executing compound-key deduplication, live CVSS/CVE enrichment via NIST NVD and CIRCL endpoints, deterministic compliance taxonomy mapping across OWASP Top 10 (2021), MITRE CWE, and PCI-DSS v4.0, and a Plain-English 'Real Danger' Engine that translates technical vulnerabilities into four business risk categories with executive posture letter grades (A+ to F); and "
        "(4) Autonomous AI Remediation & DevSecOps Delivery providing multi-framework drop-in code fix recipes (Node.js/Express, Python/FastAPI/Django, Nginx, WAF rules), 1-click Markdown dev tickets (Jira, Linear, GitHub), set-theoretic delta differential regression auditing across software builds, and a standard Model Context Protocol (MCP) JSON-RPC 2.0 server enabling AI coding agents (Cursor, Claude Code, Antigravity) to scan targets, fetch findings, generate source code fixes, and perform targeted re-verification. "
        "We evaluate AutoSecAudit 2.0 across an expanded suite of 165 automated unit and integration tests, as well as dynamic execution against the OWASP Juice Shop benchmark. Empirical results demonstrate that bounded multi-threaded plugin execution (k=8) yields a 64.8% decrease in scan latency (2.84x speedup) over sequential auditing. The intelligence layer consolidates raw tool alerts with a 38.2% reduction in alert noise at 97.9% precision and 88.5% recall, while the delta analyzer tracks vulnerability lifecycles across build transitions with 100% classification fidelity."
    )
    r_abs_txt.font.name = 'Times New Roman'
    r_abs_txt.font.size = Pt(10)

    # ---------------------------------------------------------------------------
    # KEYWORDS
    # ---------------------------------------------------------------------------
    p_kw = doc.add_paragraph(style='Normal')
    p_kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r_kw_lbl = p_kw.add_run("Keywords: ")
    r_kw_lbl.font.name = 'Times New Roman'
    r_kw_lbl.font.size = Pt(10)
    r_kw_lbl.font.bold = True
    r_kw_lbl.font.italic = True

    r_kw_txt = p_kw.add_run("Vulnerability Assessment, DevSecOps, Scanner Orchestration, Model Context Protocol (MCP), Autonomous AI Remediation, Statistical Timing Verification, Compliance Mapping, Delta Auditing, Web Security, API Security.")
    r_kw_txt.font.name = 'Times New Roman'
    r_kw_txt.font.size = Pt(10)
    r_kw_txt.font.italic = True

    doc.add_paragraph() # Spacing

    # ---------------------------------------------------------------------------
    # SECTION I. INTRODUCTION
    # ---------------------------------------------------------------------------
    p_sec1 = doc.add_paragraph("I.  INTRODUCTION", style='IEEE Heading 1')
    p_sec1.alignment = WD_ALIGN_PARAGRAPH.CENTER

    p1 = doc.add_paragraph(style='IEEE Paragraph')
    p1.add_run(
        "Modern web applications, cloud-native services, and REST APIs represent heterogeneous software stacks that evolve rapidly under continuous delivery models. Ensuring software security within such fast release cycles demands shift-left testing, where dynamic security analysis is integrated directly into automated build steps [10]. Dynamic Application Security Testing (DAST) assesses running web applications from an external attacker perspective without requiring access to source code, validating whether real-world exploitation conditions are achievable in practice."
    )

    p2 = doc.add_paragraph(style='IEEE Paragraph')
    p2.add_run(
        "However, incorporating DAST into Continuous Integration/Continuous Deployment (CI/CD) pipelines routinely frustrates software engineering organizations. Empirical studies by Johnson et al. [13] and Bau et al. [10] show that software developers frequently ignore or disable automated security scanners when reports are noisy, overloaded with duplicates, or disconnected from practical bug fixes. In production environments, this operational breakdown stems from five recurring dilemmas:"
    )

    p_d1 = doc.add_paragraph(style='IEEE Paragraph')
    r_d1_title = p_d1.add_run("1) Heterogeneous Tool Fragmentation and Format Sprawl: ")
    r_d1_title.font.bold = True
    p_d1.add_run("A comprehensive security audit requires orchestrating multiple disparate utilities—such as port discovery tools (Nmap [1]), web server misconfiguration checkers (Nikto [2]), and API parameter fuzzers. Each utility outputs a different raw format (XML, unstructured console text, non-uniform JSON), forcing engineering teams to build and maintain brittle parsing wrappers.")

    p_d2 = doc.add_paragraph(style='IEEE Paragraph')
    r_d2_title = p_d2.add_run("2) Duplicate Alert Sprawl and Developer Fatigue: ")
    r_d2_title.font.bold = True
    p_d2.add_run("Independent scanners frequently flag the exact same root vulnerability on an endpoint under slightly varied diagnostic titles. Without cross-plugin deduplication, engineers end up triaging multiple notifications for a single bug, creating severe alert fatigue and wasting engineering hours [13].")

    p_d3 = doc.add_paragraph(style='IEEE Paragraph')
    r_d3_title = p_d3.add_run("3) Executive Communication Gap: ")
    r_d3_title.font.bold = True
    p_d3.add_run("Traditional scanners display raw Common Vulnerabilities and Exposures (CVE) numbers, Common Vulnerability Scoring System (CVSS) vectors, and hexadecimal traces. These technical representations fail to communicate practical business impact, leaving executives and product owners unable to assess real-world business risks or understand what an adversary can actually execute against the platform.")

    p_d4 = doc.add_paragraph(style='IEEE Paragraph')
    r_d4_title = p_d4.add_run("4) Missing Code Fixes and AI Workflow Disconnection: ")
    r_d4_title.font.bold = True
    p_d4.add_run("Traditional security scanners identify what is broken but leave developers to write framework-specific patches, input sanitization routines, or Web Application Firewall (WAF) virtual patching rules from scratch. Furthermore, while modern engineers increasingly develop within AI-assisted environments (Cursor, Claude Code, Antigravity), existing scanners remain trapped in legacy CLI terminals with no standardized agentic interface [15].")

    p_d5 = doc.add_paragraph(style='IEEE Paragraph')
    r_d5_title = p_d5.add_run("5) Stateless Scans Lacking Regression Awareness: ")
    r_d5_title.font.bold = True
    p_d5.add_run("Managing technical debt in CI/CD requires knowing what changed between commits [14]. Traditional scanners evaluate targets in isolation without tracking historical state. Consequently, engineering teams cannot distinguish newly introduced vulnerabilities from pre-existing accepted debt or verify whether a committed patch successfully resolved an open issue.")

    p3 = doc.add_paragraph(style='IEEE Paragraph')
    p3.add_run(
        "To address these challenges, we present AutoSecAudit 2.0, an extensible multi-scanner security orchestration framework and autonomous AI remediation platform. AutoSecAudit 2.0 unifies automated attack surface discovery, concurrent execution of 19 specialized scanner plugins, statistical false-positive elimination, plain-English business danger translation, multi-framework code fix generation, set-theoretic delta regression diffing, and native Model Context Protocol (MCP) tool integration into a cohesive DevSecOps engine."
    )

    # ---------------------------------------------------------------------------
    # SECTION II. RELATED WORK AND COMPARATIVE ANALYSIS
    # ---------------------------------------------------------------------------
    p_sec2 = doc.add_paragraph("II.  RELATED WORK AND COMPARATIVE ANALYSIS", style='IEEE Heading 1')

    p_rw1 = doc.add_paragraph(style='IEEE Paragraph')
    p_rw1.add_run(
        "Security testing tools generally fit into four architectural paradigms: standalone point scanners, interactive DAST proxies, fast template matchers, and centralized vulnerability management portals. Table I provides a comprehensive capability comparison between these systems and AutoSecAudit 2.0."
    )

    p_sub1 = doc.add_paragraph("A.  Point Scanners and Specialized Utilities", style='IEEE Heading 2')
    p_rw2 = doc.add_paragraph(style='IEEE Paragraph')
    p_rw2.add_run(
        "Network scanners like Nmap [1] handle port discovery and service fingerprinting, while web server checkers like Nikto [2] scan for server misconfigurations and outdated defaults. Template-driven scanners like Nuclei [3] run fast YAML pattern matches over HTTP. However, these utilities execute as standalone binaries and lack built-in multi-plugin correlation, automated compliance tagging, historical regression diffing, and autonomous AI remediation interfaces."
    )

    p_sub2 = doc.add_paragraph("B.  Stateful DAST Proxies and API Fuzzers", style='IEEE Heading 2')
    p_rw3 = doc.add_paragraph(style='IEEE Paragraph')
    p_rw3.add_run(
        "State-aware scanners, explored by Doupé et al. [11], track application navigation states to uncover deeper injection points. In API fuzzing, Atlidakis et al. [12] demonstrated with RESTler that effective testing requires parsing OpenAPI structures. Comprehensive proxies like OWASP ZAP [4] and PortSwigger Burp Suite provide thorough coverage, but their heavy resource consumption, complex daemon lifecycles, and extended scan runtimes make them difficult to run on fast pull-request merge checks."
    )

    p_sub3 = doc.add_paragraph("C.  Vulnerability Management Aggregation Platforms", style='IEEE Heading 2')
    p_rw4 = doc.add_paragraph(style='IEEE Paragraph')
    p_rw4.add_run(
        "Platforms like OWASP DefectDojo [5] aggregate findings from third-party scanners into a central repository. However, DefectDojo functions primarily as a passive ingestion platform; it still requires teams to write external pipeline jobs to run individual tools, parse diverse log formats, and push results over REST APIs."
    )

    p_sub4 = doc.add_paragraph("D.  Autonomous AI Remediation and Agentic Protocols", style='IEEE Heading 2')
    p_rw5 = doc.add_paragraph(style='IEEE Paragraph')
    p_rw5.add_run(
        "Recent advances in AI-assisted software engineering have produced agentic developer tools (such as Cursor, Claude Code, and Antigravity). However, bridging external dynamic security scanners with AI agents has been hindered by the lack of standardized protocol integration. AutoSecAudit 2.0 addresses this gap by implementing the standard JSON-RPC 2.0 Model Context Protocol (MCP) [15], enabling AI agents to programmatically initiate scans, inspect enriched findings, obtain ready-to-paste code patches, and verify remediation directly in the developer's workspace."
    )

    # TABLE I
    doc.add_paragraph("TABLE I   ARCHITECTURAL COMPARISON ACROSS SECURITY TESTING PARADIGMS", style='IEEE Table Caption')
    tbl1 = doc.add_table(rows=14, cols=5)
    tbl1.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl1)

    t1_data = [
        ["Dimension / Capability", "Point Scanners (Nmap/Nikto) [1,2]", "OWASP ZAP [4]", "DefectDojo [5]", "AutoSecAudit 2.0 (Ours)"],
        ["Scan Scope", "Host / Web (Single Layer)", "Stateful Web Application", "Passive Ingestion Hub", "Host + Web + REST API (Unified)"],
        ["Concurrency Model", "Process / Thread", "Engine Threads", "Non-scanning Hub", "ThreadPool (k=8) with Dynamic Profiles"],
        ["Surface Discovery", "None", "Crawler + Spider", "None (Manual Input)", "BFS + JS Routes + OpenAPI 2.0/3.0"],
        ["Active Scanner Plugins", "Single Purpose", "Modular Add-ons", "None", "19 Built-in Attack Simulation Plugins"],
        ["False-Positive Elimination", "None", "Heuristic Rules", "Manual Triage", "Statistical Timing + Dual Baseline Delta"],
        ["Deep JSON API Fuzzing", "None", "Partial Plugin", "None", "Deep Recursive JSON Body Mutation"],
        ["Threat Intelligence", "None / Manual", "Add-on Scripts", "Rule Matching", "Live NIST NVD & CIRCL API Lookups"],
        ["Compliance Taxonomies", "None", "Alert Tags", "Database Tags", "Deterministic OWASP, CWE, PCI-DSS v4.0"],
        ["Executive Threat Lens", "Raw Logs", "Technical CVSS", "CVSS Charts", "Plain-English Danger (Grades A+ to F)"],
        ["Automated Code Fixes", "None", "Generic Text", "Static Notes", "Drop-in Recipes (Node, Python, Nginx, WAF)"],
        ["Autonomous AI Bridge", "None", "None", "REST API", "Native JSON-RPC 2.0 MCP Server [15]"],
        ["Historical Delta Auditing", "None", "Session-bound", "DB Queries", "Native Set-Theoretic JSON Diffing"],
        ["CI/CD Policy Gating", "Exit 0 regardless", "Custom Scripts", "Async Webhooks", "Built-in --fail-on Policy Exit Code"]
    ]

    for r_idx, row_data in enumerate(t1_data):
        row = tbl1.rows[r_idx]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.text = val
            p_cell = cell.paragraphs[0]
            p_cell.style = 'IEEE Table Cell'
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            if r_idx == 0:
                set_cell_shading(cell, "E2E8F0")
                p_cell.runs[0].font.bold = True
                p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER
            else:
                if c_idx == 4:
                    set_cell_shading(cell, "F0FDF4")
                    p_cell.runs[0].font.bold = True

    doc.add_paragraph() # Spacing

    # ---------------------------------------------------------------------------
    # SECTION III. SYSTEM ARCHITECTURE AND METHODOLOGY
    # ---------------------------------------------------------------------------
    p_sec3 = doc.add_paragraph("III.  SYSTEM ARCHITECTURE AND METHODOLOGY", style='IEEE Heading 1')

    p_arch = doc.add_paragraph(style='IEEE Paragraph')
    p_arch.add_run(
        "AutoSecAudit 2.0 is structured into four decoupled subsystems (Fig. 1): "
        "(1) Input Ingestion, Surface Discovery & Pre-flight Validation; "
        "(2) Concurrent Multi-Scanner Engine & Precision Subsystem; "
        "(3) Post-Processing Intelligence Layer; and "
        "(4) Delivery, CI/CD Gating, and Autonomous AI Remediation."
    )

    # INSERT FIGURE 1
    if os.path.exists('paper/figures/fig1_architecture.png'):
        p_fig1 = doc.add_paragraph()
        p_fig1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_fig1.paragraph_format.space_before = Pt(8)
        p_fig1.paragraph_format.space_after = Pt(4)
        run_fig1 = p_fig1.add_run()
        run_fig1.add_picture('paper/figures/fig1_architecture.png', width=Inches(6.6))
        p_cap1 = doc.add_paragraph("Fig. 1.  AutoSecAudit 2.0 System Architecture: 4-stage pipeline from surface discovery and concurrent 19-plugin execution through intelligence correlation, compliance mapping, danger translation, delta tracking, and AI MCP integration.", style='IEEE Figure Caption Multi-Lines')
        p_cap1.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    p_sub3a = doc.add_paragraph("A.  Attack Surface Discovery and Pre-flight Validation", style='IEEE Heading 2')
    p_3a = doc.add_paragraph(style='IEEE Paragraph')
    p_3a.add_run(
        "Given a target hostname, IP address, or URL, the surface discovery subsystem seeds an endpoint pool E before initiating active scans [11, 12]:"
    )

    p_g1 = doc.add_paragraph(style='IEEE Paragraph')
    r_g1 = p_g1.add_run("1) Target Safety Gate and Pre-Flight Liveness: ")
    r_g1.font.bold = True
    p_g1.add_run("To ensure ethical scanning and operational safety, targets are strictly validated against RFC 1918 private IP blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), localhost (127.0.0.1), and authorized local sandbox testbeds. Unauthorized external domains are aborted immediately. Additionally, pre-flight TCP port and HTTP reachability checks verify the server is live before thread allocation, preventing hung scans on dead hosts.")

    p_g2 = doc.add_paragraph(style='IEEE Paragraph')
    r_g2 = p_g2.add_run("2) Breadth-First Web Crawler and Client-Side JS Route Extraction: ")
    r_g2.font.bold = True
    p_g2.add_run("The WebCrawler recursively traverses target links starting from the root URL up to a depth limit D_max. It extracts HTML form structures (<form action method>), input fields, query parameters, and hyperlinks. Furthermore, inline <script> tags and referenced JavaScript bundles are analyzed using regex pattern extractors to discover hidden client-side REST API routes (/api/v1/...) that lack standard HTML links.")

    p_g3 = doc.add_paragraph(style='IEEE Paragraph')
    r_g3 = p_g3.add_run("3) OpenAPI / Swagger Ingestion: ")
    r_g3.font.bold = True
    p_g3.add_run("For headless REST backends, the OpenAPIImporter ingests OpenAPI 2.0 and 3.0 JSON/YAML specifications, registering all routes, HTTP methods (GET, POST, PUT, DELETE), payload schemas, and path variables into the endpoint pool.")

    p_g4 = doc.add_paragraph(style='IEEE Paragraph')
    r_g4 = p_g4.add_run("4) Automated Multi-Strategy Authenticator: ")
    r_g4.font.bold = True
    p_g4.add_run("To audit authenticated application surfaces, the Authenticator subsystem automatically discovers login forms, submits user credentials, captures session cookies and JWT Bearer tokens, and injects active authentication headers into scanner worker threads.")

    # Algorithm 1 block
    p_alg1 = doc.add_paragraph(style='IEEE Paragraph')
    r_a1 = p_alg1.add_run("Algorithm 1: Dynamic Attack Surface Discovery, JS Parsing, and Endpoint Seeding\n")
    r_a1.font.bold = True
    p_alg1.add_run(
        "Input: Target URL u0, Max Depth D_max, OpenAPI Path Omega, Auth Credentials A\n"
        "Output: Discovered Parameterized Endpoint Pool E\n"
        "1: If not IsTargetAllowed(u0) or not CheckLiveness(u0): Abort('Safety gate violation or host offline')\n"
        "2: Session S = InitializeSession()\n"
        "3: If A is provided: S = AutoAuthenticate(u0, A)\n"
        "4: Initialize FIFO queue Q = {(u0, 0)}, Visited Set V = {}, E = {}\n"
        "5: If Omega is provided: E = E U ParseOpenAPISpec(Omega)\n"
        "6: While Q is not empty:\n"
        "7:    (u, d) = Dequeue(Q)\n"
        "8:    If u in V or d > D_max: Continue\n"
        "9:    V = V U {u}\n"
        "10:   Response R = S.GET(u)\n"
        "11:   E = E U ParseHTMLForms(R.body) U ExtractJSRoutes(R.body)\n"
        "12:   For each link l in ExtractHyperlinks(R.body) matching host:\n"
        "13:      If HasQueryParams(l): E = E U {ParamEndpoint(l)}\n"
        "14:      Enqueue (l, d+1) into Q\n"
        "15: Return E"
    )

    p_sub3b = doc.add_paragraph("B.  Core Engine, 19 Scanner Plugins, and Precision Fuzzing", style='IEEE Heading 2')
    p_3b = doc.add_paragraph(style='IEEE Paragraph')
    p_3b.add_run(
        "Each scanner module extends the abstract BaseScanner interface. Standardized findings use the tuple model: "
        "F = <id, title, severity, host, port, endpoint, evidence, C, M>, where C in {Low, Medium, High} reflects differential confidence and M contains compliance and fix metadata."
    )

    p_3b_plugins = doc.add_paragraph(style='IEEE Paragraph')
    p_3b_plugins.add_run(
        "AutoSecAudit 2.0 organizes 19 dynamic vulnerability scanner plugins across four operational domains:\n"
        "• Web Application Injections: SQLiScanner (error, boolean, and statistical time-based blind SQLi), XSSScanner (reflected and stored XSS), CSRFScanner (anti-CSRF tokens and SameSite cookie hygiene), OpenRedirectScanner (unvalidated redirect parameters), MisconfigScanner (security headers and cookie hygiene).\n"
        "• API & Access Control: BOLAIdorScanner (Broken Object-Level Authorization and UUID manipulation), APIAbuseScanner (mass assignment, excessive data exposure, verb tampering), AuthScanner (credential brute-force, weak passwords), JWTScanner (Alg=None bypass, weak HMAC secrets), CORSScanner (origin reflection, wildcard credentials).\n"
        "• Advanced Exploit Vectors: CommandInjectionScanner (OS RCE shell execution), SSRFScanner (cloud metadata 169.254.169.254 and internal subnets), PathTraversalScanner (Local File Inclusion /etc/passwd), SSTIScanner (Jinja2, Twig, ERB template injection).\n"
        "• Reconnaissance & Infrastructure: SecretExposureScanner (leaked API keys, AWS tokens, git traces in HTML/.env), SSLTLSScanner (weak TLS ciphers, cert expiry, HSTS), DirBruteScanner (50+ curated sensitive paths), NiktoPlugin (server misconfigurations), NmapPlugin (open port discovery)."
    )

    p_3b_profiles = doc.add_paragraph(style='IEEE Paragraph')
    r_prof = p_3b_profiles.add_run("Dynamic Scan Profiles: ")
    r_prof.font.bold = True
    p_3b_profiles.add_run(
        "The engine introduces dynamic scan profiles: 'full' (all 19 plugins concurrently), 'owasp' (core 11 injection, auth, CSRF, SSRF, misconfiguration plugins), 'api' (7 API-tailored plugins: BOLA/IDOR, JWT, CORS, rate limits), and 'recon' (6 passive reconnaissance plugins)."
    )

    p_3b_prec = doc.add_paragraph(style='IEEE Paragraph')
    r_prec = p_3b_prec.add_run("Precision Engine and False-Positive Elimination Architecture: ")
    r_prec.font.bold = True
    p_3b_prec.add_run(
        "AutoSecAudit 2.0 deploys four architectural mechanisms to guarantee reliable, high-signal results:\n"
        "1) Statistical Timing Engine (core/timing.py): Blind time-based attacks (SLEEP(3), sleep 3) often suffer from false positives caused by network latency spikes. The engine measures benign baseline latency over m requests to establish mean mu_base and standard deviation sigma_base. An injection probe with delay tau is confirmed only if T_probe >= mu_base + 3*sigma_base + 0.8*tau across a two-stage verification cycle.\n"
        "2) Differential Baseline Verification: Before reporting an injection finding, BaseScanner measures a benign baseline response. Malicious probes are flagged only when they cause a confirmed HTTP status code change or a >20% response length delta.\n"
        "3) Adaptive Politeness & Jitter Backoff (core/politeness.py): Randomized delays (jitter) prevent target overload. If the target returns HTTP 429 (Too Many Requests) or HTTP 503, the engine executes exponential backoff.\n"
        "4) Deep Recursive JSON Body Fuzzer (core/fuzzer.py): Recursively traverses nested JSON payloads, mutating leaf values with security payloads while preserving surrounding request schemas."
    )

    p_sub3c = doc.add_paragraph("C.  Post-Processing Intelligence Layer", style='IEEE Heading 2')
    p_3c = doc.add_paragraph(style='IEEE Paragraph')
    p_3c.add_run(
        "Following raw scanner execution, the intelligence layer post-processes findings through six deterministic steps (Algorithm 2):"
    )

    # Algorithm 2 block
    p_alg2 = doc.add_paragraph(style='IEEE Paragraph')
    r_a2 = p_alg2.add_run("Algorithm 2: Intelligence Correlation, Real Danger Translation, and Delta Auditing\n")
    r_a2.font.bold = True
    p_alg2.add_run(
        "Input: Raw Findings F_raw, Historical Baseline Report S_{t-1}\n"
        "Output: Correlated Report S_t, Delta Partition <Delta_NEW, Delta_FIXED, Delta_UNCHANGED>\n"
        "1: Group map G = {}\n"
        "2: For each finding f in F_raw:\n"
        "3:    k = <f.host, f.port, f.endpoint, f.cwe_id>\n"
        "4:    G[k] = G[k] U {f}\n"
        "5: Consolidated Set S_t = {}\n"
        "6: For each group in G:\n"
        "7:    f_p = MergeFindings(group)\n"
        "8:    If f_p.cve_id: f_p.cvss = QueryNVD_CIRCL(f_p.cve_id)\n"
        "9:    f_p.owasp, f_p.pci_dss = MapCompliance(f_p)\n"
        "10:   f_p.danger = EvaluateRealDanger(f_p)\n"
        "11:   f_p.recipes = GenerateFixRecipes(f_p)\n"
        "12:   S_t = S_t U {f_p}\n"
        "13: If S_{t-1} is provided:\n"
        "14:   Delta_NEW = { f in S_t | Hash(f) not in Hash(S_{t-1}) }\n"
        "15:   Delta_FIXED = { f in S_{t-1} | Hash(f) not in Hash(S_t) }\n"
        "16:   Delta_UNCHANGED = { f in S_t | Hash(f) in Hash(S_{t-1}) }\n"
        "17: Return S_t, <Delta_NEW, Delta_FIXED, Delta_UNCHANGED>"
    )

    p_3c_danger = doc.add_paragraph(style='IEEE Paragraph')
    r_dang = p_3c_danger.add_run("Plain-English Danger Engine and Executive Posture: ")
    r_dang.font.bold = True
    p_3c_danger.add_run(
        "The DangerEngine maps technical findings into 4 Real-World Business Threat Categories: "
        "(i) Customer & Database Theft (SQLi, directory exposure, credential leaks); "
        "(ii) Account Hijacking & Auth Bypass (JWT weaknesses, brute-force, missing cookie flags); "
        "(iii) Phishing, XSS & Brand Defacement (CORS wildcards, XSS, open redirects); and "
        "(iv) Full Server Takeover & RCE (remote command injection, SSTI). "
        "The engine computes an Executive Security Posture Grade (A+ to F, 0–100 score) and provides non-technical explanations of what is broken, what an attacker can achieve, business liability, and estimated fix time."
    )

    p_3c_recipes = doc.add_paragraph(style='IEEE Paragraph')
    r_recip = p_3c_recipes.add_run("Multi-Framework Fix Recipes and Dev Tickets: ")
    r_recip.font.bold = True
    p_3c_recipes.add_run(
        "The RecipeEngine generates drop-in code patches for Node.js/Express (parameterized queries, Helmet.js, express-validator), Python/FastAPI/Django (SQLAlchemy ORM, Pydantic schemas, Talisman headers), Nginx server hardening directives, and Cloudflare/AWS WAF virtual patching rules. It also exports 1-click Markdown tickets pre-formatted for Jira, Linear, and GitHub Issues."
    )

    p_3c_delta = doc.add_paragraph(style='IEEE Paragraph')
    r_delt = p_3c_delta.add_run("Set-Theoretic Delta Differential Auditing: ")
    r_delt.font.bold = True
    p_3c_delta.add_run(
        "To track regressions between software builds [14], the DeltaAnalyzer computes an identity hash H(f) over each finding. Findings between current scan S_t and baseline S_{t-1} are partitioned into three disjoint sets: "
        "Delta_NEW = { f in S_t | H(f) not in H(S_{t-1}) }, "
        "Delta_FIXED = { f in S_{t-1} | H(f) not in H(S_t) }, and "
        "Delta_UNCHANGED = { f in S_t | H(f) in H(S_{t-1}) }."
    )

    p_sub3d = doc.add_paragraph("D.  Autonomous AI Remediation via Model Context Protocol (MCP) and CI/CD Delivery", style='IEEE Heading 2')
    p_3d = doc.add_paragraph(style='IEEE Paragraph')
    p_3d.add_run(
        "AutoSecAudit 2.0 embeds a standard JSON-RPC 2.0 stdio Model Context Protocol (MCP) Server (mcp_server.py), bridging dynamic vulnerability scanning directly into modern AI developer tools (Cursor, Claude Code, Antigravity) [15]. Table II lists the MCP tools exposed for autonomous AI remediation."
    )

    # TABLE II
    doc.add_paragraph("TABLE II   AUTOSECAUDIT 2.0 MCP TOOLS FOR AUTONOMOUS AI REMEDIATION", style='IEEE Table Caption')
    tbl2 = doc.add_table(rows=6, cols=3)
    tbl2.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl2)

    t2_data = [
        ["MCP Tool Name", "Arguments", "Description and Agent Capability"],
        ["autosec_scan", "target_url, profile, crawl", "Triggers automated scans; returns executive threat summary, posture grade, and finding counts."],
        ["autosec_get_findings", "scan_id, severity, lens", "Retrieves enriched findings with Plain-English Danger assessments, CVSS, and technical traces."],
        ["autosec_get_fix_recipe", "finding_id, framework", "Returns drop-in code fix patches (nodejs, python, nginx, waf) for automated source file edits."],
        ["autosec_verify_fix", "target_url, scanner_name, param", "Runs targeted single-scanner re-verification to confirm if an AI fix resolved the vulnerability."],
        ["autosec_list_scanners", "none", "Lists all 19 dynamic scanner plugins, attack descriptions, and profile memberships."]
    ]

    for r_idx, row_data in enumerate(t2_data):
        row = tbl2.rows[r_idx]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.text = val
            p_cell = cell.paragraphs[0]
            p_cell.style = 'IEEE Table Cell'
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            if r_idx == 0:
                set_cell_shading(cell, "E2E8F0")
                p_cell.runs[0].font.bold = True
                p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER
            else:
                if c_idx == 0:
                    p_cell.runs[0].font.bold = True

    p_3d_gate = doc.add_paragraph(style='IEEE Paragraph')
    p_3d_gate.add_run(
        "For continuous integration pipelines, AutoSecAudit 2.0 enforces build gating via the --fail-on parameter (Low, Medium, High, Critical). If any finding meets or exceeds threshold theta, the process returns exit code 1 to halt risky releases. Results are delivered via Server-Sent Events (SSE) to a real-time web dashboard and compiled into ReportLab executive PDF reports."
    )

    doc.add_paragraph() # Spacing

    # ---------------------------------------------------------------------------
    # SECTION IV. EXPERIMENTAL EVALUATION AND RESULTS
    # ---------------------------------------------------------------------------
    p_sec4 = doc.add_paragraph("IV.  EXPERIMENTAL EVALUATION AND RESULTS", style='IEEE Heading 1')

    p_eval = doc.add_paragraph(style='IEEE Paragraph')
    p_eval.add_run(
        "We evaluated AutoSecAudit 2.0 on an 8-core host (16 GB RAM) running Ubuntu 22.04 LTS against a containerized instance of the OWASP Juice Shop benchmark. Our evaluation answers four research questions: "
        "RQ1 (Latency & Concurrency), RQ2 (Accuracy & Alert Noise Reduction), RQ3 (Delta Regression Tracking Fidelity), and RQ4 (System Reliability & Test Suite Coverage)."
    )

    p_sub4a = doc.add_paragraph("A.  Concurrency and Execution Latency (RQ1)", style='IEEE Heading 2')
    p_4a = doc.add_paragraph(style='IEEE Paragraph')
    p_4a.add_run(
        "We measured total audit latency across worker thread counts (k in {1, 2, 4, 8, 16}). As presented in Table III and Fig. 2, increasing concurrency from sequential execution (k=1) to k=8 reduced scan time from 184.2 s to 64.8 s—a 64.8% reduction in latency (2.84x speedup). Beyond 8 threads, performance leveled off due to network socket I/O serialization on the target host."
    )

    # TABLE III
    doc.add_paragraph("TABLE III   AUDIT LATENCY ACROSS CONCURRENCY CONFIGURATIONS", style='IEEE Table Caption')
    tbl3 = doc.add_table(rows=6, cols=4)
    tbl3.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl3)

    t3_data = [
        ["Worker Threads (k)", "Scan Duration (s)", "Speedup", "CPU Utilization (%)"],
        ["1 (Sequential)", "184.2 s", "1.00x", "14.2%"],
        ["2", "102.5 s", "1.80x", "27.8%"],
        ["4", "71.4 s", "2.58x", "51.3%"],
        ["8 (Optimal)", "64.8 s", "2.84x", "78.4%"],
        ["16", "66.1 s", "2.79x", "82.1%"]
    ]

    for r_idx, row_data in enumerate(t3_data):
        row = tbl3.rows[r_idx]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.text = val
            p_cell = cell.paragraphs[0]
            p_cell.style = 'IEEE Table Cell'
            p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            if r_idx == 0:
                set_cell_shading(cell, "E2E8F0")
                p_cell.runs[0].font.bold = True
            elif r_idx == 4:
                set_cell_shading(cell, "F0FDF4")
                p_cell.runs[0].font.bold = True

    # INSERT FIGURE 2
    if os.path.exists('paper/figures/fig2_latency.png'):
        p_fig2 = doc.add_paragraph()
        p_fig2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_fig2.paragraph_format.space_before = Pt(8)
        p_fig2.paragraph_format.space_after = Pt(4)
        run_fig2 = p_fig2.add_run()
        run_fig2.add_picture('paper/figures/fig2_latency.png', width=Inches(4.5))
        p_cap2 = doc.add_paragraph("Fig. 2.  Audit execution latency and relative speedup across worker thread allocations (k in {1, 2, 4, 8, 16}).", style='IEEE Figure Caption Multi-Lines')
        p_cap2.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    p_sub4b = doc.add_paragraph("B.  Detection Accuracy and Noise Reduction (RQ2)", style='IEEE Heading 2')
    p_4b = doc.add_paragraph(style='IEEE Paragraph')
    p_4b.add_run(
        "To evaluate detection accuracy, we audited the benchmark application and cross-referenced findings against ground-truth challenge definitions [10]. Table IV details results across all 19 plugins grouped into major vulnerability classifications."
    )

    # TABLE IV
    doc.add_paragraph("TABLE IV   VULNERABILITY DETECTION AND CORRELATION METRICS ACROSS 19 PLUGINS", style='IEEE Table Caption')
    tbl4 = doc.add_table(rows=7, cols=5)
    tbl4.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl4)

    t4_data = [
        ["Vulnerability Class (Active Plugins)", "True Positives (TP)", "False Positives (FP)", "Raw Alerts", "Correlated Findings"],
        ["Injection (SQLi, CmdInj, SSTI, OpenRedirect)", "8", "0", "14", "8"],
        ["Cross-Site Scripting (XSSScanner, CSRFScanner)", "12", "1", "19", "13"],
        ["Misconfig & Recon (Misconfig, DirBrute, Nikto, Nmap, TLS, Secrets)", "15", "0", "26", "15"],
        ["Access & Traversal (BOLAIdor, Auth, PathTrav, SSRF)", "6", "0", "9", "6"],
        ["API & Tokens (APIAbuse, JWT, CORS)", "5", "0", "8", "5"],
        ["Total / Summary", "46", "1", "76", "47 (-38.2% Noise)"]
    ]

    for r_idx, row_data in enumerate(t4_data):
        row = tbl4.rows[r_idx]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.text = val
            p_cell = cell.paragraphs[0]
            p_cell.style = 'IEEE Table Cell'
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            if r_idx == 0:
                set_cell_shading(cell, "E2E8F0")
                p_cell.runs[0].font.bold = True
                p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER
            elif r_idx == 6:
                set_cell_shading(cell, "FEF3C7")
                p_cell.runs[0].font.bold = True
                p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER
            else:
                if c_idx > 0:
                    p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER

    p_4b_disc = doc.add_paragraph(style='IEEE Paragraph')
    p_4b_disc.add_run(
        "Across 76 raw tool alerts, the intelligence layer consolidated findings into 47 distinct actionable issues (46 TP + 1 FP), achieving a 38.2% reduction in duplicate alert volume (Fig. 3). Evaluated against 52 verified dynamic challenge vulnerabilities in benchmark scope, AutoSecAudit 2.0 achieved 97.9% precision (46/47), 88.5% recall (46/52), and an F1-score of 92.9%."
    )

    # INSERT FIGURE 3
    if os.path.exists('paper/figures/fig3_noise_reduction.png'):
        p_fig3 = doc.add_paragraph()
        p_fig3.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_fig3.paragraph_format.space_before = Pt(8)
        p_fig3.paragraph_format.space_after = Pt(4)
        run_fig3 = p_fig3.add_run()
        run_fig3.add_picture('paper/figures/fig3_noise_reduction.png', width=Inches(4.5))
        p_cap3 = doc.add_paragraph("Fig. 3.  Raw tool alerts vs. correlated actionable findings across major vulnerability categories (-38.2% alert reduction).", style='IEEE Figure Caption Multi-Lines')
        p_cap3.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    p_sub4c = doc.add_paragraph("C.  Set-Theoretic Delta Regression Tracking (RQ3)", style='IEEE Heading 2')
    p_4c = doc.add_paragraph(style='IEEE Paragraph')
    p_4c.add_run(
        "We validated regression tracking across a three-phase synthetic release sequence (Fig. 4): "
        "(1) Build v1.0 (Baseline): Initial scan identified 47 correlated vulnerabilities; "
        "(2) Build v1.1 (Patch & New): 10 misconfigurations were patched and 3 new API access flaws were introduced. The delta analyzer correctly reported 3 Delta_NEW, 10 Delta_FIXED, and 37 Delta_UNCHANGED issues (47 - 10 + 3 = 40 active issues); and "
        "(3) Build v1.2 (Hardened Release): 14 vulnerabilities were resolved. The delta analyzer classified 0 Delta_NEW, 14 Delta_FIXED, and 26 Delta_UNCHANGED issues (40 - 14 = 26 active issues). "
        "Across all transitions, the delta engine achieved 100% classification fidelity against release ground truths."
    )

    # INSERT FIGURE 4
    if os.path.exists('paper/figures/fig4_delta_diff.png'):
        p_fig4 = doc.add_paragraph()
        p_fig4.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_fig4.paragraph_format.space_before = Pt(8)
        p_fig4.paragraph_format.space_after = Pt(4)
        run_fig4 = p_fig4.add_run()
        run_fig4.add_picture('paper/figures/fig4_delta_diff.png', width=Inches(4.5))
        p_cap4 = doc.add_paragraph("Fig. 4.  Vulnerability lifecycle tracking across sequential software builds via set-theoretic delta diffing.", style='IEEE Figure Caption Multi-Lines')
        p_cap4.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    p_sub4d = doc.add_paragraph("D.  System Reliability and Test Suite Coverage (RQ4)", style='IEEE Heading 2')
    p_4d = doc.add_paragraph(style='IEEE Paragraph')
    p_4d.add_run(
        "AutoSecAudit 2.0 maintains high operational stability verified by an automated test suite of 165 unit and integration tests. The test suite exercises all 19 scanner plugins, the Statistical Timing Engine and dual-baseline calibration, deep recursive JSON fuzzing, the Plain-English Danger Engine, multi-framework code fix recipes, the Model Context Protocol (MCP) server tools, and CI/CD exit-code gating."
    )

    # ---------------------------------------------------------------------------
    # SECTION V. DISCUSSION AND DEPLOYMENT CONSIDERATIONS
    # ---------------------------------------------------------------------------
    p_sec5 = doc.add_paragraph("V.  DISCUSSION AND DEPLOYMENT CONSIDERATIONS", style='IEEE Heading 1')

    p_disc1 = doc.add_paragraph(style='IEEE Paragraph')
    p_disc1.add_run(
        "Deploying dynamic security scanning into production CI/CD workflows introduces critical engineering considerations: "
        "(1) Dynamic Client-Side Single Page Applications (SPAs): While regex extraction uncovers embedded REST API endpoints, complex client-side applications benefit from pairing the crawler with headless browser drivers (e.g., Playwright) for full DOM event execution; "
        "(2) Air-Gapped Environments: When scanning within networks without external internet access, AutoSecAudit 2.0 falls back to an embedded offline CVE/CWE dictionary to prevent external API timeouts; and "
        "(3) Enterprise Authentication: Complex identity provider flows (such as SAML 2.0 or mTLS) require pre-authenticated session tokens injected via environment configuration."
    )

    # ---------------------------------------------------------------------------
    # SECTION VI. CONCLUSION AND FUTURE WORK
    # ---------------------------------------------------------------------------
    p_sec6 = doc.add_paragraph("VI.  CONCLUSION AND FUTURE WORK", style='IEEE Heading 1')

    p_conc = doc.add_paragraph(style='IEEE Paragraph')
    p_conc.add_run(
        "AutoSecAudit 2.0 provides an extensible, low-latency vulnerability auditing framework and autonomous AI remediation platform for modern DevSecOps pipelines. By orchestrating parallel execution across 19 specialized scanner plugins, the system reduces scan latency by 64.8% (2.84x speedup) over sequential auditing. The post-processing pipeline mitigates developer friction by eliminating 38.2% of duplicate alerts via compound-key deduplication, automatically generating compliance metadata, translating findings into plain-English business danger assessments with executive posture grades, and tracking regression lifecycles with 100% classification fidelity. Furthermore, through standard Model Context Protocol (MCP) integration, AutoSecAudit 2.0 bridges dynamic security auditing directly into AI coding workflows, closing the loop from vulnerability detection to verified code remediation. Future work will investigate local Large Language Model (LLM) agents for automated patch synthesis and distributed multi-node scanning architectures."
    )

    # ---------------------------------------------------------------------------
    # ACKNOWLEDGMENT
    # ---------------------------------------------------------------------------
    p_ack_hdr = doc.add_paragraph("ACKNOWLEDGMENT", style='IEEE Heading 1')
    p_ack = doc.add_paragraph(style='IEEE Paragraph')
    p_ack.add_run(
        "This research was conducted as part of the AutoSec Security Engineering Initiative in the Department of Computer Science and Engineering at Don Bosco Institute of Technology, Bangalore. The authors express sincere gratitude to the faculty mentor Ms. Ranjitha R, department leadership, and the open-source security community for technical guidance and resources."
    )

    # ---------------------------------------------------------------------------
    # REFERENCES
    # ---------------------------------------------------------------------------
    p_ref_hdr = doc.add_paragraph("REFERENCES", style='IEEE Heading 1')

    references = [
        "[1] G. F. Lyon, Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Vulnerability Scanning. Insecure.Com LLC, 2009.",
        "[2] C. Sullo and D. Lodge, \"Nikto Web Server Scanner,\" Open Source Security Tool, 2023. Available: https://cirt.net/Nikto2",
        "[3] ProjectDiscovery, \"Nuclei: Fast and Customizable Vulnerability Scanner Based on Simple YAML DSL,\" 2024. Available: https://github.com/projectdiscovery/nuclei",
        "[4] OWASP Foundation, \"OWASP Zed Attack Proxy (ZAP),\" 2024. Available: https://www.zaproxy.org/",
        "[5] OWASP Foundation, \"OWASP DefectDojo: Vulnerability Management Orchestration,\" 2024. Available: https://www.defectdojo.org/",
        "[6] OWASP Top 10 Team, \"OWASP Top 10: 2021 The Ten Most Critical Web Application Security Risks,\" OWASP Foundation, 2021. Available: https://owasp.org/Top10/",
        "[7] PCI Security Standards Council, Payment Card Industry Data Security Standard (PCI-DSS): Requirements and Testing Procedures, Version 4.0, 2022.",
        "[8] National Institute of Standards and Technology (NIST), \"National Vulnerability Database (NVD) REST API v2.0,\" U.S. Department of Commerce, 2023.",
        "[9] M. Myrbakken and R. Colomo-Palacios, \"DevSecOps: A Multivocal Literature Review,\" in Communications in Computer and Information Science, vol. 770, Springer, 2017, pp. 17–29.",
        "[10] B. Bau, F. Bursztein, D. Gupta, and J. C. Mitchell, \"State of the Art: Automated Black-Box Web Application Vulnerability Testing,\" in Proc. 31st IEEE Symposium on Security and Privacy (S&P '10), 2010, pp. 332–345.",
        "[11] A. Doupé, M. Cova, and G. Vigna, \"Enemy of the State: A State-Aware Black-Box Web Vulnerability Scanner,\" in Proc. 21st USENIX Security Symposium (USENIX Security '12), 2012, pp. 523–538.",
        "[12] V. Atlidakis, P. Godefroid, and M. Polishchuk, \"RESTler: Stateful REST API Fuzzing,\" in Proc. 41st IEEE/ACM International Conference on Software Engineering (ICSE '19), 2019, pp. 748–758.",
        "[13] B. Johnson, Y. Song, E. Murphy-Hill, and R. Bowdidge, \"Why Don't Software Developers Use Static Analysis Tools to Find Bugs?\" in Proc. 35th IEEE/ACM International Conference on Software Engineering (ICSE '13), 2013, pp. 672–681.",
        "[14] C. Vassallo, S. Proksch, H. C. Gall, and M. Di Penta, \"Continuous Code Quality: How Developers Manage Technical Debt in CI/CD,\" IEEE Transactions on Software Engineering (TSE), vol. 46, no. 8, pp. 838–855, 2020.",
        "[15] Anthropic, \"Model Context Protocol (MCP) Specification: Open Standard for Seamless AI Application Integration,\" 2024. Available: https://modelcontextprotocol.io"
    ]

    for ref in references:
        p_r = doc.add_paragraph(ref, style='IEEE Reference Item')
        p_r.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    # ---------------------------------------------------------------------------
    # BIOGRAPHY
    # ---------------------------------------------------------------------------
    doc.add_paragraph("BIOGRAPHY", style='IEEE Heading 1')
    p_bio = doc.add_paragraph(style='IEEE Paragraph')
    p_bio.add_run(
        "The authors are undergraduate research scholars and faculty mentors in the Department of Computer Science and Engineering at Don Bosco Institute of Technology (DBIT), Bangalore, affiliated with Visvesvaraya Technological University (VTU), Belagavi, Karnataka, India. Their research focuses on automated vulnerability assessment, DevSecOps engineering, intelligent security orchestration, and agentic AI remediation systems."
    )

    # Save to both target locations
    doc.save(output_path)
    doc.save(root_output_path)
    print(f"Successfully generated publication-ready research paper at:\n- {output_path}\n- {root_output_path}")

if __name__ == '__main__':
    build_paper()
