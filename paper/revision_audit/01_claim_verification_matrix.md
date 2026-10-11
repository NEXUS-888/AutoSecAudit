# Claim Verification Matrix — AutoSecAudit IJARCCE paper

Audit date: 2026-10-11. Source of truth: repository working tree (branch `main`, uncommitted changes included).
Status key: **Verified** (code/test evidence) · **Partial** · **Not verified** (evidence unavailable) · **Contradicted** (code shows otherwise).
"Experimental evidence" means raw logs/fixtures that would let a reader reproduce a measurement. **None exist in the repository** for the evaluation numbers; the saved scans in `data/reports/` are mock-mode output (all 19 plugins finish within one second, raw output contains "Mock Output", 51 findings, not 76/47).

## A. Implementation claims

| # | Paper claim (original) | Implementation evidence | Experimental evidence | Status | Action taken |
|---|---|---|---|---|---|
| 1 | 19 scanner plugins | `Engine.load_plugins()` loads exactly 19 `BaseScanner` subclasses (mock plugin excluded); class list matches the paper's inventory | n/a | **Verified** | Kept; inventory re-described per plugin (see 24) |
| 2a | Profiles `full`/`owasp`/`api`/`recon` = 19/11/7/6 plugins | `config.SCAN_PROFILES`; loaded each profile: 19, 11, 7, 6; all names resolve | `test_scan_profiles.py` (4 tests) | **Verified** (counts) | Kept; member lists now printed in the paper |
| 2b | `api` = "7 API-tailored plugins: BOLA/IDOR, JWT, CORS, rate limits" | Also includes `AuthScanner`, `SQLiScanner`, `XSSScanner`; no standalone rate-limit plugin | — | **Partial** | Replaced by the actual member list |
| 2c | `recon` = "6 passive reconnaissance plugins" | `NmapPlugin` runs `nmap`; `NiktoPlugin` runs `nikto`; `DirBruteScanner`, `MisconfigScanner`, `SecretExposureScanner` send active HTTP probes. Config text says "Passive & Non-Intrusive" | — | **Contradicted** | Re-labelled "reconnaissance-oriented, non-exploitative, not passive" |
| 3 | Targets strictly validated against RFC 1918, localhost, sandbox testbeds; "unauthorized external domains are aborted immediately" | `core/utils.is_target_allowed`: **lexical** match on hostname prefixes (`10.`, `172.16–31.`, `192.168.`), `127.`, a name list (`localhost`, `juice-shop`, `dvwa`, `hackthebox`, …) and suffix match. Probed: `10.example.com`, `192.168.attacker.net`, `127.evil.org`, `foo.hackthebox` → **allowed**; `8.8.8.8`, `example.com`, `172.32.0.1` → rejected. No DNS resolution, no ownership/authorization check. Juice Shop passes as `localhost`/`juice-shop`. `audit/BACKLOG.md` AUD-04 already tracks this defect | — | **Partial** | Section III-A rewritten: guardrail not authorization; lexical matching and bypass disclosed; Juice Shop setup explained; listed as limitation |
| 4a | Breadth-first crawler with FIFO queue (Alg. 1) | `WebCrawler._crawl_page` is **recursive depth-first**, `max_depth=3`, `max_pages=20`, same-host only | `test_crawler*.py` | **Contradicted** | Text, Algorithm 1 and Table I corrected |
| 4b | JS route extraction from inline scripts **and referenced bundles** | Regex applied to HTML text of visited pages only; non-HTML responses (JS files) are not parsed | `test_crawler_js_extractor.py` (3) | **Partial** | Bundles claim removed; limitation added |
| 4c | OpenAPI 2.0/3.0 **JSON/YAML**, payload schemas, registered in endpoint pool | `OpenAPIImporter` uses `json.load`/`resp.json()` only; no YAML, `$ref`, `requestBody`; output stored in `engine.crawler_data` which **nothing reads** (grep) | `test_enterprise.py` covers importer | **Partial** | Rewritten; "not yet consumed by plugins" disclosed |
| 5 | Authenticator discovers login forms, captures cookies/JWT, injects headers into worker threads | `core/authenticator.py`: HTML-form, JSON-API, blind-form strategies; CSRF token extraction; engine passes headers/cookies to crawler and `plugin.set_auth()`; runs only when `not mock_mode` | `test_auto_authenticator.py` (9) | **Verified** (propagation reach per plugin not audited) | Kept with qualifiers |
| 6a | Timing: confirmed only if `T ≥ μ + 3σ + 0.8τ` across two stages; "dual-baseline"; "Gaussian bounds" | `core/timing.py`: threshold `μ + 0.70·τ` (`min_delay_ratio`); σ computed but **unused**; phase 2 control probe `≤ μ + 0.35·τ` gives "high", otherwise still **reported as "medium"**; `BaseScanner` uses `baseline_samples=2`; used by SQLi and CmdInj only | `test_timing_engine.py` (3) | **Contradicted** | Formula, thresholds, m=2, medium-confidence behavior and "heuristic" caveat rewritten |
| 6b | Baseline differential (status change or >20% length) before reporting injection | `_verify_against_baseline` exists (status/length rules, graded high/medium/low, minor change still flagged "low"); only `sqli_plugin` calls `_get_baseline` | `test_verification.py` | **Partial** | Scoped to SQLi; grading described |
| 7a | Deep recursive JSON fuzzer | `core/fuzzer.py`; used via `_fuzz_json_body` by SQLi and CmdInj. Dotted-path scheme breaks on keys containing "."; empty containers have no leaf | `test_json_fuzzer.py` (3) | **Verified** | Kept; edge cases disclosed |
| 7b | Exponential backoff on 429/503 | `PolitenessEngine.handle_response_status`: sleep `min(2^(n−1), 8)` s; response **not retried** (`max_retries_on_429` unused); jitter 0–20 ms; per-plugin instance | — (no direct test) | **Verified** | Described precisely |
| 8 | Compound-key dedup `⟨host, port, endpoint, CWE⟩` + `MergeFindings` (Alg. 2) | `Correlator` groups by `host:port` only, never merges/removes; CLI calls only `link_related` (adds "Related findings" reference); `Finding` has **no `endpoint` field**; engine/UI/MCP never call `Correlator` | — | **Contradicted** | Algorithm 2 and III-C rewritten; consolidation flagged non-reproducible (see 18) |
| 9a | Live CVSS v3.1 from NVD and CIRCL | `Enricher`: only findings with `cve_id`; prefers v3.1, falls back to v3.0/v2.0; 2 s timeout; silent skip on failure; CIRCL fallback | `test_intelligence.py` | **Partial** | Qualified |
| 9b | Deterministic OWASP/CWE/PCI-DSS mapping | `ComplianceMapper`: keyword rules on title + small CWE/PCI table, severity fallback; deterministic | tests exist | **Partial** | "keyword rules" stated |
| 9c | Business-risk grading A+ to F, 0–100 | `calculate_security_posture`: score `100−(25C+12H+5M+1L)` clamped to [10,100]; only grades F, D, C, B, A+; category by keyword; SSTI is not routed to "server takeover" | `test_danger_recipes.py` (8) | **Partial** | Five levels stated; SSTI example removed; "heuristic, not evaluated" |
| 10 | Recipes for Node.js, Python, Nginx, WAF; tickets for Jira/Linear/GitHub | `recipes.py`: 7 vulnerability classes + generic fallback; none for XSS, CmdInj, SSRF, SSTI, JWT, path traversal; one Markdown ticket template | `test_danger_recipes.py` | **Partial** | Coverage listed; "static templates, effectiveness untested" |
| 11 | Delta uses identity hash `H(f)`; NEW/FIXED/UNCHANGED | `DeltaAnalyzer` compares **`Finding.id` strings** (plugin counters like `AUTH-IDOR-002`); no hash. Probed: renumbering → true-present finding reported FIXED; same id/different finding → UNCHANGED; empty id dropped; `compare_with_dict` has no UNCHANGED | `test_silent_failures.py`, `test_intelligence.py` (trivial) | **Contradicted** (hash) / **Verified** (set logic) | III-C rewritten with rule and edge cases |
| 12 | MCP JSON-RPC server with **five** tools incl. `autosec_list_scanners`; args `target_url, scan_id, scanner_name…` | `mcp_server.TOOLS_MANIFEST` has **four** tools; no `autosec_list_scanners`; argument names differ (`target`, `report_id`, `finding_title`, `vulnerability_type`) | `test_mcp_server.py` (5) | **Contradicted** | Table II rebuilt from the manifest |
| 12b | MCP "apply code patches" and "verify remediation" | Server never edits files. `handle_verify_fix` always runs `Engine(mock_mode=True)` (simulated findings) and returns `verified: True`. `handle_get_findings` reads key `findings` but saved reports use `all_findings` → **0 findings, grade A+** on a real saved report (probed). `autosec_scan` defaults `mock=True` | `test_mcp_server.py` uses fixtures | **Contradicted** | Four-level remediation taxonomy added; limitations column in Table II; code defects listed (not fixed) |
| 13 | `--fail-on` low/medium/high/critical, exit 1 | `main.run_scan` loop over summary; also returns 1 for invalid/unreachable target | `test_enterprise.py` (critical), `test_target_reachability.py` | **Verified** | Exit-1-on-unreachable added |
| 14 | 165 tests; exercise all 19 plugins, timing, fuzzing, MCP, gating | `pytest --collect-only`: **165**; `pytest` run: 164 pass, **1 fail** (`test_auth.py`: user `testdev` already in persistent `data/users.db`); `run_tests.py` (unittest): 161 run, 0 fail. `CLAUDE.md` still says 120 | pytest/unittest output | **Partial** | RQ4 rewritten with exact counts, failure cause, mock-mode caveat |
| 15 | SSE dashboard, ReportLab PDF | `ui/app.py` `text/event-stream` route + `EventSource`; `reports/generator.py` uses ReportLab | `test_sse.py`, `test_pdf_download.py` (inside the 165) | **Verified** | Kept |

## B. Plugin-level descriptions (Section III-B)

| # | Original wording | Evidence | Status | Action |
|---|---|---|---|---|
| 24a | SQLi "error, boolean, statistical time-based" | error/tautology payloads + time-based; no dedicated boolean-differential routine | Partial | "error-based and tautology … plus time-based" |
| 24b | XSS "reflected **and stored**" | only reflected-payload reflection check; no stored workflow | Contradicted | "reflected XSS only" |
| 24c | JWT "Alg=None bypass, **weak HMAC secrets**" | Passive regex of JWTs seen in responses; flags `alg=none` header, missing/expired `exp`. No secret cracking, no forged-token test | Contradicted | Rewritten |
| 24d | APIAbuse "verb tampering"; Auth "credential brute-force" | APIAbuse: data exposure, mass assignment, pagination, GraphQL introspection, versioning, broken auth (no verb tampering). Auth: default creds, IDOR, weak-password registration, admin panels, enumeration, rate-limit | Partial | Rewritten from code |
| 24e | SSRF "cloud metadata 169.254.169.254" | Metadata probes only if `AUTOSEC_ENABLE_METADATA_PROBES=true` (default false) | Partial | Opt-in disclosed |
| 24f | SSTI "Jinja2, Twig, ERB" | Arithmetic probes `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `*{7*7}`; no engine fingerprinting | Partial | Probes listed |
| 24g | TLS "weak ciphers, cert expiry, HSTS" | cert validity/expiry, HSTS, obsolete TLS versions; no cipher-suite enumeration | Partial | Corrected |
| 24h | DirBrute "50+ curated paths" | `DIRECTORY_WORDLIST` has exactly 50 entries, incl. Juice-Shop-specific (`/ftp`, `/api/Challenges`…); `AuthScanner` hard-codes `admin@juice-sh.op` | Partial | "50-entry … includes Juice Shop-specific"; benchmark-tuning limitation added |
| 24i | Nikto/Nmap plugins | Wrappers around external executables (must be installed) | Verified | Dependency stated |

## C. Experimental claims

| # | Paper claim | Arithmetic re-check (`verify_metrics.py`) | Raw evidence | Status | Action |
|---|---|---|---|---|---|
| 16 | 184.2 s → 64.8 s, −64.8 %, 2.84× | 184.2/64.8 = 2.8426; (184.2−64.8)/184.2 = 64.82 % | none | Arithmetic **verified**; measurement **Not verified** | Kept, labelled author-reported/preliminary; "optimal" → "best observed"; causal claim ("socket serialization") removed; plugin-makespan bound noted |
| 17 | Table III speedups 1.80/2.58/2.79 | 1.797 / 2.580 / 2.787 — consistent | none | same | same |
| 18 | 76 raw → 47 (46 TP + 1 FP); Table IV rows | Column sums 46/1/76/47 ✓; each row consolidated = TP+FP ✓ | none; **Correlator cannot produce the merge** | Arithmetic verified; measurement Not verified; reproducibility **Contradicted** | Kept with explicit reproducibility caveat |
| 19 | Precision 97.9 %, recall 88.5 %, F1 92.9 %, GT = 52 | 97.87 % / 88.46 % / 92.93 % (FN = 6) ✓ | GT list and labels absent | Arithmetic verified; GT Not verified | Definitions of TP/FP/FN added; FN stated; benchmark-specific caveat |
| 20 | 38.2 % alert reduction | 29/76 = 38.16 % ✓ | none | same as 18 | Reworded "fewer alerts"; figure/table labels aligned |
| 21 | Delta 47 → 40 → 26, "100 % fidelity" | 47−10+3 = 40; 40−14 = 26 ✓. Synthetic ids fed to repo `DeltaAnalyzer` (`verify_delta_sequence.py`) → 3/10/37 and 0/14/26 | no repository fixture before this audit | Arithmetic and set logic **Verified** (synthetic only); "100 % fidelity" **Contradicted** as a general claim | Reworded to "reproduced on a synthetic sequence"; edge cases documented |
| 22 | 8-core, 16 GB, Ubuntu 22.04, Juice Shop container | repo shows Windows 11 dev host; `docker-compose.yml` pins `juice-shop:latest` | none | **Not verified** | Stated as author-reported; version not recorded |
| 23 | "False alarms are eliminated"; "guarantee reliable results" | Evaluation itself reports 1 FP; timing check reports medium-confidence hits | — | **Contradicted** | Replaced with "reduce"/"heuristic" wording throughout |
| 25 | Repeats/aggregation, who labelled, how duplicates identified | not documented anywhere | none | **Not verified** | Declared as missing; follow-up experiments listed |

## D. Related-work and reference claims

| # | Claim | Finding | Action |
|---|---|---|---|
| 26a | Table I: DefectDojo "Manual Triage", "DB Queries", "None" for scanners | DefectDojo has built-in deduplication and re-import that closes/reopens findings ([19], web-verified) | Cells rewritten |
| 26b | ZAP: "Custom Scripts" gating, "None" AI bridge, heavy/difficult in PR checks | ZAP has an Automation Framework with an `exitStatus` job and packaged baseline/API scans ([16]); ZAP MCP add-on (alpha, Apr 2026, [18]); Burp MCP Server extension ([17]) | Cells and prose rewritten; no superiority claim |
| 26c | Nuclei etc. "lack compliance tagging" | Nuclei templates carry classification metadata | Softened |
| 26d | Point scanners "Exit 0 regardless" | Indefensible as stated | Removed |
| 27a | "Johnson [13] and Bau [10] establish developers disable DAST scanners" | [13] studies static-analysis tools; [10] evaluates scanner accuracy/coverage | Intro reworded; claim made proportionate |
| 27b | Ground truth cited to [10] (Bau) | Wrong source; Juice Shop challenge catalog is the ground truth | Re-cited to new ref [15] |
| 27c | Ref [14] (Vassallo et al., "Continuous Code Quality: How Developers Manage Technical Debt in CI/CD", TSE 46(8) 2020) | Could **not** be verified by search; the closest known works are ASE 2018 / FSE 2020 papers by the same group | Removed from text and list (authors may restore if verified); MCP renumbered [15]→[14] |
| 27d | [10] authors "B. Bau, F. Bursztein" | Initials are J. Bau, E. Bursztein | Corrected |
| 27e | Refs [6], [7], [8] never cited in text | — | Cited in III-C |
| 27f | New refs [15]–[19] | Juice Shop, ZAP automation docs, Burp MCP, ZAP MCP add-on, DefectDojo docs; existence confirmed by web search 2026-10-11 | Added; authors must still confirm bibliographic formatting and access dates |
