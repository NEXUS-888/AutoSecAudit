# Change Log — revised paper vs. original (9-page PDF → 11-page PDF)

Original files are preserved in `paper/revision_audit/original/` (DOCX, PDF, build script, plot script). Evidence column references rows of `01_claim_verification_matrix.md` (CVM).

| # | Location (original) | Change | Reason | Evidence |
|---|---|---|---|---|
| 1 | Title | "Autonomous AI Remediation" → "AI-Assisted Remediation Guidance" (keyword likewise) | Evaluation supports recipe delivery only | CVM 12b |
| 2 | Abstract | Rewritten (shorter, hedged): removed "false alarms are eliminated", "Gaussian bounds", "compound-key deduplication", "apply code patches", "100 % fidelity"; added scope statement for MCP, "preliminary, single-configuration, author-reported, unreplicated" | A, C, D principal weaknesses | CVM 6a, 8, 11, 12b, 23 |
| 3 | I. Introduction | Shift-left cite [10]→[9]; Johnson [13] / Bau [10] claim made proportionate; "no standardized agentic interface" replaced (MCP integrations exist for Burp/ZAP); "scanners evaluate in isolation" softened; contribution/preliminary-evaluation sentence added; [14] removed | Misattributed or overstated citations | CVM 26–27 |
| 4 | II intro + II.A–D | Table scope statement ("built-in per public docs, accessed Oct 2026"); Nuclei/ZAP/Burp/DefectDojo descriptions corrected; "no superiority claim, no benchmark"; MCP described as not a contribution; II.D retitled | Defensible competitor comparison | CVM 26a–d |
| 5 | Table I | Rebuilt: columns now Nmap/Nikto/Nuclei, ZAP, DefectDojo, AutoSecAudit; 12 dimensions re-worded to "built-in vs add-on/integration"; unverifiable cells set to "Not assessed"; added honest AutoSecAudit qualifiers (OpenAPI not wired, benchmark-tuned, heuristic) | Same | CVM 4c, 26 |
| 6 | III intro, Fig. 1 | "Autonomous AI Remediation" stage renamed; Fig. 1 text regenerated (recursive crawler, scope guardrail, k configurable, cross-referencing, ID-based delta, 4 MCP tools; removed "Key host+port+URI+CWE" and "−38.2 %") | Figure contradicted code | CVM 4, 8, 11, 12 |
| 7 | III-A.1 | "Target Safety Gate" → "Scope Guardrail": actual allowlist (names + prefixes + loopback), lexical-matching bypass, not an authorization control, Juice Shop acceptance, probe details | Principal weakness B | CVM 3 |
| 8 | III-A.2 | BFS → recursive depth-first, D_max=3, 20-page budget; bundles claim removed | Contradicted | CVM 4a, 4b |
| 9 | III-A.3 | OpenAPI: JSON only, no YAML/$ref/body schemas; extracted list not consumed by plugins | Contradicted/partial | CVM 4c |
| 10 | III-A.4 | Authenticator described by actual strategies; real-mode only | Precision | CVM 5 |
| 11 | Algorithm 1 | Rewritten as depth-first bounded `Crawl(u,d)` with page budget; OpenAPI shown as separate importer | Matches code | CVM 4 |
| 12 | III-B (tuple) | `F` redefined to real `Finding` fields; no `endpoint` field; confidence is a heuristic label | Matches `core/models.py` | CVM 8 |
| 13 | III-B (plugin list) | All nine plugin descriptions corrected (stored XSS, weak HMAC, verb tampering, SSTI engines, TLS ciphers, 50 paths, metadata probes opt-in…) | Per-plugin code check | CVM 24 |
| 14 | III-B (profiles) | Actual member lists; `api` content corrected; `recon` "passive" → "reconnaissance-oriented, non-exploitative, not passive"; thread default 4 vs evaluation k=8 | Principal weakness E | CVM 2 |
| 15 | III-B (precision) | New formula text: `T_delay ≥ μ + 0.70τ`, control probe `≤ μ + 0.35τ`, m=2, σ unused, "medium" still reported, SQLi/CmdInj only; baseline check scoped to SQLi; SPA/dev-server filter added; politeness numbers; fuzzer edge cases | Principal weakness H | CVM 6, 7 |
| 16 | III-C intro, Algorithm 2 | Rewritten to implemented pipeline (host:port cross-reference, CVE-only enrichment, keyword mapping, ID-based delta); compound-key merge declared not implemented; refs [6]–[8] cited | Contradicted | CVM 8, 9, 11 |
| 17 | III-C Danger/Recipe/Delta paragraphs | Danger: keyword categories, score formula, five grades, "not evaluated"; Recipes: 7 classes, static templates, none for XSS/CmdInj/…; Delta: ID rule, positional-ID, shared-ID, empty-ID edge cases | Principal weaknesses C, D | CVM 9c, 10, 11 |
| 18 | III-D + Table II | Retitled; four remediation levels (generate / expose / apply / verify); Table II rebuilt from `TOOLS_MANIFEST` (4 tools, real argument names) with a limitations column; "autosec_list_scanners" removed; CI paragraph adds exit-1-on-unreachable | Contradicted | CVM 12, 12b, 13 |
| 19 | IV intro | Setup stated as author-reported; run mode, Juice Shop tag not recorded; "Evidence status" paragraph; RQ names adjusted ("Fidelity" → "Behavior", "Reliability" → "Status") | Methodology honesty | CVM 22, 25 |
| 20 | IV-A | "Optimal" → "best observed"; removed unsupported "socket serialization" cause; makespan bound; single-run/mean unrecorded; coincidence of 64.8 % / 64.8 s noted. Table III/IV captions "(author-reported)" | Evidence-proportionate | CVM 16–17 |
| 21 | IV-B | TP/FP/FN/P/R/F1 definitions; FN = 6; class grouping vs Sec. III-B domains clarified; labelling/dup-detection undocumented; Juice-Shop-specific plugin inputs; "not eliminated" statement; Correlator reproducibility caveat; ground truth re-cited [10]→[15]; "Correlated" → "Consolidated"; "(−38.2 % Noise)" → "(38.2 % fewer than raw)" | Principal weakness A, G | CVM 18–20, 27b |
| 22 | IV-C | "100 % fidelity" removed; synthetic sequence re-run with repo analyzer; claim limited to set arithmetic | Principal weakness D | CVM 21 |
| 23 | IV-D | 165 collected / 164 passed / 1 non-idempotent failure / 161 by unittest; mock-mode caveat; no test for 47-40-26 or 76→47 | Verified by running both runners | CVM 14 |
| 24 | V Discussion | Offline-CVE-dictionary claim removed (none exists; enrichment silently skipped); "environment configuration" → `--headers`; mock default, TLS verification off; new Limitations and Follow-up paragraphs | Contradicted / methodology | CVM 9a, A–C |
| 25 | VI Conclusion | Rewritten to measured wording; closed-loop remediation as future work | Principal weaknesses A, C | — |
| 26 | References | [10] author initials fixed; [14] Vassallo removed (unverifiable) and MCP renumbered [14]; added [15] Juice Shop, [16] ZAP Automation Framework, [17] Burp MCP, [18] ZAP MCP add-on, [19] DefectDojo docs; "PCI-DSS" → "PCI DSS" | Reference integrity | CVM 27 |
| 27 | Layout | Embedded line breaks split into left-aligned paragraphs (no stretched justified lines); tables keep rows together, fixed column widths; Fig. 4 y-axis/legend overlap fixed | Rendering review | page images |
| 28 | Figures 2–4 | Data unchanged; label text only ("Best observed", "Consolidated"); regenerated | Consistency | `generate_paper_plots.py` |
| 29 | Preserved unchanged | Authors, affiliation, corresponding-author mark, emails, acknowledgment, biography, Algorithm/figure/table inventory, all numeric values (184.2, 102.5, 71.4, 64.8, 66.1; 76/47/46/1/52; 47→40→26) | Mandatory rule | `validate_final.py` |

## Files created or modified by this audit
- Modified (paper tooling only): `build_ijarcce_publication_suite.py`, `generate_paper_plots.py`; regenerated `paper/figures/fig1–4.*`, `paper/AutoSecAudit_Research_Paper_IJARCCE.{docx,pdf}` and the root copies.
- Created: `paper/revision_audit/` (this folder: matrix, change log, outstanding issues, validation summary, `verify_metrics.py`, `verify_delta_sequence.py`, `validate_final.py`, `validate_final_output.txt`, `original/`).
- **Application source (`core/`, `plugins/`, `intelligence/`, `ui/`, `mcp_server.py`, `main.py`, `config.py`) was not modified.**
- Side effect: running the test suites wrote new mock scan/report files under `data/reports/` (git-ignored).
