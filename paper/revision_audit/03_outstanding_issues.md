# Outstanding Issues Report

## 1. Mandatory before IJARCCE submission (author action required)

| ID | Issue | Why it blocks | Smallest fix |
|---|---|---|---|
| M1 | **No raw data for Tables III–IV.** No logs, no run count, no aggregation method; `generate_paper_plots.py` hard-codes the numbers; git history (`f33b566` "rectify Table III FP/Correlated bookkeeping") shows the table was edited to make arithmetic agree. Saved scans in `data/reports/` are mock output (51 findings, 19 plugins in <1 s) | Experimental claims are unverifiable | Re-run the k-sweep (k ∈ {1,2,4,8,16}) ≥ 10× per setting against a pinned Juice Shop tag in real mode; save per-run JSON + wall-clock logs; report median and IQR; replace Tables III/IV/Figs. 2–3 |
| M2 | **76 → 47 consolidation is not reproducible.** Released `Correlator` only links by host:port; `Finding` has no `endpoint`; engine/UI/MCP never call it | The headline noise-reduction result has no code path | Either implement and unit-test the merge (`⟨host, port, normalized endpoint, CWE⟩`) and re-measure, or drop the 38.2 % claim and Fig. 3 |
| M3 | **Ground truth (52) and TP/FP labels absent**; matching procedure, duplicate identification, annotator(s) undocumented | Precision/recall cannot be audited | Publish the 52-item list (Juice Shop challenge IDs), per-finding labels, raw alerts; use two annotators and report agreement |
| M4 | Hardware/OS/Docker image: paper says Ubuntu 22.04, 8-core/16 GB; repository shows a Windows 11 developer host and `juice-shop:latest` | Reproducibility | Confirm real setup; record `docker inspect` image digest and `nproc`/RAM |
| M5 | **References**: confirm [10] correction; supply or replace the removed Vassallo et al. (TSE) entry; verify formatting/access dates of new [15]–[19]; confirm [2] Nikto URL (`cirt.net`) is still current; [3]–[5], [7], [8] lack authors/dates in IEEE style | Citation integrity | Check each on DBLP/publisher pages; fill missing fields |
| M6 | **Stale parallel manuscripts and slides** still contain the retracted claims: `paper/RESEARCH_PAPER.md`, `paper/main.tex`, `paper/references.bib`, `build_ijarcce_doc.py`, `AutoSecAudit_Paper.zip`, `Presentation/*` (e.g., SPEAKER_NOTES "compound deduplication algorithm … 97.9% precision") | Submitting or presenting inconsistent versions | Retire or sync them from the revised DOCX |
| M7 | Authors must approve the narrowed title, abstract and claims (title change drops "Autonomous") | Authorship responsibility | Review diff in `02_change_log.md` |

## 2. Code defects that make paper statements false if "fixed" in prose only
The task forbade modifying application code, so these are **reported, not fixed**. If any is fixed, update the listed paper text.

| ID | Defect | Paper location to update after a fix |
|---|---|---|
| C1 | `mcp_server.handle_get_findings` reads `data["findings"]`; saved reports use `all_findings` → returns 0 findings and grade A+ for real reports (reproduced) | Table II row 2, Sec. V |
| C2 | `handle_verify_fix` always uses `Engine(mock_mode=True)` and hard-codes `verified: True`; `autosec_scan` defaults `mock=True` | Sec. III-D, Table II, abstract |
| C3 | `is_target_allowed` is lexical (`10.example.com`, `192.168.attacker.net`, `127.evil.org`, `x.hackthebox` pass); tracked as AUD-04 in `audit/BACKLOG.md` | Sec. III-A.1, Sec. V |
| C4 | OpenAPI endpoints stored in `engine.crawler_data`, never read | Sec. III-A.3, Table I |
| C5 | `Correlator` unused in pipeline and does not merge | Sec. III-C, IV-B |
| C6 | Delta identity = positional plugin IDs | Sec. III-C, IV-C |
| C7 | `config.py` describes `recon` as "Passive & Non-Intrusive" | Sec. III-B (profiles) |
| C8 | `PolitenessEngine.max_retries_on_429` unused; throttled response not retried | Sec. III-B |
| C9 | `test_auth.py` not idempotent against persistent `data/users.db` (fails on a used dev machine) | Sec. IV-D |
| C10 | `CLAUDE.md` says "120 tests" (stale; 165/161) | — |
| C11 | `TimingVerifier` computes σ but ignores it; `BaseScanner` uses m = 2 | Sec. III-B |

## 3. Unresolved evidence gaps (cannot be closed from the repository)
- Repetitions, variance, confidence intervals for every measurement.
- CPU-utilization column of Table III (no profiler output).
- Why speedup plateaus beyond k = 8 (conjecture only; plugin makespan bound is arithmetic, not measured).
- Whether Juice Shop findings were produced in real mode with the shipped plugins at that commit (git history of plugins changed after the paper's first versions).
- Per-plugin use of the authenticated session.
- Accuracy of fix recipes (never applied to a vulnerable app and re-scanned).
- Usefulness of the "plain-English danger" grade to non-technical readers (no user study).

## 4. Publication risks
1. Reviewers who run `python main.py scan … --real` on Juice Shop will not obtain 76 → 47 findings (risk of "irreproducible results").
2. A single benchmark with benchmark-specific plugin inputs (DirBrute paths, Auth credentials) invites an overfitting objection.
3. No head-to-head comparison with ZAP/Burp/Nuclei; novelty rests on integration, not on measured superiority.
4. Safety guardrail is bypassable by DNS names; a security venue may object to calling it "validation".
5. IJARCCE template: the DOCX is built on the supplied template (styles, numbering, footer). The running header was removed at the authors' request (it held the journal's Vol./Issue/DOI placeholders); the footer (licence line and page number) remains, although the template's text says headers and footers must not be used, so confirm with the editors whether the footer should also go. Table text is 10 pt as the template specifies.
6. Page count rose from 9 to 11; confirm the venue's limit.

## 5. Optional improvements
- Ablation: timing check with injected network jitter (tc/netem) to measure false-positive rate with and without phase 2.
- Delta: content-derived identity (hash of host + normalized endpoint + CWE + parameter) and a renumbering regression test; re-do the three-build experiment on real consecutive scans.
- Wire OpenAPI output into plugins; add YAML and `$ref` support; fetch and scan external JS bundles.
- Closed-loop study: agent applies recipe → re-scan against live target → regression test, report patch success rate.
- Compare with ZAP baseline/API scans and Nuclei on the same Juice Shop tag (time, TP/FP).
- Add recipes for XSS, command injection, SSRF, SSTI, JWT, path traversal.
- Replace the hard-coded numbers in `generate_paper_plots.py` with a CSV produced by the experiment harness.
- Add a CI job running `validate_final.py` against the paper build.
