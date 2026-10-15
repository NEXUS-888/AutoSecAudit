# Post-audit status (2026-10-15)

Written after the code-fix loop (batches B01–B25, AUD-01 to AUD-61) and an end-to-end retest. It updates
`03_outstanding_issues.md`, whose section 2 listed eleven code defects that made paper statements false.
Everything below was checked against the repository at the commit this file was added; none of it comes
from the Juice Shop run behind Tables III–IV.

## 1. The eleven code defects (C1–C11): current status

| ID | Defect in `03_outstanding_issues.md` | Status | Evidence |
|---|---|---|---|
| C1 | MCP `autosec_get_findings` read `data["findings"]` (returned 0 findings, grade A+) | **Fixed** | `mcp_server.py` reads `all_findings` (AUD-07); `test_b03_mcp_server.py` |
| C2 | `handle_verify_fix` always mock + `verified: True`; `autosec_scan` defaults `mock=True` | **Partly fixed.** `autosec_verify_fix` now defaults to a real engine and no longer hard-codes `verified: True` (AUD-08). `autosec_scan` **still defaults to `mock=True`** (`mcp_server.py`, `args.get("mock", True)`), so the abstract/Sec. III-D must not say MCP scans are real by default | `test_b03_mcp_server.py`, `test_mcp_server.py` |
| C3 | `is_target_allowed` lexical (`10.example.com` passes) | **Fixed.** Resolves the host; every resolved address must be private or loopback; enforced in `Engine.set_target` (AUD-04, AUD-05); verified live against `example.com` and a DNS name resolving to a public address | `test_b02_target_scope.py` |
| C4 | OpenAPI endpoints stored, never read | **Fixed.** Imported endpoints reach the plugins (AUD-31); an exposed spec is also imported automatically (AUD-57); a live scan of VAmPI used 18 spec endpoints | `test_b11_engine_correctness.py`, `test_b24_api_discovery_and_recall.py` |
| C5 | `Correlator` unused in the pipeline, does not merge | **Fixed.** One pipeline (`core/pipeline.py`) merges findings by a canonical key before delta analysis (AUD-40, AUD-50) | `test_b13_finding_identity.py`, `test_b15_pipeline.py` |
| C6 | Delta identity = positional plugin ids | **Fixed.** Findings carry a content fingerprint; delta compares merged findings and only scanners that ran in both scans (AUD-34, AUD-35, retest fix). Two identical scans now give an empty delta (regression test) | `test_b13_finding_identity.py`, `test_retest_fixes.py` |
| C7 | `config.py` calls `recon` "Passive & Non-Intrusive" | **Still open.** `config.py` still reads "Passive & Non-Intrusive Recon" for a profile that runs directory brute-forcing and port scans. Reword to "reconnaissance (low-impact active probing)" in code and paper | — |
| C8 | `max_retries_on_429` unused; throttled responses not retried | **Fixed.** Shared `ScanHttpClient` retries 429/503 with backoff and suppresses persistent throttled responses from detection (AUD-25, AUD-26) | `test_b09_shared_http_client.py` |
| C9 | `test_auth.py` not idempotent against persistent `data/users.db` | **Fixed.** The runner points tests at a per-worker temporary data directory (AUD-46) | `test_b17_hygiene.py`, `run_tests.py` |
| C10 | `CLAUDE.md` said 120 tests | **Fixed.** Now states about 490; the suite has 492 tests | `run_tests.py` output |
| C11 | `TimingVerifier` computed σ but ignored it | **Fixed.** The threshold uses `k_std_dev` times the baseline standard deviation, with two-phase verification (AUD-33) | `test_b12_false_positive_control.py` |

## 2. Facts that changed and must be updated in the paper
- Automated tests: **492** (was 165/161). Verified green on Python 3.14 and 3.10.
- Scanner plugins: **19** (unchanged; counted from `plugins/`, `mock_plugin.py` excluded).
- The scope guard is now IP-based, not lexical; Sec. III-A.1 and Sec. V (limitations) should say so and drop the DNS-name bypass caveat.
- The delta engine now identifies findings by content fingerprint; the "positional id" limitation in Sec. III-C/IV-C no longer holds.
- A server-side session revocation, CSRF protection, per-user report ownership and a localhost-only default bind now exist in the dashboard (AUD-10 to AUD-15, AUD-65, AUD-66); they were not in the paper at all.

## 3. Claims that remain unreproducible (do not restate as measured)
- **Table III (thread scaling) and the CPU-utilisation column**, **Table IV (76 raw alerts, 46 TP, 1 FP, 47 consolidated, 38.2 % reduction)** and **the delta fidelity claim**: the numbers are hard-coded in `generate_paper_plots.py` and no raw data exists. `verify_metrics.py` (22/22 pass) proves only that the numbers are arithmetically consistent with each other.
- The consolidation step 76 → 47 was never produced by a code path of the released tool; the current merge logic is different, so a rerun will not give 47.
- `verify_delta_sequence.py` assumed positional-id matching; its output no longer corresponds to any claim and it must be rewritten for fingerprint identity before it is cited.
- A Juice Shop rerun needs Docker, which has not been available on the development machine.

## 4. Replacement evidence that is measurable and reproducible
Run on an otherwise idle machine, with at least 5 repetitions per cell, reporting mean and standard deviation, and keeping the raw per-run results next to the paper:
1. **Detection accuracy:** the benchmark harness (AUD-69/70, batch B26) against built-in testbed 1 and testbed 2, and ground-truth files for pygoat, VAmPI and vulpy. Report planted items found (recall), reported findings that are false (precision) and scan time.
2. **Thread scaling:** the same scan of testbed 1 with `AUTOSEC_THREAD_COUNT` = 1, 2, 4, 8, 16, recording wall time. State the host (OS, CPU, RAM) actually used.
3. **Delta fidelity:** three consecutive real scans of a testbed with a deliberate change between builds; report new/fixed/unchanged against the known change.
4. **Optional:** Juice Shop at a pinned image digest if Docker becomes available; compare with the published ZAP/Nuclei baselines on the same tag.
5. **Replace** `generate_paper_plots.py`'s hard-coded arrays with a CSV produced by the harness, and fail loudly if the CSV is missing.

## 5. Safety and robustness results usable as new evaluation material (all reproduced in this repository)
- **State-changing form safety:** a trap server logged every request during a full scan. No POST reached a delete, logout, password-change or reset form; a form pointing at a second origin received no request; safe forms were probed. A follow-up fix stopped open-redirect GET probes from reaching state-changing paths.
- **Hostile target:** report output escaped hostile markup in the HTML report, dashboard report page, PDF, WAF rules and dev tickets; redirects to a cloud-metadata address were blocked; response size and per-request time limits were added after a 300 MB response and a slow-drip response exposed their absence.
- **Real-browser dashboard check:** login, a scan from the UI, report view, JSON/PDF download and logout ran without JavaScript errors.

## 6. Paper text that needs author action
1. Sec. III-A.1, Sec. V: scope guard now IP-based (C3).
2. Sec. III-A.3, Table I: OpenAPI endpoints are used (C4).
3. Sec. III-B: `recon` wording (C7 still open); 429 handling (C8); timing σ (C11).
4. Sec. III-C, IV-B, IV-C: correlator and fingerprint delta (C5, C6).
5. Sec. III-D, Table II, abstract: MCP verify-fix is real; **`autosec_scan` still defaults to mock** (C2).
6. Sec. IV-A/IV-D: test count 492; tests are isolated from persistent data (C9).
7. Tables III–V and Fig. 2–4: replace with measured results from section 4, or label them as unreproduced.
8. Stale parallel copies (`RESEARCH_PAPER.md`, `main.tex`, `build_ijarcce_*.py`, the zip, `Presentation/*`) still contain retracted claims (item M6); update after the manuscript is settled.
