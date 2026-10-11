# Final Validation Summary

Run: 2026-10-11. Scripts live in `paper/revision_audit/`; raw output of the last full run is `validate_final_output.txt`.

## 1. Deliverables
| Deliverable | Location |
|---|---|
| Revised paper (editable) | `AutoSecAudit_Research_Paper_IJARCCE.docx` (copy in `paper/`) |
| Submission PDF (11 pages, A4, exported by Word) | `AutoSecAudit_Research_Paper_IJARCCE.pdf` (copy in `paper/`) |
| Change log | `paper/revision_audit/02_change_log.md` |
| Claim verification matrix | `paper/revision_audit/01_claim_verification_matrix.md` (also serves as the pre-edit audit report) |
| Outstanding issues | `paper/revision_audit/03_outstanding_issues.md` |
| Originals | `paper/revision_audit/original/` |

## 2. Recalculated metrics (`verify_metrics.py`: 22/22 pass)
| Metric | Reported | Recomputed | Result |
|---|---|---|---|
| Speedup k=2/4/8/16 | 1.80 / 2.58 / 2.84 / 2.79 | 1.797 / 2.580 / 2.843 / 2.787 | PASS |
| Latency reduction | 64.8 % | 64.82 % | PASS |
| Table IV TP / FP / raw / consolidated | 46 / 1 / 76 / 47 | sums 46 / 1 / 76 / 47; each row consolidated = TP + FP | PASS |
| Precision | 97.9 % | 46/47 = 97.87 % | PASS |
| Recall (FN = 6) | 88.5 % | 46/52 = 88.46 % | PASS |
| F1 | 92.9 % | 92.93 % (= 2·46/(2·46+1+6)) | PASS |
| Alert reduction | 38.2 % | 29/76 = 38.16 % | PASS |
| Delta | 47 → 40 → 26 | 47−10+3 = 40; 40−14 = 26 | PASS |

**Caveat:** these checks prove the arithmetic only. The underlying measurements remain **unverified** (no raw data; see M1–M4).

## 3. Delta sequence (`verify_delta_sequence.py`: pass)
Repository `DeltaAnalyzer` on a synthetic identifier sequence returns 3 NEW / 10 FIXED / 37 UNCHANGED, then 0 / 14 / 26. Edge cases reproduced: renumbered finding reported FIXED while still present; same id with different content reported UNCHANGED; empty id dropped.

## 4. Document checks (`validate_final.py`: **69/69 pass**)
- Authors, affiliation, corresponding-author mark, emails, acknowledgment preserved.
- 4 tables, 4 figures embedded (also 4 images in the PDF), all captions present, all figures referenced in text.
- Table III and IV recomputed from the DOCX tables themselves; headline numbers present in abstract and conclusion.
- References: 19 entries, every [1]–[19] cited in the body, none out of range.
- Banned or negated claims absent: "false alarms are eliminated", "100 % classification", "Autonomous AI Remediation", "guarantee", unqualified "compound-key deduplication", "breadth-first", `autosec_list_scanners`, offline CVE dictionary, "weak HMAC secrets", "stored XSS", `3*sigma`.
- Timing formula in paper matches code (ρ = 0.70, 0.35τ, σ unused); thread default (4) disclosed; Table II has exactly 4 tools.
- PDF: 11 pages, accented characters (Doupé) intact, no replacement characters.

## 5. Visual inspection of rendered pages (80 dpi)
No clipped tables, no broken equations (formulas are inline text), figures present and legible, Table I/II/III/IV each on a single page, Fig. 4 legend no longer overlaps data labels, no stretched justified lines. Remaining cosmetic notes: Table I is dense (5 columns, 8.5 pt); References are 8 pt as in the original.

## 6. Test-suite status used in the paper
- `python -m pytest --collect-only` → 165 collected; `python -m pytest` → 164 passed, 1 failed (`test_auth.py::test_auth_subsystem`, "Email is already registered": persistent `data/users.db` state).
- `python run_tests.py` (unittest discovery) → 161 run, 0 failures, 0 errors.

## 7. Acceptance-criteria status
| Criterion | Status |
|---|---|
| Retained implementation claims supported or qualified | **Met** (see matrix; 20+ claims corrected) |
| Retained experimental claims supported or flagged unverified | **Met** (flagged in paper Sec. IV, V and abstract) |
| Numerical consistency across abstract, tables, charts, conclusion | **Met** |
| No unsupported result or citation introduced | **Met with note:** refs [15]–[19] were added after web verification of existence; authors must confirm formatting (M5) |
| FP, AI-remediation, authorization, delta claims qualified | **Met** |
| Suitable for final human review | **Yes — but not submission-ready** until M1–M7 are resolved |
