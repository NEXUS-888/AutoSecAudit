---
name: audit-fix
description: Loop over audit batches (2-3 issues each) from audit/BACKLOG.md. Fix the current batch or address the verifier's review, hand off, wait for verification, and continue until done or blocked.
---

You are the **fixer** in an automated fix → verify loop. `audit/run_loop.py` (driven by
Claude Code) verifies your work. Work is accepted only when every acceptance criterion is
confirmed, so precision matters more than speed.

## Step 1 — Read state
Read `audit/STATE.md` (it's short).
- `awaiting_baseline`, `ready_for_review` or `explore_submitted` → go to **Step 6** and wait.
- `blocked` or `done` → STOP and report the state to the user.
- `ready_for_fix` → Step 2A.
- `revise` → Step 2B.
- `ready_for_explore` → **Step E** (you are asked to look for defects, not to fix any).

## Step E — Explore (only when status is `ready_for_explore`)
Your job is to find real defects in ONE area and to **prove each with a failing test**. A finding without a
test that fails is worthless and is discarded automatically.
1. Read `audit/EXPLORE.md` for the area. Read the code there. Look for security flaws, wrong results,
   unhandled errors, races, resource leaks and false positives/negatives. At most 5 candidates.
2. For each real defect create `audit/candidates/CAND-<slug>/` (slug: lowercase letters, digits, hyphens) with:
   - `finding.md`: a `# Title` line, then `**Area:** <file or module>`, `**Impact:** <one sentence>`, then a
     `## Reproduction` section saying how the test shows the defect.
   - exactly one `test_cand_<slug_with_underscores>.py`: a `unittest` that FAILS because of the defect.
     It must fail on an **assertion** (not an import error or exception), fail the same way every time, use
     only loopback URLs (127.0.0.1) served by a fixture you start in the test, finish in under 60 seconds, and
     must not use `subprocess`, `os.system`, `eval`/`exec`, delete files, or touch anything outside a temp dir.
3. Run it yourself 3 times:
   `.\.venv\Scripts\python.exe -m unittest discover -s audit/candidates/CAND-<slug> -p "test_cand_*.py"`.
   If it passes or errors, fix the test or delete the candidate.
4. Do NOT edit any source file, existing test, or anything under `audit/` other than your new `CAND-*` folders.
   Do NOT commit.
5. If you found nothing provable, submit zero candidates; that is a valid result.
6. Set `status: explore_submitted` in `audit/STATE.md` (only that line), then go to **Step 6**.

## Step 2A — New batch
Run `python audit/show_batch.py <batch>`. It prints the loop rules and **only** this batch's
issues. Don't open `audit/BACKLOG.md` itself, and ignore problems that belong to other batches.

## Step 2B — Revision
Read `audit/reviews/B<batch>-R<round-1>.md`. Its "Required changes" list is your entire task
for this round: address every numbered item and nothing else. Run
`python audit/show_batch.py <batch> --no-rules` to re-check the original criteria.

## Step 3 — Implement (test first)
For each issue:
1. Write tests covering **each** acceptance criterion and confirm they fail on the current code.
2. Implement the **Required fix** as written. If you think the approach is wrong, implement
   it anyway and record your objection under "Deviations". Never silently do something else.
3. Make the tests pass.

Hard rules (checked automatically; violations bounce the batch back without review):
- Touch only files needed for this batch.
- Do NOT edit `audit/BACKLOG.md`, `audit/VERIFIER.md`, `audit/*.py`, `.claude/`, or any line
  of `audit/STATE.md` except `status:`.
- Do NOT delete tests, add skip/xfail markers, or loosen assertions. If an existing test encodes
  the old wrong behavior, update it and explain why in the handoff.
- Do NOT commit. Do NOT bypass `is_target_allowed()`. Keep the stable API contract.

## Step 4 — Verify locally
`python run_tests.py` must be fully green. If `py -3.11` exists, `py -3.11 -c "import core.utils"`
must succeed.

## Step 5 — Hand off
Write `audit/handoffs/B<batch>-R<round>.md`. Keep it compact; the verifier reads it:

```
# Handoff B<batch> round <round>
## AUD-xx — <title>
- Changes: <file:line — what>
- Criteria → tests: <criterion (short)> → <test_file::test_name>   (one line each)
## Review items addressed   (revision rounds only)
1. <item> → <file:line>
## Commands run
<command> → <result, test counts>
## Deviations
<none | what and why>
```

Then set `status: ready_for_review` in `audit/STATE.md`.

## Step 6 — Wait for verification, then loop
```
python audit/wait_for_status.py ready_for_fix revise ready_for_explore blocked done --max-wait 540
```
- `timeout` → run the same command again (verification can take several minutes).
- `ready_for_fix` / `revise` / `ready_for_explore` → back to **Step 1**. Start each batch fresh; don't carry
  assumptions over from the previous batch.
- `blocked` / `done` → STOP and report it.

Keep looping until `done` or `blocked`. Don't stop between batches to ask for confirmation.
