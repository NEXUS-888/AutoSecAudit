# The improvement loop

Antigravity does the work, tools and Claude verify it, and rework is automatic. The design goal is **as few
Claude tokens as possible without lowering the bar**.

```
          +-------------------------- autopilot.py --------------------------+
          |                                                                   |
   fix -> | discover -> (explore) -> release                                  |
          +-------------------------------------------------------------------+
   Antigravity   ruff/bandit/       Antigravity proves   gates, changelog,
   fixes batches pip-audit          defects with tests   tag, archive
```

## Who uses Claude, and how much

| Step | Who decides | Claude tokens |
|---|---|---|
| Find issues (static analysis, dependency audit) | `discover.py` | none |
| Find issues (explorer) | Antigravity must submit a test that fails; `validate_candidate.py` re-runs it 3 times | none |
| Mechanical precheck (tests green, protected files, skips, Python 3.10 import) | `run_loop.py` | none |
| Batch whose issues have `Check:` commands | the commands (`loop_lib.run_checks`) | none |
| Any batch with a failing `Check:` | the commands | none (sent back before Claude is asked) |
| Judgment batch | Claude, from the diff and the acceptance criteria only; no tools, no repo exploration | one call, light model for small non-security diffs, strong model for security-sensitive files, large diffs and round 3 onward |
| Diff too large to send whole (over 120,000 characters) | Claude, agentic fallback | one longer call |
| Release | `release_gate.py` | none |

Measured on this repository: a CLI call costs about 28,500 input tokens before any prompt; with tools,
MCP servers and slash commands turned off it is about 6,700. A diff-only review of a real past batch (B21,
23,000 characters of diff) used about 19,700 input and 1,700 output tokens, $0.09 on Sonnet. Every call is
logged to `.git/audit-loop/usage.jsonl` and the loop stops when `AUTOSEC_LOOP_BUDGET_USD` (default 10) is spent.

## Running it

1. Start the loop (the driver restarts itself on crashes): `python audit/supervise.py`
   or the whole cycle: `python audit/autopilot.py [--max-cycles 3] [--explore-rounds 0] [--bump minor]`
2. In Antigravity, paste the usual prompt (workflow `audit-fix`, which also handles exploration).
3. Check spend at any time: `python -c "import sys; sys.path.insert(0,'audit'); import loop_lib as L; print(L.usage_summary())"`

## Writing a batch that costs nothing to verify

```
## B31 — Title
**Verification:** mechanical

### AUD-90 · Short title
- **Files:** `core/x.py`
- **Problem:** ...
- **Required fix:** ...
- **Check:** `{py} -m unittest test_something`
```
Every issue needs at least one `Check:` command (`{py}` is the interpreter; exit 0 means pass). Without
`**Verification:** mechanical` the checks still run first and gate the Claude review.

## Files

| File | Purpose |
|---|---|
| `run_loop.py` | the driver: precheck, verification, commit, next batch |
| `loop_lib.py` | backlog parsing, checks, model choice, diff prompt, metered Claude calls |
| `discover.py` | tool-based finding -> mechanical batches; `--check` re-verifies one finding |
| `baselines/accepted.json` | findings that are deliberate for a security scanner, each with a reason |
| `validate_candidate.py` | proves or rejects an explorer's finding by running its failing test |
| `release_gate.py`, `release_gates.json` | the release gates and the release itself |
| `autopilot.py` | the state machine that chains all of the above |
| `ux_check.py` | headless-Chrome UI/UX audit: 3 screen sizes x 2 themes, accessibility, contrast, overflow, tap targets, error and empty states; `--quick`, `--features`, screenshots in `data/ux_shots/` |
| `ux_iterations.py` | validates that a self-iterating batch really has 3+ consecutive logs, starting non-zero and ending at zero |
| `baselines/ux_accepted.json` | UX issues accepted on purpose, each with a written reason (only the owner edits it) |
| `antigravity/audit-fix.md` | copy of the Antigravity workflow (the live one is in `~/.gemini/antigravity/global_workflows`) |

The fixer may not edit any of these, nor `BACKLOG.md`, nor candidate tests (`test_cand_*`).

## Limits worth knowing
- A light-model review sees only the diff. It is used only where the change is small and not security
  sensitive; anything else goes to the strong model.
- Tools and tests find what they can express. Explorer findings are only as good as the failing test that proves
  them; a defect nobody writes a test for is not found.
- Release gates cannot judge whether the product is *good*, only that it is green, clean and reproducible.

## Self-iterating UI/UX batches (B30, B31)
Some work is judged by looking at the result, so the fixer iterates on its own: measure with `ux_check.py`,
look at the screenshots, fix, write `audit/handoffs/B<n>-ITER-<k>.md`, repeat until the measurement says 0.
Claude spends tokens only once, after every `Check:` (including a clean `ux_check.py` run and a valid iteration
history) already passes; a failing check sends the batch back with no Claude call. Needs Google Chrome and
`pip install -r requirements-dev.txt`.
