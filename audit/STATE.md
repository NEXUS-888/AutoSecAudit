# Audit loop state

batch: 10
round: 4
status: ready_for_review
base: 7701cfabeb86822ebcfecaeabdc44acad0b5ab38
tests: 247

<!--
status values:
  awaiting_baseline  - run `python audit/run_loop.py` (needs a clean working tree)
  ready_for_fix      - Antigravity: implement the batch
  revise             - Antigravity: address audit/reviews/B<batch>-R<round-1>.md
  ready_for_review   - run_loop.py prechecks, then verifies with Claude
  blocked            - 3 failed rounds (or no verdict); a human decides
  done               - all batches passed

Only run_loop.py changes batch / round / base / tests.
The fixer changes only `status:` (to ready_for_review) when it finishes.
-->
