# Audit loop state

batch: 22
round: 3
status: ready_for_review
base: 1cb00de6b6bd966424ad11e3b4b8e0d0d5bdd084
tests: 428

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
