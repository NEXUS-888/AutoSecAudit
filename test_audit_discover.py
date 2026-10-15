"""Tests for audit/discover.py: tool-found issues become mechanical backlog batches (no Claude)."""
import json
import sys
import unittest

sys.path.insert(0, "audit")

import discover as D  # noqa: E402
import loop_lib as L  # noqa: E402

RUFF = json.dumps([{"code": "F821", "message": "Undefined name `time`", "filename": "/repo/testbed/app.py",
                    "location": {"row": 207, "column": 9}}])
BANDIT = json.dumps({"results": [
    {"test_id": "B314", "filename": "plugins/nmap_plugin.py", "line_number": 56,
     "issue_text": "Using xml fromstring to parse untrusted XML", "issue_severity": "MEDIUM"},
    {"test_id": "B602", "filename": "core/run.py", "line_number": 10,
     "issue_text": "subprocess call with shell=True", "issue_severity": "HIGH"}]})
PIP = json.dumps({"dependencies": [
    {"name": "flask", "version": "2.0.0", "vulns": [{"id": "PYSEC-2023-62", "description": "cookie issue",
                                                       "fix_versions": ["2.2.5"]}]},
    {"name": "requests", "version": "2.32.0", "vulns": []}]})

BACKLOG = """# Backlog

## Rules of the loop
- rules

---

## B29 — Last existing batch

### AUD-75 · Something
- **Files:** `a.py`

---

## Deferred (not in the loop)
- later
"""


class TestParsers(unittest.TestCase):
    def test_ruff_finding_becomes_a_candidate_with_a_repo_relative_path(self):
        (c,) = D.parse_ruff(RUFF, root="/repo")
        self.assertEqual((c.tool, c.rule, c.file, c.line), ("ruff", "F821", "testbed/app.py", 207))
        self.assertIn("Undefined name", c.message)
        self.assertTrue(c.id.startswith("CAND-"))

    def test_bandit_and_pip_audit_findings_are_parsed(self):
        b = D.parse_bandit(BANDIT)
        self.assertEqual([(c.rule, c.file) for c in b], [("B314", "plugins/nmap_plugin.py"), ("B602", "core/run.py")])
        (p,) = D.parse_pip_audit(PIP)
        self.assertEqual((p.tool, p.rule, p.file), ("pip-audit", "PYSEC-2023-62", "requirements.txt"))
        self.assertIn("flask", p.message)
        self.assertIn("2.2.5", p.message)

    def test_id_is_stable_when_only_the_line_number_moves(self):
        a = D.parse_ruff(RUFF, root="/repo")[0]
        moved = D.parse_ruff(RUFF.replace("207", "312"), root="/repo")[0]
        self.assertEqual(a.id, moved.id)
        other = D.parse_ruff(RUFF.replace("F821", "F811"), root="/repo")[0]
        self.assertNotEqual(a.id, other.id)


class TestAcceptedBaseline(unittest.TestCase):
    def test_accepted_findings_are_dropped_by_tool_rule_and_file(self):
        cands = D.parse_bandit(BANDIT)
        accepted = [{"tool": "bandit", "rule": "B314", "file": "plugins/nmap_plugin.py", "reason": "local nmap output"}]
        left = D.filter_accepted(cands, accepted)
        self.assertEqual([c.rule for c in left], ["B602"])

    def test_a_whole_rule_can_be_accepted_without_a_file(self):
        cands = D.parse_bandit(BANDIT)
        left = D.filter_accepted(cands, [{"tool": "bandit", "rule": "B602", "reason": "x"}])
        self.assertEqual([c.rule for c in left], ["B314"])

    def test_an_acceptance_must_carry_a_reason(self):
        with self.assertRaises(ValueError):
            D.filter_accepted(D.parse_bandit(BANDIT), [{"tool": "bandit", "rule": "B314"}])


class TestCollect(unittest.TestCase):
    def test_tools_run_with_suppression_comments_ignored(self):
        seen = []

        def runner(cmd, **kw):
            seen.append(cmd)

            class P:
                returncode = 1
                stderr = ""
                stdout = RUFF if "ruff" in " ".join(cmd) else (BANDIT if "bandit" in " ".join(cmd) else PIP)
            return P()

        cands = D.collect(root="/repo", runner=runner, tool_prefixes={"ruff": ["ruff"], "bandit": ["bandit"],
                                                                      "pip-audit": ["pip-audit"]})
        flat = [" ".join(c) for c in seen]
        self.assertTrue(any("ruff" in c and "--ignore-noqa" in c for c in flat), flat)
        self.assertTrue(any("bandit" in c and "--ignore-nosec" in c for c in flat), flat)
        self.assertTrue(any("pip-audit" in c for c in flat))
        self.assertEqual({c.tool for c in cands}, {"ruff", "bandit", "pip-audit"})

    def test_a_tool_that_produces_no_json_is_reported_not_ignored(self):
        def runner(cmd, **kw):
            class P:
                returncode = 2
                stderr = "boom"
                stdout = "not json"
            return P()

        with self.assertRaises(D.ToolError):
            D.collect(root="/repo", runner=runner, tool_prefixes={"ruff": ["ruff"], "bandit": ["bandit"],
                                                                  "pip-audit": ["pip-audit"]})


class TestBatchGeneration(unittest.TestCase):
    def test_generated_batch_is_mechanical_and_parses_back(self):
        cands = D.parse_bandit(BANDIT) + D.parse_ruff(RUFF, root="/repo")
        text = D.batch_text(cands, batch_number=30, first_aud=76)
        parsed = L.parse_backlog("---\n\n" + text)["30"]
        self.assertEqual(parsed.verification, "mechanical")
        self.assertEqual([i.id for i in parsed.issues], ["AUD-76", "AUD-77", "AUD-78"])
        for issue, cand in zip(parsed.issues, cands):
            self.assertEqual(issue.checks, [f"{{py}} audit/discover.py --check {cand.id}"])
        self.assertIn("Do not suppress", text)

    def test_append_continues_numbering_and_keeps_deferred_last(self):
        cands = [D.Candidate("bandit", f"B{i}", "core/a.py", i, f"msg {i}") for i in range(100, 107)]
        new_text, batches = D.append_batches(BACKLOG, cands, per_batch=3)
        self.assertEqual(batches, [30, 31, 32])
        parsed = L.parse_backlog(new_text)
        self.assertEqual(sorted(parsed), ["29", "30", "31", "32"])
        self.assertEqual(parsed["30"].issues[0].id, "AUD-76")
        self.assertEqual(parsed["32"].issues[0].id, "AUD-82")
        self.assertLess(new_text.index("## B32"), new_text.index("## Deferred"))

    def test_nothing_to_append_leaves_the_backlog_unchanged(self):
        new_text, batches = D.append_batches(BACKLOG, [], per_batch=3)
        self.assertEqual(new_text, BACKLOG)
        self.assertEqual(batches, [])

    def test_already_tracked_candidates_are_not_added_twice(self):
        cands = D.parse_bandit(BANDIT)
        once, _ = D.append_batches(BACKLOG, cands, per_batch=3)
        twice, batches = D.append_batches(once, cands, per_batch=3)
        self.assertEqual(batches, [])
        self.assertEqual(once, twice)


class TestFailOnFindings(unittest.TestCase):
    def test_exit_code_reflects_remaining_findings_for_use_as_a_release_gate(self):
        original = D.collect
        try:
            D.collect = lambda: D.parse_ruff(RUFF, root="/repo")
            self.assertEqual(D.main(["--fail-on-findings"]), 1)
            self.assertEqual(D.main([]), 0)              # listing alone never fails
            D.collect = lambda: []
            self.assertEqual(D.main(["--fail-on-findings"]), 0)
        finally:
            D.collect = original


class TestCheck(unittest.TestCase):
    def test_check_passes_only_when_the_candidate_is_gone(self):
        cands = D.parse_ruff(RUFF, root="/repo")
        self.assertFalse(D.is_fixed(cands[0].id, cands))
        self.assertTrue(D.is_fixed(cands[0].id, []))
        self.assertTrue(D.is_fixed(cands[0].id, D.parse_bandit(BANDIT)))


if __name__ == "__main__":
    unittest.main()
