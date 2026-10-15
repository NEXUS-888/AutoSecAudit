"""Unit tests for the audit-loop tooling (audit/loop_lib.py): the parts that decide how much
Claude is used, and how a batch is verified. No real Claude, network or repository state is used.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "audit")

import loop_lib as L  # noqa: E402


SAMPLE_BACKLOG = """# Backlog

## Rules of the loop
- rules here

---

## B30 — Tool-found issues
**Verification:** mechanical

### AUD-80 · Unused variable in core/x.py
- **Files:** `core/x.py`
- **Check:** `{py} -m unittest test_one`
- **Check:** `{py} audit/discover.py --check CAND-1`

### AUD-81 · Second
- **Files:** `core/y.py`
- **Check:** `{py} -m unittest test_two`

---

## B31 — Judgment batch

### AUD-82 · Needs review
- **Files:** `ui/app.py`
- **Acceptance:** something a human must judge.
"""


class TestParseBacklog(unittest.TestCase):
    def test_parses_batches_issues_checks_and_verification_mode(self):
        batches = L.parse_backlog(SAMPLE_BACKLOG)
        self.assertEqual(set(batches), {"30", "31"})
        b30 = batches["30"]
        self.assertEqual(b30.verification, "mechanical")
        self.assertEqual([i.id for i in b30.issues], ["AUD-80", "AUD-81"])
        self.assertEqual(b30.issues[0].checks,
                         ["{py} -m unittest test_one", "{py} audit/discover.py --check CAND-1"])
        self.assertEqual(batches["31"].verification, "review")
        self.assertEqual(batches["31"].issues[0].checks, [])

    def test_a_mechanical_batch_with_an_issue_lacking_checks_is_not_mechanical(self):
        text = SAMPLE_BACKLOG.replace("- **Check:** `{py} -m unittest test_two`\n", "")
        self.assertEqual(L.parse_backlog(text)["30"].verification, "review")


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class TestMechanicalChecks(unittest.TestCase):
    def test_py_placeholder_is_replaced_and_results_collected(self):
        calls = []

        def runner(cmd, **kw):
            calls.append(cmd)
            return _Proc(0, "fine")

        results = L.run_checks(["{py} -m unittest test_one", "{py} audit/x.py --check A"], ".", runner=runner)
        self.assertEqual(calls[0][0], sys.executable)
        self.assertEqual(calls[0][1:], ["-m", "unittest", "test_one"])
        self.assertTrue(all(r.ok for r in results))

    def test_timeout_counts_as_failure(self):
        def runner(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)

        results = L.run_checks(["{py} -c pass"], ".", runner=runner, timeout=1)
        self.assertFalse(results[0].ok)
        self.assertEqual(results[0].returncode, 124)

    def test_mechanical_review_passes_only_when_every_check_passes(self):
        ok = L.CheckResult("{py} a", 0, "")
        bad = L.CheckResult("{py} b", 1, "line1\nTraceback: boom\n")
        verdict, review = L.mechanical_review("30", 1, [ok, ok])
        self.assertEqual(verdict, "PASS")
        verdict, review = L.mechanical_review("30", 1, [ok, bad])
        self.assertEqual(verdict, "REVISE")
        self.assertIn("{py} b", review)
        self.assertIn("Traceback: boom", review)
        self.assertIn("## Required changes", review)
        self.assertNotIn("Traceback: boom", L.mechanical_review("30", 1, [ok, ok])[1])


class TestModelChoice(unittest.TestCase):
    def test_small_non_security_diff_uses_the_light_model(self):
        self.assertEqual(L.pick_model(["plugins/ssti_plugin.py", "test_x.py"], 4000, 1), "sonnet")

    def test_security_sensitive_files_always_use_the_strong_model(self):
        for f in ("core/utils.py", "core/auth.py", "core/http_client.py", "ui/app.py",
                  "core/authenticator.py", "mcp_server.py"):
            self.assertEqual(L.pick_model([f], 100, 1), "opus", f)

    def test_large_diffs_and_late_rounds_use_the_strong_model(self):
        self.assertEqual(L.pick_model(["plugins/a.py"], L.LIGHT_MAX_DIFF_CHARS + 1, 1), "opus")
        self.assertEqual(L.pick_model(["plugins/a.py"], 100, 3), "opus")


class TestDiffPrompt(unittest.TestCase):
    def test_prompt_contains_criteria_diff_and_verdict_contract_and_is_bounded(self):
        diff = "diff --git a/x b/x\n+added line\n" * 5000
        prompt = L.build_diff_prompt("INSTR", "### AUD-1 criteria text", "handoff text", diff, "precheck ok",
                                     {"batch": "30", "round": 2})
        self.assertIn("### AUD-1 criteria text", prompt)
        self.assertIn("added line", prompt)
        self.assertIn("VERDICT: PASS|REVISE", prompt)
        self.assertLessEqual(len(prompt), L.MAX_PROMPT_CHARS + 2000)
        self.assertIn("truncated", prompt.lower())

    def test_small_diff_is_included_whole(self):
        prompt = L.build_diff_prompt("I", "S", "H", "+only change", "ok", {"batch": "1", "round": 1})
        self.assertIn("+only change", prompt)
        self.assertNotIn("truncated", prompt.lower())


class TestVerdictParsing(unittest.TestCase):
    def test_pass_and_revise_are_read_from_the_first_line(self):
        self.assertEqual(L.parse_verdict("VERDICT: PASS\n# Review B1 round 1\n| AUD-1 | PASS | ok |")[0], "PASS")
        self.assertEqual(L.parse_verdict("VERDICT: REVISE\n# Review")[0], "REVISE")

    def test_pass_with_a_failing_row_is_downgraded_to_revise(self):
        text = "VERDICT: PASS\n# Review B1 round 1\n| AUD-1 | FAIL | missing test |"
        self.assertEqual(L.parse_verdict(text)[0], "REVISE")

    def test_missing_verdict_is_none(self):
        self.assertIsNone(L.parse_verdict("no verdict here")[0])


def _claude_json(text="VERDICT: PASS", cost=0.01, inp=1000, out=50, is_error=False):
    return json.dumps({"result": text, "total_cost_usd": cost, "is_error": is_error,
                       "usage": {"input_tokens": 2, "cache_creation_input_tokens": inp,
                                 "cache_read_input_tokens": 0, "output_tokens": out}})


class TestClaudeAsk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "usage.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def test_call_is_lean_json_and_usage_is_recorded(self):
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"], seen["input"] = cmd, kw.get("input")
            return _Proc(0, _claude_json(cost=0.0123, inp=4000, out=80))

        reply = L.claude_ask("hello", "sonnet", tag="B30-R1", runner=runner, usage_log=self.log, claude_cmd=["claude"])
        cmd = seen["cmd"]
        self.assertEqual(reply.text, "VERDICT: PASS")
        self.assertIn("--output-format", cmd)
        self.assertEqual(cmd[cmd.index("--output-format") + 1], "json")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertIn("--strict-mcp-config", cmd)
        self.assertIn("--disable-slash-commands", cmd)
        self.assertNotIn("--bare", cmd)
        self.assertEqual(seen["input"], "hello")
        entry = json.loads(self.log.read_text().splitlines()[-1])
        self.assertEqual(entry["tag"], "B30-R1")
        self.assertEqual(entry["model"], "sonnet")
        self.assertAlmostEqual(entry["cost_usd"], 0.0123)
        self.assertEqual(entry["input_tokens"], 4002)
        self.assertEqual(entry["output_tokens"], 80)
        self.assertAlmostEqual(L.spent_usd(self.log), 0.0123)

    def test_budget_is_enforced_before_the_call_is_made(self):
        self.log.write_text(json.dumps({"cost_usd": 4.99}) + "\n")
        called = []
        with self.assertRaises(L.BudgetExceeded):
            L.claude_ask("x", "opus", tag="t", runner=lambda *a, **k: called.append(1), usage_log=self.log,
                         budget_usd=5.0, min_call_usd=0.05, claude_cmd=["claude"])
        self.assertEqual(called, [])

    def test_per_call_cap_never_exceeds_the_remaining_budget(self):
        self.log.write_text(json.dumps({"cost_usd": 4.50}) + "\n")
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"] = cmd
            return _Proc(0, _claude_json())

        L.claude_ask("x", "opus", tag="t", runner=runner, usage_log=self.log, budget_usd=5.0, per_call_cap_usd=1.5,
                     claude_cmd=["claude"])
        cap = float(seen["cmd"][seen["cmd"].index("--max-budget-usd") + 1])
        self.assertAlmostEqual(cap, 0.5, places=2)

    def test_tool_mode_passes_allowed_tools_instead_of_disabling_tools(self):
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"] = cmd
            return _Proc(0, _claude_json())

        L.claude_ask("x", "opus", tag="t", tools=["Read", "Grep"], runner=runner, usage_log=self.log,
                     claude_cmd=["claude"])
        self.assertIn("--allowedTools", seen["cmd"])
        self.assertNotIn("--tools", seen["cmd"])

    def test_non_json_output_and_error_results_raise(self):
        with self.assertRaises(L.ClaudeError):
            L.claude_ask("x", "haiku", tag="t", runner=lambda *a, **k: _Proc(0, "not json"),
                         usage_log=self.log, claude_cmd=["claude"])
        with self.assertRaises(L.ClaudeError):
            L.claude_ask("x", "haiku", tag="t", runner=lambda *a, **k: _Proc(0, _claude_json(is_error=True)),
                         usage_log=self.log, claude_cmd=["claude"])

    def test_summary_totals_by_model(self):
        for model, cost in (("sonnet", 0.02), ("sonnet", 0.03), ("opus", 0.4)):
            L.record_usage({"model": model, "cost_usd": cost, "input_tokens": 100, "output_tokens": 10}, self.log)
        s = L.usage_summary(self.log)
        self.assertAlmostEqual(s["total_usd"], 0.45)
        self.assertEqual(s["calls"], 3)
        self.assertEqual(s["by_model"]["sonnet"]["calls"], 2)


if __name__ == "__main__":
    unittest.main()
