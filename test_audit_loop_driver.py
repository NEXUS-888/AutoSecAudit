"""End-to-end test of audit/run_loop.py in a throwaway git repository with a fake `claude`.

Covers the paths that decide how many Claude tokens a batch costs: mechanical verification (none),
diff-only review (small, metered), model choice for security-sensitive files, and the dollar budget.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
PY = sys.executable

BACKLOG = textwrap.dedent("""\
    # Backlog

    ## Rules of the loop
    - test rules

    ---

    ## B01 — Mechanical batch
    **Verification:** mechanical

    ### AUD-01 · Needs a file
    - **Files:** `core/x.py`
    - **Check:** `{py} -c "import os, sys; sys.exit(0 if os.path.exists('core/x.py') else 1)"`

    ---

    ## B02 — Review batch

    ### AUD-02 · Needs judgement
    - **Files:** `plugins/p.py`
    - **Acceptance:** judged by a reviewer.

    ---

    ## Deferred
    - nothing
    """)

FAKE_CLAUDE = textwrap.dedent("""\
    import json, os, sys
    prompt = sys.stdin.read()
    open(os.environ["FAKE_CLAUDE_PROMPT"], "w", encoding="utf-8").write(prompt)
    args = " ".join(sys.argv[1:])
    open(os.environ["FAKE_CLAUDE_ARGS"], "w", encoding="utf-8").write(args)
    verdict = os.environ.get("FAKE_VERDICT", "PASS")
    text = f"VERDICT: {verdict}\\n# Review B02 round 1\\n| Issue | Verdict | Evidence |\\n|---|---|---|\\n| AUD-02 | PASS | ok |\\n"
    print(json.dumps({"result": text, "total_cost_usd": 0.01, "is_error": False,
                      "usage": {"input_tokens": 5, "cache_creation_input_tokens": 900,
                                "cache_read_input_tokens": 0, "output_tokens": 40}}))
    """)


def sh(args, cwd, **kw):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


class DriverRepo:
    def __init__(self, batch="01"):
        self.dir = Path(tempfile.mkdtemp(prefix="loop_driver_"))
        d = self.dir
        for sub in ("audit/handoffs", "audit/reviews", "core", "plugins"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        for name in ("loop_lib.py", "show_batch.py"):
            shutil.copy(REPO / "audit" / name, d / "audit" / name)
        shutil.copy(REPO / "audit" / "run_loop.py", d / "audit" / "run_loop.py")
        (d / "audit" / "VERIFIER.md").write_text("You are the verifier.\n", encoding="utf-8")
        (d / "audit" / "BACKLOG.md").write_text(BACKLOG, encoding="utf-8")
        (d / "core" / "utils.py").write_text("X = 1\n", encoding="utf-8")
        (d / "requirements.txt").write_text("", encoding="utf-8")
        (d / "run_tests.py").write_text(
            "print('Total Tests Executed : 1')\nprint('Total Failures       : 0')\nprint('Total Errors         : 0')\n",
            encoding="utf-8")
        (d / "fake_claude.py").write_text(FAKE_CLAUDE, encoding="utf-8")
        sh(["git", "init", "-q"], d)
        sh(["git", "config", "user.email", "t@example.test"], d)
        sh(["git", "config", "user.name", "tester"], d)
        sh(["git", "config", "core.autocrlf", "false"], d)
        sh(["git", "add", "-A"], d)
        sh(["git", "commit", "-q", "-m", "init"], d)
        self.base = sh(["git", "rev-parse", "HEAD"], d).stdout.strip()
        (d / "audit" / "STATE.md").write_text(
            f"# state\n\nbatch: {batch}\nround: 1\nstatus: ready_for_review\nbase: {self.base}\ntests: 1\n",
            encoding="utf-8")
        (d / "audit" / "handoffs" / f"B{batch}-R1.md").write_text("# Handoff\nDid the thing.\n", encoding="utf-8")
        self.prompt_file, self.args_file = d / "prompt.txt", d / "args.txt"

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def run_driver(self, budget="5", verdict="PASS"):
        env = dict(os.environ)
        env.update({
            "AUTOSEC_CLAUDE_CMD": f'"{Path(PY).as_posix()}" "{(self.dir / "fake_claude.py").as_posix()}"',
            "FAKE_CLAUDE_PROMPT": str(self.prompt_file), "FAKE_CLAUDE_ARGS": str(self.args_file),
            "FAKE_VERDICT": verdict, "AUTOSEC_LOOP_BUDGET_USD": budget,
        })
        return subprocess.run([PY, "audit/run_loop.py", "--once"], cwd=self.dir, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=300)

    def state(self):
        out = {}
        for line in (self.dir / "audit" / "STATE.md").read_text(encoding="utf-8").splitlines():
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    def last_commit_message(self):
        return sh(["git", "log", "-1", "--format=%B"], self.dir).stdout

    def commits(self):
        return int(sh(["git", "rev-list", "--count", "HEAD"], self.dir).stdout.strip())

    def usage(self):
        log = self.dir / ".git" / "audit-loop" / "usage.jsonl"
        return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestDriver(unittest.TestCase):
    def make(self, batch="01"):
        repo = DriverRepo(batch)
        self.addCleanup(repo.cleanup)
        return repo

    def test_mechanical_batch_is_verified_without_any_claude_call(self):
        repo = self.make("01")
        repo.write("core/x.py", "VALUE = 1\n")
        r = repo.run_driver()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(repo.usage(), [], "a mechanical batch must not call Claude")
        self.assertFalse(repo.prompt_file.exists())
        self.assertEqual(repo.commits(), 2)
        self.assertIn("mechanical checks", repo.last_commit_message())
        self.assertEqual(repo.state()["batch"], "02")
        self.assertEqual(repo.state()["status"], "ready_for_fix")

    def test_failing_mechanical_check_sends_the_batch_back_with_the_command_output(self):
        repo = self.make("01")          # core/x.py is NOT created, so the check fails
        repo.write("core/other.py", "pass\n")
        r = repo.run_driver()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(repo.usage(), [])
        self.assertEqual(repo.commits(), 1)
        self.assertEqual(repo.state()["status"], "revise")
        self.assertEqual(repo.state()["round"], "2")
        review = (repo.dir / "audit" / "reviews" / "B01-R1.md").read_text(encoding="utf-8")
        self.assertIn("Required changes", review)
        self.assertIn("core/x.py", review)

    def test_review_batch_uses_a_lean_diff_only_call_on_the_light_model(self):
        repo = self.make("02")
        repo.write("plugins/p.py", "def feature():\n    return 'UNIQUE_MARKER_LINE'\n")
        r = repo.run_driver()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        prompt = repo.prompt_file.read_text(encoding="utf-8")
        args = repo.args_file.read_text(encoding="utf-8")
        self.assertIn("UNIQUE_MARKER_LINE", prompt)             # the diff, including a NEW file, is in the prompt
        self.assertIn("VERDICT: PASS|REVISE", prompt)
        self.assertIn("Did the thing.", prompt)                 # the handoff
        self.assertIn("AUD-02", prompt)                         # the acceptance criteria
        self.assertIn("--tools", args)
        self.assertIn("--strict-mcp-config", args)
        self.assertNotIn("--allowedTools", args)
        self.assertEqual(args.split("--model ")[1].split()[0], "sonnet")
        usage = repo.usage()
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["model"], "sonnet")
        self.assertIn("Claude (sonnet)", repo.last_commit_message())
        self.assertEqual(repo.state()["status"], "done")   # B02 is the last batch in the sample backlog

    def test_a_failing_check_in_a_review_batch_is_rejected_without_calling_claude(self):
        repo = self.make("02")
        text = (repo.dir / "audit" / "BACKLOG.md").read_text(encoding="utf-8")
        check = "- **Check:** `{py} -c \"import sys; sys.exit(3)\"`"
        text = text.replace("- **Acceptance:** judged by a reviewer.", "- **Acceptance:** judged by a reviewer.\n" + check)
        (repo.dir / "audit" / "BACKLOG.md").write_text(text, encoding="utf-8")
        sh(["git", "add", "-A"], repo.dir)
        sh(["git", "commit", "-q", "-m", "backlog with a check"], repo.dir)
        repo.write("plugins/p.py", "x = 1\n")
        r = repo.run_driver()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(repo.prompt_file.exists(), "a failing check must not reach Claude")
        self.assertEqual(repo.usage(), [])
        self.assertEqual(repo.state()["status"], "revise")

    def test_security_sensitive_change_uses_the_strong_model(self):
        repo = self.make("02")
        repo.write("core/auth.py", "def login():\n    return True\n")
        r = repo.run_driver()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(repo.usage()[0]["model"], "opus")

    def test_revise_verdict_sends_the_batch_back_and_does_not_commit(self):
        repo = self.make("02")
        repo.write("plugins/p.py", "x = 1\n")
        r = repo.run_driver(verdict="REVISE")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(repo.commits(), 1)
        self.assertEqual(repo.state()["status"], "revise")

    def test_exhausted_budget_blocks_the_loop_without_calling_claude(self):
        repo = self.make("02")
        repo.write("plugins/p.py", "x = 1\n")
        r = repo.run_driver(budget="0.001")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(repo.prompt_file.exists())
        self.assertEqual(repo.commits(), 1)
        self.assertEqual(repo.state()["status"], "blocked")
        self.assertIn("budget", (r.stdout + r.stderr).lower())


if __name__ == "__main__":
    unittest.main()
