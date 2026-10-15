"""Tests for audit/validate_candidate.py: an explorer's finding counts only if a test proves it."""
import json
import shutil
import sys
import tempfile
import textwrap
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, "audit")

import loop_lib as L  # noqa: E402
import validate_candidate as V  # noqa: E402

FINDING = textwrap.dedent("""\
    # Login accepts an empty password
    **Area:** core/auth.py
    **Impact:** Anyone can log in as any user with an empty password.

    ## Reproduction
    Call verify_user with an empty password; it returns success.
    """)

FAILING_TEST = textwrap.dedent("""\
    import unittest

    class T(unittest.TestCase):
        def test_empty_password_is_rejected(self):
            self.assertEqual(1 + 1, 3, "empty password was accepted")
    """)

BACKLOG = "# Backlog\n\n## Rules of the loop\n- r\n\n---\n\n## B05 — Existing\n\n### AUD-09 · x\n- **Files:** `a.py`\n\n---\n\n## Deferred\n- later\n"


class Env:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="cand_root_"))
        (self.root / "audit" / "candidates").mkdir(parents=True)
        (self.root / "audit" / "BACKLOG.md").write_text(BACKLOG, encoding="utf-8")

    def candidate(self, slug="empty-password", finding=FINDING, test=FAILING_TEST, test_name=None):
        d = self.root / "audit" / "candidates" / f"CAND-{slug}"
        d.mkdir(parents=True, exist_ok=True)
        if finding is not None:
            (d / "finding.md").write_text(finding, encoding="utf-8")
        if test is not None:
            (d / (test_name or f"test_cand_{slug.replace('-', '_')}.py")).write_text(test, encoding="utf-8")
        return d

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class TestValidate(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def validate(self, d):
        return V.validate(d, root=self.env.root, runs=3, timeout=60)

    def test_a_stable_assertion_failure_is_proven(self):
        v = self.validate(self.env.candidate())
        self.assertEqual(v.status, "proven", v.reason)
        self.assertEqual(v.failing_tests, ["test_empty_password_is_rejected"])

    def test_a_passing_test_proves_nothing(self):
        d = self.env.candidate(test="import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n")
        v = self.validate(d)
        self.assertEqual(v.status, "rejected")
        self.assertIn("passes", v.reason)

    def test_an_import_error_is_not_a_finding(self):
        d = self.env.candidate(test="import module_that_does_not_exist_xyz\nimport unittest\n")
        v = self.validate(d)
        self.assertEqual(v.status, "rejected")

    def test_a_crashing_test_is_not_a_finding(self):
        # An exception inside the test (not an assertion) shows a bug in the test, not in the code.
        test = "import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n        raise RuntimeError('boom')\n"
        v = self.validate(self.env.candidate(slug="crash", test=test))
        self.assertEqual(v.status, "rejected")
        self.assertIn("errors instead of failing", v.reason)

    def test_an_unstable_failure_is_rejected(self):
        marker = Path(tempfile.gettempdir()) / f"flaky_{uuid.uuid4().hex}"
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        test = textwrap.dedent(f"""\
            import unittest, pathlib
            class T(unittest.TestCase):
                def test_flaky(self):
                    m = pathlib.Path({str(marker)!r})
                    if not m.exists():
                        m.write_text("x")
                        self.fail("first run only")
            """)
        v = self.validate(self.env.candidate(slug="flaky", test=test))
        self.assertEqual(v.status, "rejected")
        self.assertIn("stable", v.reason)

    def test_incomplete_finding_description_is_rejected(self):
        v = self.validate(self.env.candidate(finding="# Title only\n"))
        self.assertEqual(v.status, "rejected")
        self.assertIn("finding.md", v.reason)

    def test_missing_or_misnamed_test_file_is_rejected(self):
        self.assertEqual(self.validate(self.env.candidate(slug="a", test=None)).status, "rejected")
        self.assertEqual(self.validate(self.env.candidate(slug="b", test_name="check_b.py")).status, "rejected")

    def test_dangerous_calls_and_imports_are_rejected_before_running(self):
        for body in ("import subprocess\nsubprocess.run(['x'])\n",
                     "import os\nos.system('echo hi')\n",
                     "import shutil\nshutil.rmtree('/')\n",
                     "eval('1+1')\n"):
            test = "import unittest\n" + body + "class T(unittest.TestCase):\n    def test_x(self):\n        self.fail('x')\n"
            v = self.validate(self.env.candidate(slug="danger", test=test))
            self.assertEqual(v.status, "rejected", body)
            self.assertIn("not allowed", v.reason)

    def test_only_loopback_urls_are_allowed(self):
        bad = "import unittest\nURL = 'http://evil.example.com/x'\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.fail('x')\n"
        v = self.validate(self.env.candidate(slug="net", test=bad))
        self.assertEqual(v.status, "rejected")
        self.assertIn("loopback", v.reason)
        good = bad.replace("evil.example.com", "127.0.0.1:5000")
        self.assertEqual(self.validate(self.env.candidate(slug="net2", test=good)).status, "proven")


class TestAccept(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def test_accepting_copies_the_test_and_queues_a_review_batch_with_a_check(self):
        d = self.env.candidate()
        number = V.accept(d, root=self.env.root)
        self.assertEqual(number, 6)
        copied = self.env.root / "test_cand_empty_password.py"
        self.assertTrue(copied.exists())
        batch = L.parse_backlog((self.env.root / "audit" / "BACKLOG.md").read_text(encoding="utf-8"))["06"]
        self.assertEqual(batch.verification, "review")        # a test can be gamed; a diff review still happens
        self.assertEqual(batch.issues[0].id, "AUD-10")
        self.assertEqual(batch.issues[0].checks, ["{py} -m unittest test_cand_empty_password"])
        text = (self.env.root / "audit" / "BACKLOG.md").read_text(encoding="utf-8")
        self.assertIn("Login accepts an empty password", text)
        self.assertIn("do not edit", text.lower())
        self.assertLess(text.index("## B06"), text.index("## Deferred"))

    def test_the_same_candidate_is_never_queued_twice(self):
        d = self.env.candidate()
        V.accept(d, root=self.env.root)
        with self.assertRaises(FileExistsError):
            V.accept(d, root=self.env.root)


class TestProcessAll(unittest.TestCase):
    def test_proven_candidates_are_queued_and_rejected_ones_are_marked(self):
        env = Env()
        self.addCleanup(env.cleanup)
        env.candidate(slug="good")
        env.candidate(slug="bad", test="import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n")
        summary = V.process_all(root=env.root, runs=3, timeout=60)
        self.assertEqual(sorted(summary["proven"]), ["CAND-good"])
        self.assertEqual(sorted(summary["rejected"]), ["CAND-bad"])
        proof = json.loads((env.root / "audit" / "candidates" / "CAND-bad" / "proof.json").read_text())
        self.assertEqual(proof["status"], "rejected")
        again = V.process_all(root=env.root, runs=3, timeout=60)      # already decided: not re-run, not re-queued
        self.assertEqual(again, {"proven": [], "rejected": [], "queued_batches": []})


if __name__ == "__main__":
    unittest.main()
