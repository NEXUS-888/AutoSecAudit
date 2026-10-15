"""Tests for audit/release_gate.py: a release is cut only when every required gate passes."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, "audit")

import release_gate as R  # noqa: E402

PY = sys.executable


def sh(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


class TestVersions(unittest.TestCase):
    def test_bumps(self):
        self.assertEqual(R.next_version("v2.0.3", "patch"), "2.0.4")
        self.assertEqual(R.next_version("v2.0.3", "minor"), "2.1.0")
        self.assertEqual(R.next_version("v2.4.9", "major"), "3.0.0")

    def test_without_a_previous_tag_the_base_version_is_used(self):
        self.assertEqual(R.next_version(None, "patch", base="2.0.0"), "2.0.1")
        self.assertEqual(R.next_version(None, "minor", base="2.0.0"), "2.1.0")

    def test_unusable_tag_is_rejected(self):
        with self.assertRaises(ValueError):
            R.next_version("release-final", "patch")


class TestChangelog(unittest.TestCase):
    def test_conventional_commits_are_grouped_and_noise_is_dropped(self):
        subjects = [
            "feat(scanning): add GraphQL scanner",
            "fix(ui): escape the report title",
            "fix(audit): resolve batch B12 (AUD-32, AUD-33)",
            "docs: explain the loop",
            "test: run the suite in parallel",
            "chore(audit): add batches B26-B29",
            "Merge branch 'x'",
            "some free-form message",
        ]
        text = R.changelog_section(subjects, "2.1.0", "2026-10-15")
        self.assertIn("## v2.1.0 — 2026-10-15", text)
        self.assertIn("### Features", text)
        self.assertIn("add GraphQL scanner", text)
        self.assertIn("### Fixes", text)
        self.assertIn("escape the report title", text)
        self.assertIn("resolve batch B12", text)
        self.assertIn("### Documentation", text)
        self.assertIn("### Tests", text)
        self.assertNotIn("add batches B26-B29", text)       # loop bookkeeping is not a user-facing change
        self.assertNotIn("Merge branch", text)
        self.assertIn("some free-form message", text)       # kept under 'Other', never silently dropped

    def test_empty_history_still_produces_a_section(self):
        self.assertIn("No user-facing changes", R.changelog_section([], "2.0.1", "2026-10-15"))


class Repo:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="release_"))
        sh(["git", "init", "-q"], self.dir)
        for k, v in (("user.email", "t@example.test"), ("user.name", "tester"), ("core.autocrlf", "false")):
            sh(["git", "config", k, v], self.dir)
        (self.dir / "audit").mkdir()
        (self.dir / "app.py").write_text("print('hi')\n", encoding="utf-8")
        (self.dir / ".gitignore").write_text("dist/\n", encoding="utf-8")
        self.commit("feat(core): first feature")

    def commit(self, subject, name=None):
        if name:
            (self.dir / name).write_text(subject, encoding="utf-8")
        sh(["git", "add", "-A"], self.dir)
        sh(["git", "commit", "-q", "--allow-empty", "-m", subject], self.dir)

    def gates(self, specs):
        (self.dir / "audit" / "release_gates.json").write_text(json.dumps(specs), encoding="utf-8")
        sh(["git", "add", "-A"], self.dir)
        sh(["git", "commit", "-q", "-m", "chore: gates"], self.dir)

    def tags(self):
        return sh(["git", "tag"], self.dir).stdout.split()

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestRelease(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)

    def test_all_gates_passing_cuts_a_tagged_release_with_artifacts(self):
        self.repo.gates([{"name": "tests", "cmd": ["{py}", "-c", "pass"], "required": True},
                         {"name": "extra", "cmd": ["{py}", "-c", "pass"], "required": False}])
        self.repo.commit("fix(core): repair the thing", name="fix.txt")
        result = R.release(root=self.repo.dir, bump="minor", base="2.0.0", today="2026-10-15")
        self.assertTrue(result.released, result.report)
        self.assertEqual(result.version, "2.1.0")
        self.assertIn("v2.1.0", self.repo.tags())
        self.assertEqual((self.repo.dir / "VERSION").read_text().strip(), "2.1.0")
        changelog = (self.repo.dir / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## v2.1.0", changelog)
        self.assertIn("repair the thing", changelog)
        archive = self.repo.dir / "dist" / "autosecaudit-v2.1.0.zip"
        self.assertTrue(archive.exists())
        with zipfile.ZipFile(archive) as z:
            self.assertIn("app.py", z.namelist())
        report = (self.repo.dir / "audit" / "RELEASE_REPORT.md").read_text(encoding="utf-8")
        self.assertIn("| tests | PASS |", report)
        self.assertEqual(sh(["git", "status", "--porcelain"], self.repo.dir).stdout.strip(), "")

    def test_a_failing_required_gate_blocks_the_release_and_changes_nothing(self):
        self.repo.gates([{"name": "tests", "cmd": ["{py}", "-c", "import sys; sys.exit(1)"], "required": True}])
        before = sh(["git", "rev-parse", "HEAD"], self.repo.dir).stdout
        result = R.release(root=self.repo.dir, bump="patch", base="2.0.0", today="2026-10-15")
        self.assertFalse(result.released)
        self.assertEqual(self.repo.tags(), [])
        self.assertEqual(sh(["git", "rev-parse", "HEAD"], self.repo.dir).stdout, before)
        self.assertFalse((self.repo.dir / "VERSION").exists())
        self.assertIn("| tests | FAIL |", result.report)

    def test_a_failing_optional_gate_is_reported_but_does_not_block(self):
        self.repo.gates([{"name": "tests", "cmd": ["{py}", "-c", "pass"], "required": True},
                         {"name": "py310", "cmd": ["{py}", "-c", "import sys; sys.exit(1)"], "required": False}])
        result = R.release(root=self.repo.dir, bump="patch", base="2.0.0", today="2026-10-15")
        self.assertTrue(result.released)
        self.assertIn("| py310 | FAIL (optional) |", result.report)

    def test_a_missing_optional_interpreter_is_skipped_not_failed(self):
        self.repo.gates([{"name": "tests", "cmd": ["{py}", "-c", "pass"], "required": True},
                         {"name": "py310", "cmd": ["no-such-interpreter-xyz", "run_tests.py"], "required": False}])
        result = R.release(root=self.repo.dir, bump="patch", base="2.0.0", today="2026-10-15")
        self.assertTrue(result.released)
        self.assertIn("| py310 | SKIPPED", result.report)

    def test_a_dirty_working_tree_blocks_the_release(self):
        self.repo.gates([{"name": "tests", "cmd": ["{py}", "-c", "pass"], "required": True}])
        (self.repo.dir / "uncommitted.txt").write_text("x", encoding="utf-8")
        result = R.release(root=self.repo.dir, bump="patch", base="2.0.0", today="2026-10-15")
        self.assertFalse(result.released)
        self.assertIn("uncommitted", result.report.lower())
        self.assertEqual(self.repo.tags(), [])

    def test_the_second_release_bumps_from_the_previous_tag(self):
        self.repo.gates([{"name": "tests", "cmd": ["{py}", "-c", "pass"], "required": True}])
        R.release(root=self.repo.dir, bump="patch", base="2.0.0", today="2026-10-15")
        self.repo.commit("feat(core): another", name="b.txt")
        second = R.release(root=self.repo.dir, bump="patch", base="2.0.0", today="2026-10-16")
        self.assertTrue(second.released, second.report)
        self.assertEqual(second.version, "2.0.2")
        changelog = (self.repo.dir / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertLess(changelog.index("v2.0.2"), changelog.index("v2.0.1"))   # newest first


if __name__ == "__main__":
    unittest.main()
