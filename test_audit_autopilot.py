"""State-machine tests for audit/autopilot.py (fix -> discover -> explore -> release) with fake hooks."""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "audit")

import autopilot as A  # noqa: E402


class FakeHooks:
    def __init__(self, fix=("done",), discover=(), explore=(), release=True):
        self.fix_results = list(fix)
        self.discover_results = list(discover)
        self.explore_results = list(explore)
        self.release_ok = release
        self.calls = []

    def fix_loop(self):
        self.calls.append("fix")
        return self.fix_results.pop(0) if self.fix_results else "done"

    def discover(self):
        self.calls.append("discover")
        return self.discover_results.pop(0) if self.discover_results else []

    def explore(self, area):
        self.calls.append(f"explore:{area}")
        return self.explore_results.pop(0) if self.explore_results else []

    def start_batch(self, number):
        self.calls.append(f"start:{number}")

    def release(self):
        self.calls.append("release")
        return self.release_ok

    def log(self, message):
        self.calls.append(f"log:{message}")


class TestStateMachine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tmp.name) / "autopilot.json"
        self.addCleanup(self.tmp.cleanup)

    def run_ap(self, hooks, **kw):
        ap = A.Autopilot(hooks, state_file=self.state_file, **kw)
        return ap.run(), [c for c in hooks.calls if not c.startswith("log:")]

    def test_clean_project_goes_straight_to_a_release(self):
        result, calls = self.run_ap(FakeHooks())
        self.assertEqual(result, "released")
        self.assertEqual(calls, ["fix", "discover", "release"])

    def test_discovered_batches_are_fixed_then_discovery_runs_again(self):
        hooks = FakeHooks(discover=([30, 31], []))
        result, calls = self.run_ap(hooks)
        self.assertEqual(result, "released")
        self.assertEqual(calls, ["fix", "discover", "start:30", "fix", "discover", "release"])

    def test_a_blocked_fix_loop_stops_everything_and_never_releases(self):
        result, calls = self.run_ap(FakeHooks(fix=("blocked",)))
        self.assertEqual(result, "blocked")
        self.assertNotIn("release", calls)
        self.assertNotIn("discover", calls)

    def test_an_exhausted_budget_stops_with_its_own_result(self):
        result, calls = self.run_ap(FakeHooks(fix=("budget",)))
        self.assertEqual(result, "budget")
        self.assertNotIn("release", calls)

    def test_discovery_cycles_are_bounded_so_the_loop_cannot_churn_forever(self):
        hooks = FakeHooks(discover=([30], [31], [32], [33], [34]))
        result, calls = self.run_ap(hooks, max_cycles=2)
        self.assertEqual(result, "released")
        self.assertEqual(calls.count("discover"), 2)
        self.assertEqual(calls[-1], "release")

    def test_exploration_runs_only_when_enabled_and_rotates_areas(self):
        hooks = FakeHooks(explore=([], []))
        result, calls = self.run_ap(hooks, explore_rounds=2)
        explored = [c for c in calls if c.startswith("explore:")]
        self.assertEqual(len(explored), 2)
        self.assertNotEqual(explored[0], explored[1])
        self.assertEqual(calls[-1], "release")
        result, calls = self.run_ap(FakeHooks())
        self.assertFalse([c for c in calls if c.startswith("explore:")])

    def test_proven_findings_from_exploration_are_fixed_before_releasing(self):
        hooks = FakeHooks(explore=([40],), discover=([], []))
        result, calls = self.run_ap(hooks, explore_rounds=1)
        self.assertEqual(calls, ["fix", "discover", "explore:" + A.AREAS[0], "start:40", "fix", "discover", "release"])

    def test_a_failed_release_gate_is_reported_not_hidden(self):
        result, calls = self.run_ap(FakeHooks(release=False))
        self.assertEqual(result, "release-blocked")

    def test_progress_is_saved_so_a_restart_resumes_in_the_right_phase(self):
        hooks = FakeHooks(fix=("done", "blocked"), discover=([30],))
        self.run_ap(hooks)
        saved = json.loads(self.state_file.read_text())
        self.assertEqual(saved["phase"], "fix")
        self.assertEqual(saved["cycles"], 1)
        resumed = FakeHooks(fix=("done",), discover=([],))
        result, calls = self.run_ap(resumed)
        self.assertEqual(result, "released")
        self.assertEqual(calls[0], "fix")
        self.assertEqual(calls.count("discover"), 1)


if __name__ == "__main__":
    unittest.main()
