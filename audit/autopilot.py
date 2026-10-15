#!/usr/bin/env python3
"""Run the whole improvement cycle unattended: fix -> discover -> (explore) -> release.

    python audit/autopilot.py [--max-cycles 3] [--explore-rounds 0] [--bump minor]

  fix       run audit/run_loop.py until every batch passed (Antigravity fixes, the verifier checks)
  discover  ruff / bandit / pip-audit find new issues -> mechanical batches (no Claude)
  explore   optional: Antigravity hunts for defects in one code area and must prove each with a failing
            test; only proven findings become batches (audit/validate_candidate.py, no Claude)
  release   audit/release_gate.py: tests, static analysis, changelog, tag, archive; nothing changes unless
            every required gate passes

It stops (and says why) when a batch is blocked, when the Claude budget is spent, or when a release gate fails.
Progress is saved to .git/audit-loop/autopilot.json, so it can be restarted at any point.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".git" / "audit-loop"
STATE_FILE = RUNTIME / "autopilot.json"

AREAS = ["plugins/ (scanner plugins: detection logic, false positives)",
         "core/ (engine, crawler, http client, pipeline, authenticator)",
         "ui/ (Flask dashboard: auth, sessions, report access, scan jobs)",
         "intelligence/ and reports/ (correlation, delta, grading, report output)",
         "mcp_server.py, main.py and config.py (entry points and configuration)"]


class Autopilot:
    def __init__(self, hooks, state_file: Path = STATE_FILE, max_cycles: int = 3, explore_rounds: int = 0):
        self.hooks = hooks
        self.state_file = Path(state_file)
        self.max_cycles = max_cycles
        self.explore_rounds = explore_rounds

    def _load(self) -> dict:
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text(encoding="utf-8"))
            except ValueError:
                pass
        return {"phase": "fix", "cycles": 0, "explored": 0}

    def _save(self, state: dict) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

    def run(self) -> str:
        state = self._load()
        say = self.hooks.log
        while True:
            self._save(state)
            phase = state["phase"]
            if phase == "fix":
                say("phase: fix")
                result = self.hooks.fix_loop()
                if result != "done":
                    say(f"stopped: fix loop ended with '{result}'")
                    return result
                state["phase"] = "discover"
            elif phase == "discover":
                if state["cycles"] >= self.max_cycles:
                    say(f"discovery cycle limit ({self.max_cycles}) reached; moving to release")
                    state["phase"] = "release"
                    continue
                say("phase: discover")
                state["cycles"] += 1
                batches = self.hooks.discover()
                if batches:
                    self.hooks.start_batch(batches[0])
                    state["phase"] = "fix"
                else:
                    state["phase"] = "explore" if state["explored"] < self.explore_rounds else "release"
            elif phase == "explore":
                area = AREAS[state["explored"] % len(AREAS)]
                say(f"phase: explore ({area})")
                state["explored"] += 1
                batches = self.hooks.explore(area)
                if batches:
                    self.hooks.start_batch(batches[0])
                    state["phase"] = "fix"
                elif state["explored"] >= self.explore_rounds:
                    state["phase"] = "release"
            elif phase == "release":
                say("phase: release")
                ok = self.hooks.release()
                state["phase"] = "released" if ok else "release-blocked"
                self._save(state)
                return "released" if ok else "release-blocked"
            else:
                return phase


# ---------------------------------------------------------------------------
# Real hooks
# ---------------------------------------------------------------------------
class RealHooks:
    def __init__(self):
        import run_loop
        import loop_lib
        import discover
        import validate_candidate
        import release_gate
        self.rl, self.ll, self.disc, self.val, self.rel = run_loop, loop_lib, discover, validate_candidate, release_gate

    def log(self, message: str) -> None:
        self.rl.log(f"[autopilot] {message}")

    def _git(self, *args):
        return self.rl.git(*args)

    def _commit(self, paths, message: str) -> None:
        self._git("add", *paths)
        self._git("commit", "-q", "-m", message + "\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>")

    def fix_loop(self) -> str:
        if self.rl.read_state().get("status") == "done":
            return "done"
        code = subprocess.call([sys.executable, "audit/run_loop.py"], cwd=ROOT)
        status = self.rl.read_state().get("status")
        if status == "done":
            return "done"
        if self.ll.spent_usd() >= self.ll.default_budget_usd():
            return "budget"
        return "blocked" if code else status or "blocked"

    def start_batch(self, number: int) -> None:
        head = self._git("rev-parse", "HEAD").strip()
        self.rl.write_state(batch=f"{number:02d}", round="1", status="ready_for_fix", base=head)

    def discover(self) -> List[int]:
        cands = self.disc.collect()
        backlog = ROOT / "audit" / "BACKLOG.md"
        new_text, numbers = self.disc.append_batches(backlog.read_text(encoding="utf-8"), cands)
        if numbers:
            backlog.write_text(new_text, encoding="utf-8", newline="\n")
            self._commit(["audit/BACKLOG.md"], f"chore(audit): add tool-found batches {', '.join('B%02d' % n for n in numbers)}")
        return numbers

    def explore(self, area: str) -> List[int]:
        (ROOT / "audit" / "EXPLORE.md").write_text(
            f"# Exploration assignment\n\n**Area:** {area}\n\nFollow the explorer instructions in the audit-fix "
            "workflow (status `ready_for_explore`). Submit proven findings under audit/candidates/ and then set "
            "`status: explore_submitted` in audit/STATE.md.\n", encoding="utf-8")
        self.rl.write_state(status="ready_for_explore")
        self.log("waiting for the explorer (up to 3 hours)...")
        deadline = time.time() + 3 * 3600
        while time.time() < deadline and self.rl.read_state().get("status") != "explore_submitted":
            time.sleep(15)
        summary = self.val.process_all(root=ROOT)
        self.log(f"explorer result: {len(summary['proven'])} proven, {len(summary['rejected'])} rejected")
        if summary["queued_batches"]:
            self._commit(["audit/BACKLOG.md", "audit/candidates", *[p.name for p in ROOT.glob("test_cand_*.py")]],
                         f"chore(audit): queue {len(summary['proven'])} proven finding(s) from exploration")
        else:
            self.rl.write_state(status="done")
        return summary["queued_batches"]

    def release(self) -> bool:
        result = self.rel.release(bump="minor")
        self.log(("released v" + result.version) if result.released else "release blocked; see the report below")
        print(result.report)
        return result.released


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-cycles", type=int, default=3)
    parser.add_argument("--explore-rounds", type=int, default=0)
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    result = Autopilot(RealHooks(), max_cycles=args.max_cycles, explore_rounds=args.explore_rounds).run()
    print(f"autopilot finished: {result}")
    return 0 if result == "released" else 1


if __name__ == "__main__":
    sys.exit(main())
