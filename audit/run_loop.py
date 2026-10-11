#!/usr/bin/env python3
"""
Token-lean driver for the audit fix -> verify loop.

Everything mechanical (waiting, test runs, integrity checks, commits, state) is done here
with zero LLM tokens. Claude is called only to judge a batch, as a fresh headless
`claude -p` session on the model assigned to that batch, so no context builds up across
batches. Rounds that fail mechanical checks are sent back to Antigravity without calling
Claude at all.

    python audit/run_loop.py            # run until done or blocked
    python audit/run_loop.py --once     # handle the current state once, then exit
    python audit/run_loop.py --dry-run  # precheck only: no Claude call, no state change
"""

import argparse
import datetime
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "audit"
STATE = AUDIT / "STATE.md"
RUNTIME = ROOT / ".git" / "audit-loop"  # inside .git: never committed, never in diffs

LAST_BATCH = 18
MAX_ROUNDS = 4
SONNET_BATCHES = {"01", "06", "17"}  # mechanical batches; everything else is verified by Opus
PROTECTED = ("audit/BACKLOG.md", "audit/VERIFIER.md", "audit/run_loop.py",
             "audit/show_batch.py", "audit/wait_for_status.py", ".claude/")
TEST_FILE_RE = re.compile(r"(^|/)test_[^/]*\.py$")
SKIP_RE = re.compile(r"unittest\.skip|skipTest\(|expectedFailure|pytest\.mark\.(skip|xfail)|@skip")
VERIFIER_TOOLS = ["Read", "Grep", "Glob", "Bash(git diff:*)", "Bash(git show:*)", "Bash(git log:*)",
                  "Bash(git status:*)", "Bash(python:*)", "Bash(py:*)"]
VERIFIER_TIMEOUT = 2400
TEST_TIMEOUT = 1800


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def run(args, timeout=None, input_text=None):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, input=input_text)


def git(*args) -> str:
    result = run(["git", *args])
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def log(message: str) -> None:
    line = f"[{datetime.datetime.now():%H:%M:%S}] {message}"
    print(line, flush=True)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with open(RUNTIME / "loop.log", "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_state() -> dict:
    text = STATE.read_text(encoding="utf-8").split("<!--")[0]
    return dict(re.findall(r"^(\w+):\s*(\S+)", text, re.MULTILINE))


def _without_status(text: str) -> str:
    return re.sub(r"^status:.*$", "", text, flags=re.MULTILINE)


def write_state(**updates) -> None:
    text = STATE.read_text(encoding="utf-8")
    for key, value in updates.items():
        if re.search(rf"^{key}:", text, re.MULTILINE):
            text = re.sub(rf"^{key}:.*$", f"{key}: {value}", text, flags=re.MULTILINE)
        else:
            text = text.replace("\n<!--", f"\n{key}: {value}\n<!--", 1)
    STATE.write_text(text, encoding="utf-8")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    (RUNTIME / "state_snapshot").write_text(_without_status(text), encoding="utf-8")


def state_tampered() -> bool:
    snapshot = RUNTIME / "state_snapshot"
    if not snapshot.exists():
        return False
    return _without_status(STATE.read_text(encoding="utf-8")) != snapshot.read_text(encoding="utf-8")


def batch_ids(batch: str) -> str:
    text = run([sys.executable, "audit/show_batch.py", batch, "--no-rules"]).stdout
    return ", ".join(re.findall(r"### (AUD-\d+)", text))


def model_for(batch: str, round_no: int) -> str:
    return "sonnet" if batch in SONNET_BATCHES and round_no < MAX_ROUNDS else "opus"


def older_python():
    for candidate in (["py", "-3.10"], ["py", "-3.11"], ["python3.10"], ["python3.11"]):
        try:
            if run(candidate + ["-c", "pass"], timeout=30).returncode == 0:
                return candidate
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def run_tests(tag: str) -> dict:
    try:
        result = run([sys.executable, "run_tests.py"], timeout=TEST_TIMEOUT)
        output = result.stdout + result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        output, returncode = f"run_tests.py timed out after {TEST_TIMEOUT}s", 1
    RUNTIME.mkdir(parents=True, exist_ok=True)
    (RUNTIME / f"tests-{tag}.log").write_text(output, encoding="utf-8")

    def count(label):
        match = re.search(rf"{label}\s*:\s*(\d+)", output)
        return int(match.group(1)) if match else -1

    failing = [f"{kind}: {name} ({where})" for kind, name, where in
               re.findall(r"^(FAIL|ERROR): (\S+) \(([^)]+)\)", output, re.MULTILINE)]
    total, failures, errors = count("Total Tests Executed"), count("Total Failures"), count("Total Errors")
    return {"total": total, "failures": failures, "errors": errors, "failing": failing,
            "ok": returncode == 0 and failures == 0 and errors == 0 and total > 0}


# ---------------------------------------------------------------------------
# Mechanical precheck (no LLM)
# ---------------------------------------------------------------------------
def changed_files(base: str) -> list:
    tracked = git("diff", "--name-only", base).splitlines()
    untracked = git("ls-files", "-o", "--exclude-standard").splitlines()
    return sorted({f.strip().replace("\\", "/") for f in tracked + untracked if f.strip()})


def precheck(state: dict):
    batch, round_no, base = state["batch"], int(state["round"]), state["base"]
    hard, notes = [], []
    files = [f for f in changed_files(base) if f != "audit/STATE.md"]

    touched = [f for f in files if f.startswith(PROTECTED)]
    if touched:
        hard.append(f"Edited protected file(s): {', '.join(touched)}. Revert these edits.")
    if state_tampered():
        hard.append("audit/STATE.md changed beyond the `status:` line. Only `status:` may be edited.")
    handoff = AUDIT / "handoffs" / f"B{batch}-R{round_no}.md"
    if not handoff.exists():
        hard.append(f"Missing handoff file {handoff.relative_to(ROOT).as_posix()}.")

    added_asserts = removed_asserts = 0
    for f in (f for f in files if TEST_FILE_RE.search(f)):
        path = ROOT / f
        if not path.exists():
            hard.append(f"Test file deleted: {f}. Existing tests may not be removed.")
            continue
        tracked_at_base = run(["git", "cat-file", "-e", f"{base}:{f}"]).returncode == 0
        if tracked_at_base:
            diff = git("diff", base, "--", f).splitlines()
            added = [l[1:] for l in diff if l.startswith("+") and not l.startswith("+++")]
            removed = [l[1:] for l in diff if l.startswith("-") and not l.startswith("---")]
        else:
            added, removed = path.read_text(encoding="utf-8", errors="replace").splitlines(), []
        if any(SKIP_RE.search(l) for l in added):
            hard.append(f"{f}: adds a skip/xfail marker. Tests may not be skipped.")
        added_asserts += sum("assert" in l for l in added)
        removed_asserts += sum("assert" in l for l in removed)
    if removed_asserts > added_asserts:
        notes.append(f"More assertion lines removed ({removed_asserts}) than added ({added_asserts}) in tests — verifier should check.")

    old_py = older_python()
    py_line = "skipped (no 3.10/3.11 interpreter)"
    if old_py:
        result = run(old_py + ["-c", "import core.utils"], timeout=120)
        py_line = "ok" if result.returncode == 0 else "FAILED"
        if result.returncode != 0:
            last = (result.stderr.strip().splitlines() or ["?"])[-1]
            hard.append(f"`{' '.join(old_py)} -c \"import core.utils\"` fails: {last}")

    tests = run_tests(f"B{batch}-R{round_no}")
    if not tests["ok"]:  # one retry so a flaky test doesn't bounce a good batch
        first_failing = tests["failing"]
        tests = run_tests(f"B{batch}-R{round_no}-retry")
        if tests["ok"]:
            notes.append(f"Flaky on first run, green on retry: {'; '.join(first_failing[:5])}")
    baseline_total = int(state.get("tests", "0") or 0)
    if not tests["ok"]:
        listed = "; ".join(tests["failing"][:15]) or "see `python run_tests.py` output"
        hard.append(f"Test suite is not green (failures={tests['failures']}, errors={tests['errors']}): {listed}")
    if baseline_total and 0 <= tests["total"] < baseline_total:
        hard.append(f"Test count dropped from {baseline_total} to {tests['total']}. Existing tests may not be removed.")

    summary = "\n".join([
        f"Changed files ({len(files)}): {', '.join(files) or 'none'}",
        f"Tests: total {tests['total']} (baseline {baseline_total}), failures {tests['failures']}, errors {tests['errors']}",
        f"Py3.10/3.11 import core.utils: {py_line}",
        f"Assertion lines in test diffs: +{added_asserts} / -{removed_asserts}",
        "Hard failures: " + ("none" if not hard else "; ".join(hard)),
        *(f"Note: {n}" for n in notes),
    ])
    return hard, summary, tests["total"]


def auto_review(batch: str, round_no: int, hard: list) -> str:
    items = "\n".join(f"{i}. {h}" for i, h in enumerate(hard, 1))
    return (f"# Review B{batch} round {round_no} — REVISE (automatic precheck)\n\n"
            "The change failed mechanical checks, so it was not sent for code review.\n\n"
            f"## Required changes\n{items}\n\n"
            "Fix these, run `python run_tests.py` until green, then hand off again.\n")


# ---------------------------------------------------------------------------
# Headless Claude verification
# ---------------------------------------------------------------------------
def build_prompt(state: dict, summary: str) -> str:
    batch, round_no, base = state["batch"], int(state["round"]), state["base"]
    instructions = (AUDIT / "VERIFIER.md").read_text(encoding="utf-8")
    section = run([sys.executable, "audit/show_batch.py", batch]).stdout
    previous = f"audit/reviews/B{batch}-R{round_no - 1}.md" if round_no > 1 else "none"
    return (f"{instructions}\n\n---\n\n# Batch under review\n\n{section}\n\n---\n\n"
            f"# Context\n- Batch: B{batch}\n- Round: {round_no}\n- Base commit: {base}\n"
            f"- Handoff: audit/handoffs/B{batch}-R{round_no}.md\n- Previous review: {previous}\n\n"
            f"# Precheck summary (already verified mechanically)\n{summary}\n")


def verify_with_claude(state: dict, summary: str, model: str):
    claude = shutil.which("claude")
    if not claude:
        raise RuntimeError("`claude` CLI not found on PATH")
    prompt = build_prompt(state, summary)
    cmd = [claude, "-p", "--model", model, "--permission-mode", "dontAsk",
           "--no-session-persistence", "--output-format", "text", "--allowedTools", *VERIFIER_TOOLS]
    try:
        result = run(cmd, timeout=VERIFIER_TIMEOUT, input_text=prompt)
        output = result.stdout
    except subprocess.TimeoutExpired:
        output = ""
    tag = f"B{state['batch']}-R{state['round']}-{model}"
    (RUNTIME / f"verifier-{tag}.txt").write_text(output, encoding="utf-8")
    match = re.search(r"^VERDICT:\s*(PASS|REVISE)\b", output, re.MULTILINE)
    review = output[output.find("# Review"):] if "# Review" in output else output
    verdict = match.group(1) if match else None
    # A PASS whose own table reports FAIL/PARTIAL is treated as REVISE.
    if verdict == "PASS" and re.search(r"\|\s*(FAIL|PARTIAL)\s*\|", review):
        verdict = "REVISE"
    return verdict, review.strip() + "\n"


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------
def baseline() -> bool:
    dirty = [l for l in git("status", "--porcelain").splitlines()
             if not l[3:].strip('"').startswith(("audit/", ".claude/"))]
    if dirty:
        log("Working tree has uncommitted changes outside audit/. Commit or stash them, then re-run:")
        for line in dirty[:20]:
            print("   " + line)
        return False
    log("Running test suite for the baseline count...")
    tests = run_tests("baseline")
    if not tests["ok"]:
        tests = run_tests("baseline-retry")
    if not tests["ok"]:
        log(f"Baseline suite is not green ({tests['failing'][:5]}). Fix it before starting the loop.")
        return False
    git("add", "audit")
    if (ROOT / ".claude").exists():
        git("add", ".claude")
    if run(["git", "diff", "--cached", "--quiet"]).returncode != 0:
        git("commit", "-m", "chore(audit): add automated fix-verify loop and backlog")
    write_state(batch="01", round="1", status="ready_for_fix", base=git("rev-parse", "HEAD").strip(),
                tests=tests["total"])
    log(f"Baseline recorded ({tests['total']} tests). Antigravity can start: /audit-fix")
    return True


def review_round(state: dict, dry_run: bool) -> None:
    batch, round_no = state["batch"], int(state["round"])
    log(f"B{batch} R{round_no}: running precheck...")
    hard, summary, total = precheck(state)
    log("Precheck:\n   " + summary.replace("\n", "\n   "))
    if dry_run:
        log(f"Dry run: would send {len(build_prompt(state, summary))} chars to Claude ({model_for(batch, round_no)}).")
        return

    if hard:
        verdict, review, model = "REVISE", auto_review(batch, round_no, hard), "precheck"
    else:
        model = model_for(batch, round_no)
        log(f"B{batch} R{round_no}: verifying with Claude ({model})...")
        verdict, review = verify_with_claude(state, summary, model)
        if verdict is None and model != "opus":
            log("No verdict returned; retrying with opus.")
            model = "opus"
            verdict, review = verify_with_claude(state, summary, model)
        if verdict is None:
            (AUDIT / "reviews").mkdir(exist_ok=True)
            (AUDIT / "reviews" / f"B{batch}-R{round_no}.md").write_text(review, encoding="utf-8")
            write_state(status="blocked")
            log("Verifier produced no verdict twice. Loop blocked; see .git/audit-loop/verifier-*.txt")
            return

    (AUDIT / "reviews").mkdir(exist_ok=True)
    (AUDIT / "reviews" / f"B{batch}-R{round_no}.md").write_text(review, encoding="utf-8")

    if verdict == "PASS":
        git("add", "-A")
        ids = batch_ids(batch)
        git("commit", "-m", f"fix(audit): resolve batch B{batch} ({ids})\n\n"
                            f"Fixed by Antigravity; verified by Claude ({model}) in round {round_no}.")
        head = git("rev-parse", "HEAD").strip()
        if int(batch) >= LAST_BATCH:
            write_state(status="done", base=head, tests=total)
        else:
            write_state(batch=f"{int(batch) + 1:02d}", round="1", status="ready_for_fix", base=head, tests=total)
        log(f"B{batch} R{round_no} [{model}]: PASS — committed {head[:8]} ({ids})")
    elif round_no >= MAX_ROUNDS:
        write_state(status="blocked")
        log(f"B{batch} R{round_no} [{model}]: REVISE on final round — loop BLOCKED. See audit/reviews/.")
    else:
        write_state(round=str(round_no + 1), status="revise")
        log(f"B{batch} R{round_no} [{model}]: REVISE — sent back to Antigravity")


def wait_for(statuses) -> str:
    while True:
        status = read_state().get("status", "")
        if status in statuses:
            return status
        time.sleep(10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    while True:
        state = read_state()
        status = state.get("status", "")
        if status == "awaiting_baseline":
            if args.dry_run:
                log("Dry run: state is awaiting_baseline; nothing to precheck.")
                return 0
            if not baseline():
                return 1
        elif status in ("ready_for_fix", "revise"):
            if args.once or args.dry_run:
                log(f"Waiting on Antigravity (B{state.get('batch')} R{state.get('round')}, {status}).")
                return 0
            log(f"Waiting for Antigravity on B{state.get('batch')} R{state.get('round')}...")
            wait_for({"ready_for_review", "blocked", "done", "awaiting_baseline"})
        elif status == "ready_for_review":
            review_round(state, args.dry_run)
            if args.once or args.dry_run:
                return 0
        elif status == "blocked":
            log("Loop is BLOCKED. Read the latest file in audit/reviews/, then fix it or reset status.")
            return 2
        elif status == "done":
            log("All batches passed.")
            return 0
        else:
            log(f"Unknown status '{status}' in audit/STATE.md")
            return 1


if __name__ == "__main__":
    sys.exit(main())
