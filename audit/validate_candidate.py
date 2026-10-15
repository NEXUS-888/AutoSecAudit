#!/usr/bin/env python3
"""Turn an explorer's suspected defect into a *proven* finding, or reject it. No Claude involved.

An explorer (Antigravity, workflow audit-explore) writes, per suspected defect:

    audit/candidates/CAND-<slug>/finding.md          title, **Area:**, **Impact:**, ## Reproduction
    audit/candidates/CAND-<slug>/test_cand_<slug>.py a unittest that FAILS because of the defect

The candidate is proven only if that test fails with an assertion in every one of several runs on the
current code, always the same tests, with no errors. Anything else (passes, import error, flaky, unsafe,
non-loopback network) is rejected, so false findings never reach the fix loop.

    python audit/validate_candidate.py audit/candidates/CAND-x          # judge one
    python audit/validate_candidate.py --all [--accept]                 # judge every undecided one
"""

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_IMPORTS = {"subprocess", "ctypes", "pickle", "marshal", "multiprocessing", "ftplib", "smtplib", "telnetlib"}
FORBIDDEN_CALLS = {"eval", "exec", "__import__", "compile", "os.system", "os.popen", "os.remove", "os.unlink",
                   "os.rmdir", "os.removedirs", "shutil.rmtree", "shutil.move", "os.rename", "os.kill"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


@dataclass
class Verdict:
    status: str                      # "proven" | "rejected"
    reason: str = ""
    failing_tests: List[str] = field(default_factory=list)


def _reject(reason: str) -> Verdict:
    return Verdict("rejected", reason)


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def static_problems(source: str) -> Optional[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return f"test does not parse: {exc}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                    return f"import of {alias.name} is not allowed in a candidate test"
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in FORBIDDEN_IMPORTS:
            return f"import from {node.module} is not allowed in a candidate test"
        elif isinstance(node, ast.Call) and _dotted(node.func) in FORBIDDEN_CALLS:
            return f"call to {_dotted(node.func)} is not allowed in a candidate test"
    for match in re.finditer(r"https?://([^/\s'\"`)\]]+)", source):
        host = match.group(1)
        if host.startswith(("{", "%", "$")):
            continue                                  # built at run time from a local fixture server
        host = re.sub(r":\d+$", "", host) if not host.startswith("[") else host.split("]")[0] + "]"
        if host not in LOOPBACK_HOSTS:
            return f"only loopback URLs are allowed in a candidate test (found {match.group(0)})"
    return None


def _finding_problems(text: str) -> Optional[str]:
    missing = []
    if not re.search(r"^# \S", text, re.MULTILINE):
        missing.append("a '# Title' line")
    if not re.search(r"^\*\*Area:\*\*\s*\S", text, re.MULTILINE):
        missing.append("**Area:**")
    if not re.search(r"^\*\*Impact:\*\*\s*\S", text, re.MULTILINE):
        missing.append("**Impact:**")
    if not re.search(r"^## Reproduction\s*\n\s*\S", text, re.MULTILINE):
        missing.append("a non-empty '## Reproduction' section")
    return f"finding.md is incomplete: missing {', '.join(missing)}" if missing else None


def _run_once(cand_dir: Path, root: Path, runner: Callable, timeout: int):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    with tempfile.TemporaryDirectory(prefix="cand_data_") as data:
        env["AUTOSEC_DATA_DIR"] = data
        proc = runner([sys.executable, "-m", "unittest", "discover", "-s", str(cand_dir), "-p", "test_cand_*.py"],
                      cwd=str(root), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                      timeout=timeout)
    out = (proc.stdout or "") + (proc.stderr or "")
    failures = sorted(re.findall(r"^FAIL: (\S+) \(", out, re.MULTILINE))
    errors = re.findall(r"^ERROR: (\S+) \(", out, re.MULTILINE)
    return proc.returncode, failures, errors, out


def validate(cand_dir, root=ROOT, runs: int = 3, timeout: int = 90, runner: Callable = subprocess.run) -> Verdict:
    cand_dir, root = Path(cand_dir), Path(root)
    finding = cand_dir / "finding.md"
    if not finding.exists():
        return _reject("finding.md is missing")
    problem = _finding_problems(finding.read_text(encoding="utf-8"))
    if problem:
        return _reject(problem)
    tests = sorted(cand_dir.glob("test_cand_*.py"))
    if len(tests) != 1 or not re.fullmatch(r"test_cand_[a-z0-9_]+\.py", tests[0].name):
        return _reject("expected exactly one test file named test_cand_<slug>.py (lowercase, digits, underscores)")
    problem = static_problems(tests[0].read_text(encoding="utf-8"))
    if problem:
        return _reject(problem)

    seen = []
    for _ in range(runs):
        try:
            code, failures, errors, out = _run_once(cand_dir, root, runner, timeout)
        except subprocess.TimeoutExpired:
            return _reject(f"test did not finish within {timeout}s")
        if code == 0:
            if seen:
                return _reject(f"the failure is not stable across runs: it failed {len(seen)} time(s), then passed")
            return _reject("the test passes on the current code, so it shows no defect")
        if errors or not failures or re.search(r"(ImportError|ModuleNotFoundError|SyntaxError)", out):
            return _reject("the test errors instead of failing an assertion: " + (errors[0] if errors else "see output"))
        seen.append(failures)
    if any(s != seen[0] for s in seen):
        return _reject("the failure is not stable across runs")
    return Verdict("proven", f"fails with an assertion in all {runs} runs", [f.split(".")[-1] for f in seen[0]])


# ---------------------------------------------------------------------------
# Queueing a proven candidate
# ---------------------------------------------------------------------------
def _field(text: str, name: str) -> str:
    m = re.search(rf"^\*\*{name}:\*\*\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def accept(cand_dir, root=ROOT) -> int:
    """Copy the proving test into the repository and append a fix batch. Returns the batch number."""
    cand_dir, root = Path(cand_dir), Path(root)
    test = next(cand_dir.glob("test_cand_*.py"))
    target = root / test.name
    if target.exists():
        raise FileExistsError(f"{target.name} already exists: this candidate was already queued")
    text = (cand_dir / "finding.md").read_text(encoding="utf-8")
    title = re.search(r"^# (.+)$", text, re.MULTILINE).group(1).strip()
    repro = text.split("## Reproduction", 1)[1].strip()
    backlog_path = root / "audit" / "BACKLOG.md"
    backlog = backlog_path.read_text(encoding="utf-8")
    number = max([int(n) for n in re.findall(r"^## B(\d+) ", backlog, re.MULTILINE)] or [0]) + 1
    aud = max([int(n) for n in re.findall(r"### AUD-(\d+)", backlog)] or [0]) + 1
    module = test.stem
    section = (
        f"## B{number:02d} — Proven defect: {title}\n\n"
        f"### AUD-{aud} · {title}\n"
        f"- **Files:** `{_field(text, 'Area')}`\n"
        f"- **Problem:** {_field(text, 'Impact')} Reproduction: {repro}\n"
        f"- **Required fix:** fix the defect in the code. The proving test `{module}` (already in the repository) "
        "must pass because the code is correct; do not edit that test, special-case its inputs, or weaken any "
        "other test.\n"
        f"- **Check:** `{{py}} -m unittest {module}`\n"
        "- **Acceptance:** the proving test passes; the full suite stays green; the change is limited to the "
        "defect.\n"
    )
    shutil.copy(test, target)
    marker = re.search(r"^---\s*\n\n## Deferred", backlog, flags=re.MULTILINE)
    block = "---\n\n" + section
    new = backlog[:marker.start()] + block + backlog[marker.start():] if marker else backlog.rstrip("\n") + "\n\n" + block
    backlog_path.write_text(new, encoding="utf-8", newline="\n")
    return number


def process_all(root=ROOT, runs: int = 3, timeout: int = 90, runner: Callable = subprocess.run,
                do_accept: bool = True) -> dict:
    """Judge every candidate directory that has no proof.json yet."""
    root = Path(root)
    summary = {"proven": [], "rejected": [], "queued_batches": []}
    for cand in sorted((root / "audit" / "candidates").glob("CAND-*")):
        if not cand.is_dir() or (cand / "proof.json").exists():
            continue
        verdict = validate(cand, root=root, runs=runs, timeout=timeout, runner=runner)
        (cand / "proof.json").write_text(json.dumps(verdict.__dict__, indent=1), encoding="utf-8")
        summary[verdict.status].append(cand.name)
        if verdict.status == "proven" and do_accept:
            summary["queued_batches"].append(accept(cand, root=root))
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("candidate", nargs="?")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--accept", action="store_true", help="queue proven candidates into the backlog")
    args = parser.parse_args(argv)
    if args.all:
        print(json.dumps(process_all(do_accept=args.accept), indent=1))
        return 0
    if not args.candidate:
        parser.print_usage()
        return 2
    verdict = validate(args.candidate)
    print(json.dumps(verdict.__dict__, indent=1))
    return 0 if verdict.status == "proven" else 1


if __name__ == "__main__":
    sys.exit(main())
