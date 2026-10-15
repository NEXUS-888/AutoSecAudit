#!/usr/bin/env python3
"""Deliver the finished software: run the release gates and, only if every required one passes, cut a release.

    python audit/release_gate.py [--bump patch|minor|major] [--dry-run]

Gates come from audit/release_gates.json: a list of {"name", "cmd", "required"} where `cmd` is an argument list
(`{py}` is the current interpreter) and exit code 0 means pass. A gate whose program is not installed is
SKIPPED (optional gates only). When all required gates pass: VERSION is written, CHANGELOG.md gets a new section
built from the conventional commits since the last tag, audit/RELEASE_REPORT.md records the gate results and the
Claude spend, one commit and an annotated tag `vX.Y.Z` are created, and a source archive goes to dist/.
Nothing is changed when a gate fails. No Claude tokens are used.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import loop_lib  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GATES_FILE = "audit/release_gates.json"
BASE_VERSION = "2.0.0"
GROUPS = [("feat", "Features"), ("fix", "Fixes"), ("perf", "Performance"), ("refactor", "Refactoring"),
          ("docs", "Documentation"), ("test", "Tests")]
BOOKKEEPING = ("chore(audit)", "chore: snapshot", "Merge ")


def next_version(last_tag: Optional[str], bump: str, base: str = BASE_VERSION) -> str:
    if last_tag is None:
        major, minor, patch = (int(x) for x in base.split("."))
    else:
        m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", last_tag.strip())
        if not m:
            raise ValueError(f"cannot read a version from tag {last_tag!r}")
        major, minor, patch = (int(x) for x in m.groups())
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def changelog_section(subjects: Sequence[str], version: str, date: str) -> str:
    buckets = {key: [] for key, _ in GROUPS}
    other: List[str] = []
    for subject in subjects:
        if subject.startswith(BOOKKEEPING):
            continue
        m = re.match(r"(\w+)(\([^)]*\))?!?:\s*(.+)", subject)
        if m and m.group(1) in buckets:
            buckets[m.group(1)].append(m.group(3))
        elif m and m.group(1) == "chore":
            continue
        else:
            other.append(subject)
    lines = [f"## v{version} — {date}", ""]
    wrote = False
    for key, title in GROUPS:
        if buckets[key]:
            wrote = True
            lines += [f"### {title}", *[f"- {s}" for s in buckets[key]], ""]
    if other:
        wrote = True
        lines += ["### Other", *[f"- {s}" for s in other], ""]
    if not wrote:
        lines += ["No user-facing changes.", ""]
    return "\n".join(lines)


@dataclass
class GateResult:
    name: str
    status: str            # PASS | FAIL | SKIPPED
    required: bool
    detail: str = ""


@dataclass
class ReleaseResult:
    released: bool
    version: Optional[str] = None
    report: str = ""
    gates: List[GateResult] = field(default_factory=list)


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def run_gates(root: Path, specs: Sequence[dict], runner=subprocess.run) -> List[GateResult]:
    results = []
    for spec in specs:
        required = bool(spec.get("required", True))
        cmd = [sys.executable if part == "{py}" else os.environ.get("AUTOSEC_PY310", "python3.10-not-configured")
               if part == "{py310}" else part for part in spec["cmd"]]
        if shutil.which(cmd[0]) is None and not Path(cmd[0]).exists():
            results.append(GateResult(spec["name"], "SKIPPED", required, f"{cmd[0]} not found"))
            continue
        try:
            proc = runner(cmd, cwd=str(root), capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=int(spec.get("timeout", 2400)))
            ok = proc.returncode == 0
            tail = "\n".join(((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()[-6:])
            results.append(GateResult(spec["name"], "PASS" if ok else "FAIL", required, "" if ok else tail))
        except subprocess.TimeoutExpired:
            results.append(GateResult(spec["name"], "FAIL", required, "timed out"))
    return results


def _report(version: str, results: Sequence[GateResult], blocked: Optional[str], date: str) -> str:
    rows = []
    for r in results:
        label = r.status if r.required or r.status == "SKIPPED" else f"{r.status} (optional)"
        rows.append(f"| {r.name} | {label} |" if r.status != "SKIPPED" else f"| {r.name} | SKIPPED: {r.detail} |")
    spend = loop_lib.usage_summary()
    lines = [f"# Release report — v{version} ({date})", "",
             "## Result", blocked or "All required gates passed; release cut.", "",
             "## Gates", "| Gate | Result |", "|---|---|", *rows, "",
             "## Claude usage for the whole loop",
             f"- {spend['calls']} call(s), ${spend['total_usd']:.2f} in total"]
    for model, m in sorted(spend["by_model"].items()):
        lines.append(f"- {model}: {m['calls']} call(s), ${m['usd']:.2f}, {m['input_tokens']} input / "
                     f"{m['output_tokens']} output tokens")
    failed = [r for r in results if r.status == "FAIL" and r.detail]
    if failed:
        lines += ["", "## Failure detail"] + [f"### {r.name}\n```\n{r.detail}\n```" for r in failed]
    return "\n".join(lines) + "\n"


def release(root=ROOT, bump: str = "patch", base: str = BASE_VERSION, today: Optional[str] = None,
            dry_run: bool = False, runner=subprocess.run) -> ReleaseResult:
    root = Path(root)
    today = today or datetime.date.today().isoformat()
    tags = [t for t in _git(root, "tag", "--list", "v*", "--sort=-v:refname").split() if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    last_tag = tags[0] if tags else None
    version = next_version(last_tag, bump, base)

    dirty = [l for l in _git(root, "status", "--porcelain").splitlines() if not l[3:].startswith(("dist/",))
             and l[3:].strip() != "audit/STATE.md"]
    if dirty:
        report = _report(version, [], "Blocked: the working tree has uncommitted changes: "
                         + ", ".join(l[3:] for l in dirty[:5]), today)
        return ReleaseResult(False, version, report)

    specs = json.loads((root / GATES_FILE).read_text(encoding="utf-8"))
    results = run_gates(root, specs, runner)
    failed_required = [r.name for r in results if r.required and r.status != "PASS"]
    if failed_required:
        report = _report(version, results, "Blocked: required gate(s) failed or did not run: "
                         + ", ".join(failed_required), today)
        return ReleaseResult(False, version, report, results)
    if dry_run:
        return ReleaseResult(False, version, _report(version, results, "Dry run: every required gate passed.", today), results)

    range_spec = f"{last_tag}..HEAD" if last_tag else "HEAD"
    subjects = [s for s in _git(root, "log", range_spec, "--pretty=%s").splitlines() if s.strip()]
    section = changelog_section(subjects, version, today)
    changelog = root / "CHANGELOG.md"
    previous = changelog.read_text(encoding="utf-8") if changelog.exists() else ""
    body = previous.split("\n", 1)[1].lstrip("\n") if previous.startswith("# Changelog") else previous
    changelog.write_text("# Changelog\n\n" + section + "\n" + body, encoding="utf-8", newline="\n")
    (root / "VERSION").write_text(version + "\n", encoding="utf-8", newline="\n")
    report = _report(version, results, None, today)
    (root / "audit" / "RELEASE_REPORT.md").write_text(report, encoding="utf-8", newline="\n")

    _git(root, "add", "CHANGELOG.md", "VERSION", "audit/RELEASE_REPORT.md")
    _git(root, "commit", "-q", "-m", f"chore(release): v{version}")
    _git(root, "tag", "-a", f"v{version}", "-m", f"AutoSecAudit {version}")
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"autosecaudit-v{version}.zip"
    raw = dist / f"autosecaudit-v{version}.tmp.zip"
    _git(root, "archive", "--format=zip", f"--output={raw}", f"v{version}")
    shutil.move(str(raw), str(archive))
    return ReleaseResult(True, version, report, results)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bump", choices=("patch", "minor", "major"), default="minor")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    result = release(bump=args.bump, dry_run=args.dry_run)
    print(result.report)
    return 0 if (result.released or args.dry_run) and not any(
        r.required and r.status != "PASS" for r in result.gates) else 1


if __name__ == "__main__":
    sys.exit(main())
