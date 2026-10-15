#!/usr/bin/env python3
"""Find issues with tools, not with Claude, and turn them into mechanical backlog batches.

    python audit/discover.py                 # list new findings
    python audit/discover.py --write         # append them to audit/BACKLOG.md as mechanical batches
    python audit/discover.py --check CAND-1a2b3c4d   # exit 0 when that finding is gone (used by the loop)

Sources: ruff (real-bug rules only), bandit (medium+ severity and confidence), pip-audit (known CVEs in
requirements.txt). Suppression comments (`# noqa`, `# nosec`) are ignored so a finding cannot be hidden
instead of fixed. Findings that are intentional for a security scanner live in audit/baselines/accepted.json
(each with a reason); that file is protected from the fixer.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = ROOT / "audit" / "baselines" / "accepted.json"
BACKLOG = ROOT / "audit" / "BACKLOG.md"

RUFF_RULES = "F821,F811,F823,F601,F632,F402,B006,B015,B018,PLE"
RUFF_EXCLUDE = ".venv,paper,Presentation,audit,build_ijarcce_doc.py,build_ijarcce_publication_suite.py,benchmark/results"
BANDIT_TARGETS = ["core", "plugins", "intelligence", "reports", "ui", "testbed", "main.py", "mcp_server.py", "config.py"]


class ToolError(RuntimeError):
    pass


@dataclass
class Candidate:
    tool: str
    rule: str
    file: str
    line: int
    message: str

    @property
    def id(self) -> str:
        key = "|".join([self.tool, self.rule, self.file, re.sub(r"\d+", "N", self.message)])
        return "CAND-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]


def _relative(path: str, root: str) -> str:
    norm = path.replace("\\", "/")
    base = str(root).replace("\\", "/").rstrip("/") + "/"
    return norm[len(base):] if norm.lower().startswith(base.lower()) else norm


def parse_ruff(text: str, root=ROOT) -> List[Candidate]:
    return [Candidate("ruff", item["code"], _relative(item["filename"], str(root)),
                      int(item["location"]["row"]), item["message"]) for item in json.loads(text)]


def parse_bandit(text: str) -> List[Candidate]:
    data = json.loads(text)
    return [Candidate("bandit", r["test_id"], r["filename"].replace("\\", "/"), int(r["line_number"]),
                      r["issue_text"]) for r in data.get("results", [])]


def parse_pip_audit(text: str) -> List[Candidate]:
    out = []
    for dep in json.loads(text).get("dependencies", []):
        for vuln in dep.get("vulns", []):
            fixes = ", ".join(vuln.get("fix_versions") or []) or "no fixed version listed"
            out.append(Candidate("pip-audit", vuln["id"], "requirements.txt", 0,
                                 f"{dep['name']} {dep['version']}: {vuln.get('description', '')[:160]} (fixed in: {fixes})"))
    return out


def filter_accepted(cands: Sequence[Candidate], accepted: Sequence[dict]) -> List[Candidate]:
    for item in accepted:
        if not item.get("reason"):
            raise ValueError(f"accepted entry without a reason: {item}")
    def is_accepted(c: Candidate) -> bool:
        return any(a["tool"] == c.tool and a["rule"] == c.rule and (not a.get("file") or c.file.endswith(a["file"]))
                   for a in accepted)
    return [c for c in cands if not is_accepted(c)]


def load_accepted(path: Path = ACCEPTED) -> List[dict]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


# ---------------------------------------------------------------------------
# Running the tools
# ---------------------------------------------------------------------------
def tool_prefix(name: str) -> List[str]:
    exe = shutil.which(name)
    if exe:
        return [exe]
    uv = shutil.which("uv") or shutil.which("uvx")
    if uv:
        return [uv, "tool", "run", name]
    raise ToolError(f"{name} is not installed and uv is not available to run it")


def collect(root=ROOT, runner: Callable = subprocess.run, tool_prefixes: Optional[Dict[str, List[str]]] = None,
            accepted: Optional[Sequence[dict]] = None) -> List[Candidate]:
    prefixes = tool_prefixes or {n: tool_prefix(n) for n in ("ruff", "bandit", "pip-audit")}
    jobs = [
        ("ruff", [*prefixes["ruff"], "check", "--select", RUFF_RULES, "--exclude", RUFF_EXCLUDE, "--ignore-noqa",
                  "--no-cache", "--output-format", "json", "."], parse_ruff),
        ("bandit", [*prefixes["bandit"], "-r", *BANDIT_TARGETS, "-ll", "-ii", "-q", "-f", "json", "--ignore-nosec"],
         parse_bandit),
        ("pip-audit", [*prefixes["pip-audit"], "-r", "requirements.txt", "-f", "json", "--progress-spinner", "off"],
         parse_pip_audit),
    ]
    found: List[Candidate] = []
    for name, cmd, parser in jobs:
        proc = runner(cmd, cwd=str(root), capture_output=True, text=True, encoding="utf-8", errors="replace",
                      timeout=900)
        try:
            found.extend(parser(proc.stdout, root=root) if parser is parse_ruff else parser(proc.stdout))
        except (ValueError, KeyError, TypeError) as exc:
            raise ToolError(f"{name} produced unreadable output (exit {proc.returncode}): "
                            f"{(proc.stdout or '')[:120]!r} {(proc.stderr or '')[:160]!r}") from exc
    return filter_accepted(found, load_accepted() if accepted is None else accepted)


def is_fixed(candidate_id: str, current: Sequence[Candidate]) -> bool:
    return all(c.id != candidate_id for c in current)


# ---------------------------------------------------------------------------
# Backlog generation
# ---------------------------------------------------------------------------
def _issue_text(c: Candidate, aud: int) -> str:
    where = f"{c.file}:{c.line}" if c.line else c.file
    return (
        f"### AUD-{aud} · {c.tool} {c.rule} in {where}\n"
        f"- **Files:** `{c.file}`\n"
        f"- **Problem:** {c.tool} reports {c.rule}: {c.message}\n"
        "- **Required fix:** remove the underlying problem. Do not suppress it with `# noqa` or `# nosec`: the "
        "check ignores suppression comments. If you believe this is a deliberate, safe pattern for a security "
        "scanner, keep the code and say so under Deviations in your handoff; a person decides.\n"
        f"- **Check:** `{{py}} audit/discover.py --check {c.id}`\n"
    )


def batch_text(cands: Sequence[Candidate], batch_number: int, first_aud: int) -> str:
    issues = "\n".join(_issue_text(c, first_aud + i) for i, c in enumerate(cands))
    return (f"## B{batch_number} — Tool-found issues\n"
            "**Verification:** mechanical\n\n"
            "Found by static analysis or a dependency audit and verified by re-running the tool; the full test "
            "suite must stay green.\n\n" + issues)


def append_batches(backlog_text: str, cands: Sequence[Candidate], per_batch: int = 3) -> Tuple[str, List[int]]:
    tracked = set(re.findall(r"audit/discover\.py --check (CAND-[0-9a-f]{8})", backlog_text))
    fresh = [c for c in cands if c.id not in tracked]
    if not fresh:
        return backlog_text, []
    last_batch = max([int(n) for n in re.findall(r"^## B(\d+) ", backlog_text, flags=re.MULTILINE)] or [0])
    last_aud = max([int(n) for n in re.findall(r"### AUD-(\d+)", backlog_text)] or [0])
    chunks, numbers = [], []
    for start in range(0, len(fresh), per_batch):
        last_batch += 1
        group = fresh[start:start + per_batch]
        chunks.append(batch_text(group, last_batch, last_aud + 1))
        last_aud += len(group)
        numbers.append(last_batch)
    block = "---\n\n" + "\n---\n\n".join(chunks) + "\n"
    marker = re.search(r"^---\s*\n\n## Deferred", backlog_text, flags=re.MULTILINE)
    if marker:
        return backlog_text[:marker.start()] + block + backlog_text[marker.start():], numbers
    return backlog_text.rstrip("\n") + "\n\n" + block, numbers


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true", help="append new findings to audit/BACKLOG.md")
    parser.add_argument("--check", metavar="CAND_ID", help="exit 0 when this finding no longer exists")
    parser.add_argument("--per-batch", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        cands = collect()
    except ToolError as exc:
        print(f"discover: {exc}", file=sys.stderr)
        return 2
    if args.check:
        if is_fixed(args.check, cands):
            print(f"{args.check}: fixed")
            return 0
        c = next(c for c in cands if c.id == args.check)
        print(f"{args.check}: still present: {c.tool} {c.rule} {c.file}:{c.line} {c.message}")
        return 1
    print(f"{len(cands)} finding(s) after the accepted baseline")
    for c in cands:
        print(f"  {c.id} {c.tool:9} {c.rule:8} {c.file}:{c.line}  {c.message[:90]}")
    if args.write and cands:
        text = BACKLOG.read_text(encoding="utf-8")
        new_text, numbers = append_batches(text, cands, args.per_batch)
        if numbers:
            BACKLOG.write_text(new_text, encoding="utf-8", newline="\n")
            print(f"appended batch(es): {', '.join('B%02d' % n for n in numbers)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
