"""Shared helpers for the audit fix loop: backlog parsing, mechanical verification, model choice, the
diff-only review prompt, and a single metered, budgeted way to call Claude.

Design goal: use as few Claude tokens as possible without lowering accuracy.
  * Findings are proven by tools or failing tests, not by Claude.
  * A batch whose issues each carry `Check:` commands is verified by running them (no Claude).
  * Other batches are reviewed from the diff and the acceptance criteria only (no tools, no repo
    exploration), on a light model unless the change is large or security-sensitive.
  * Every call is measured (`usage.jsonl`) and capped by a dollar budget.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".git" / "audit-loop"
USAGE_LOG = RUNTIME / "usage.jsonl"

LIGHT_MODEL = "sonnet"
STRONG_MODEL = "opus"
LIGHT_MAX_DIFF_CHARS = 25_000
MAX_PROMPT_CHARS = 150_000
DIFF_CHAR_BUDGET = 120_000
SECURITY_SENSITIVE = ("core/utils.py", "core/auth.py", "core/http_client.py", "core/authenticator.py",
                      "ui/app.py", "mcp_server.py")


# ---------------------------------------------------------------------------
# Backlog parsing
# ---------------------------------------------------------------------------
@dataclass
class Issue:
    id: str
    title: str
    files: str = ""
    checks: List[str] = field(default_factory=list)


@dataclass
class Batch:
    number: str
    title: str
    verification: str = "review"
    issues: List[Issue] = field(default_factory=list)


def parse_backlog(text: str) -> Dict[str, Batch]:
    """Parse BACKLOG.md into batches. A batch is `mechanical` only if it declares
    `**Verification:** mechanical` and every issue has at least one `Check:` command."""
    batches: Dict[str, Batch] = {}
    for block in re.split(r"^---\s*$", text, flags=re.MULTILINE):
        block = block.strip()
        m = re.match(r"## B(\d+) — (.+)", block)
        if not m:
            continue
        batch = Batch(number=m.group(1).zfill(2), title=m.group(2).strip())
        declared = re.search(r"^\*\*Verification:\*\*\s*(\w+)", block, re.MULTILINE)
        for part in re.split(r"^### ", block, flags=re.MULTILINE)[1:]:
            head = part.splitlines()[0]
            im = re.match(r"(AUD-\d+) · (.+)", head)
            if not im:
                continue
            issue = Issue(id=im.group(1), title=im.group(2).strip())
            files = re.search(r"^- \*\*Files:\*\*\s*(.+)$", part, re.MULTILINE)
            issue.files = files.group(1).strip() if files else ""
            issue.checks = [c.strip() for c in re.findall(r"^- \*\*Check:\*\*\s*`([^`]+)`", part, re.MULTILINE)]
            batch.issues.append(issue)
        if declared and declared.group(1).lower() == "mechanical" and batch.issues \
                and all(i.checks for i in batch.issues):
            batch.verification = "mechanical"
        batches[batch.number] = batch
    return batches


# ---------------------------------------------------------------------------
# Mechanical verification (no Claude)
# ---------------------------------------------------------------------------
@dataclass
class CheckResult:
    cmd: str
    returncode: int
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_checks(checks: Sequence[str], cwd, runner: Callable = subprocess.run, timeout: int = 900) -> List[CheckResult]:
    results = []
    for cmd in checks:
        tokens = [sys.executable if t == "{py}" else t for t in shlex.split(cmd)]
        try:
            proc = runner(tokens, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)
            results.append(CheckResult(cmd, proc.returncode, (proc.stdout or "") + (proc.stderr or "")))
        except subprocess.TimeoutExpired:
            results.append(CheckResult(cmd, 124, f"timed out after {timeout}s"))
        except OSError as exc:
            results.append(CheckResult(cmd, 127, f"could not run: {exc}"))
    return results


def _tail(text: str, lines: int = 25) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def mechanical_review(batch: str, round_no: int, results: Sequence[CheckResult]) -> Tuple[str, str]:
    failed = [r for r in results if not r.ok]
    rows = "\n".join(f"| `{r.cmd}` | {'PASS' if r.ok else 'FAIL'} |" for r in results)
    head = f"# Review B{batch} round {round_no} — {'PASS' if not failed else 'REVISE'} (mechanical)\n\n"
    table = f"| Check | Result |\n|---|---|\n{rows}\n"
    if not failed:
        return "PASS", head + table
    items = "\n".join(f"{i}. `{r.cmd}` exited {r.returncode}. Output (tail):\n```\n{_tail(r.output)}\n```"
                      for i, r in enumerate(failed, 1))
    return "REVISE", head + table + "\n## Required changes\n" + items + "\n"


# ---------------------------------------------------------------------------
# Model choice and the diff-only prompt
# ---------------------------------------------------------------------------
def pick_model(changed_files: Sequence[str], diff_chars: int, round_no: int) -> str:
    if round_no >= 3 or diff_chars > LIGHT_MAX_DIFF_CHARS:
        return STRONG_MODEL
    if any(f.replace("\\", "/").startswith(SECURITY_SENSITIVE) for f in changed_files):
        return STRONG_MODEL
    return LIGHT_MODEL


def build_diff_prompt(instructions: str, section: str, handoff: str, diff: str, summary: str, ctx: dict) -> str:
    note = ""
    if len(diff) > DIFF_CHAR_BUDGET:
        diff = diff[:DIFF_CHAR_BUDGET]
        note = (f"\n[diff truncated to {DIFF_CHAR_BUDGET} characters; judge what is shown and say in "
                "'Required changes' if the unseen part must be provided]\n")
    return (
        f"{instructions}\n\n---\n\n"
        "You review from the material below only. You have no tools and cannot read the repository; do not ask "
        "to. Tests, protected files, skips, assertion counts and the Python 3.10/3.11 import were already "
        "verified mechanically (see the precheck summary).\n\n"
        f"Reply with the first line exactly `VERDICT: PASS|REVISE` (one of the two words), then "
        f"`# Review B{ctx.get('batch')} round {ctx.get('round')}`, a table with one row per issue "
        "(`| Issue | Verdict | Evidence (file:line) |`, verdict PASS/PARTIAL/FAIL), and, if REVISE, "
        "a numbered `## Required changes` list where each item names the file, what is wrong and how it will be "
        "re-checked. Be terse: at most 40 words of evidence per issue, no preamble and no summary after the "
        "table; output tokens are the main cost.\n\n---\n\n"
        f"# Batch under review\n\n{section}\n\n---\n\n"
        f"# Handoff from the fixer\n\n{handoff}\n\n---\n\n"
        f"# Precheck summary\n{summary}\n\n---\n\n"
        f"# Diff against the base commit\n```diff\n{diff}\n```{note}"
    )


def parse_verdict(output: str) -> Tuple[Optional[str], str]:
    match = re.search(r"^VERDICT:\s*(PASS|REVISE)\b", output, re.MULTILINE)
    review = output[output.find("# Review"):] if "# Review" in output else output
    verdict = match.group(1) if match else None
    if verdict == "PASS" and re.search(r"\|\s*(FAIL|PARTIAL)\s*\|", review):
        verdict = "REVISE"
    return verdict, review.strip() + "\n"


# ---------------------------------------------------------------------------
# Claude: one metered, budgeted entry point
# ---------------------------------------------------------------------------
class ClaudeError(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Reply:
    text: str
    cost_usd: float
    input_tokens: int
    output_tokens: int


def record_usage(entry: dict, log: Path = USAGE_LOG) -> None:
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **entry}
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def _entries(log: Path):
    log = Path(log)
    if not log.exists():
        return []
    out = []
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def spent_usd(log: Path = USAGE_LOG) -> float:
    return sum(float(e.get("cost_usd", 0) or 0) for e in _entries(log))


def usage_summary(log: Path = USAGE_LOG) -> dict:
    by_model: Dict[str, dict] = {}
    total = 0.0
    entries = _entries(log)
    for e in entries:
        m = by_model.setdefault(e.get("model", "?"), {"calls": 0, "usd": 0.0, "input_tokens": 0, "output_tokens": 0})
        m["calls"] += 1
        m["usd"] += float(e.get("cost_usd", 0) or 0)
        m["input_tokens"] += int(e.get("input_tokens", 0) or 0)
        m["output_tokens"] += int(e.get("output_tokens", 0) or 0)
        total += float(e.get("cost_usd", 0) or 0)
    return {"total_usd": total, "calls": len(entries), "by_model": by_model}


def default_budget_usd() -> float:
    try:
        return float(os.environ.get("AUTOSEC_LOOP_BUDGET_USD", "10"))
    except ValueError:
        return 10.0


def _claude_cmd() -> List[str]:
    override = os.environ.get("AUTOSEC_CLAUDE_CMD")
    if override:
        return shlex.split(override)
    exe = shutil.which("claude")
    if not exe:
        raise ClaudeError("`claude` CLI not found on PATH")
    return [exe]


def claude_ask(prompt: str, model: str, *, tag: str, tools: Optional[Sequence[str]] = None,
               timeout: int = 1200, runner: Callable = subprocess.run, usage_log: Path = USAGE_LOG,
               budget_usd: Optional[float] = None, per_call_cap_usd: float = 1.5, min_call_usd: float = 0.02,
               claude_cmd: Optional[List[str]] = None) -> Reply:
    """Run one headless Claude call. Tools are off unless `tools` is given; the dollar budget is
    checked before the call and the call itself is capped by --max-budget-usd."""
    budget = default_budget_usd() if budget_usd is None else budget_usd
    remaining = budget - spent_usd(usage_log)
    if remaining < min_call_usd:
        raise BudgetExceeded(f"Claude budget exhausted: spent ${spent_usd(usage_log):.2f} of ${budget:.2f}")
    cap = max(min_call_usd, min(per_call_cap_usd, remaining))

    cmd = list(claude_cmd or _claude_cmd()) + [
        "-p", "--model", model, "--output-format", "json", "--no-session-persistence",
        "--permission-mode", "dontAsk", "--strict-mcp-config", "--disable-slash-commands",
        "--max-budget-usd", f"{cap:.2f}",
    ]
    if tools is None:
        cmd += ["--tools", ""]
    else:
        cmd += ["--allowedTools", *tools]
    try:
        proc = runner(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace",
                      timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ClaudeError(f"claude timed out after {timeout}s") from exc
    try:
        data = json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        raise ClaudeError(f"claude returned non-JSON output: {(proc.stdout or '')[:200]!r} {(proc.stderr or '')[:200]!r}") from exc
    usage = data.get("usage") or {}
    input_tokens = sum(int(usage.get(k, 0) or 0) for k in
                       ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
    output_tokens = int(usage.get("output_tokens", 0) or 0)
    cost = float(data.get("total_cost_usd", 0) or 0)
    record_usage({"tag": tag, "model": model, "cost_usd": cost, "input_tokens": input_tokens,
                  "output_tokens": output_tokens, "tools": bool(tools)}, usage_log)
    if data.get("is_error"):
        raise ClaudeError(f"claude reported an error: {str(data.get('result'))[:200]}")
    return Reply(text=str(data.get("result", "")), cost_usd=cost, input_tokens=input_tokens,
                 output_tokens=output_tokens)
