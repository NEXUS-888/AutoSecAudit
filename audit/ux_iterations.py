#!/usr/bin/env python3
"""Check that a self-iterating batch really was iterated.

    python audit/ux_iterations.py --batch 30 --min 3

The fixer writes one log per pass, audit/handoffs/B<batch>-ITER-<n>.md, containing:

    ux_check issues: <N>            (what `python audit/ux_check.py` reported at the START of the pass)
    ## Own visual review            (what it saw itself in the screenshots, page by page)
    ## Fixed / ## Remaining

This validates the shape of the history (enough consecutive passes, an honest starting point, a clean end).
Whether the UI is really clean is decided separately by running ux_check itself, not by this file.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "audit" / "handoffs"
COUNT_RE = re.compile(r"^ux_check issues:\s*(\d+)\s*$", re.M)
REVIEW_RE = re.compile(r"^##\s*Own visual review\s*\n(.*?)(?=^##\s|\Z)", re.M | re.S | re.I)
MIN_REVIEW_CHARS = 20


def check(batch: str, minimum: int, directory: Path = DEFAULT_DIR) -> Tuple[bool, str]:
    pat = re.compile(rf"^B{re.escape(batch)}-ITER-(\d+)\.md$")
    found = sorted((int(m.group(1)), p) for p in directory.glob(f"B{batch}-ITER-*.md") if (m := pat.match(p.name)))
    problems: List[str] = []
    numbers = [n for n, _ in found]
    if len(found) < minimum:
        problems.append(f"found {len(found)} iteration log(s); at least {minimum} are required "
                        f"(B{batch}-ITER-1.md, B{batch}-ITER-2.md, ...)")
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        problems.append(f"iteration numbers must be consecutive from 1, found {numbers}")

    counts = {}
    for n, path in found:
        text = path.read_text(encoding="utf-8", errors="replace")
        m = COUNT_RE.search(text)
        if not m:
            problems.append(f"{path.name}: missing the line `ux_check issues: <N>`")
        else:
            counts[n] = int(m.group(1))
        r = REVIEW_RE.search(text)
        if not r or len(r.group(1).strip()) < MIN_REVIEW_CHARS:
            problems.append(f"{path.name}: missing or empty '## Own visual review' section "
                            f"(describe what you saw in the screenshots, page by page)")

    if counts and numbers:
        first, last = numbers[0], numbers[-1]
        if first in counts and counts[first] == 0:
            problems.append("the first iteration reports 0 issues, so nothing was actually found and improved; "
                            "run `python audit/ux_check.py` against the unmodified UI and record that count")
        if last in counts and counts[last] != 0:
            problems.append(f"the last iteration (ITER-{last}) must report `ux_check issues: 0`, it reports {counts[last]}")

    if problems:
        return False, "Iteration history is not acceptable:\n- " + "\n- ".join(problems)
    trail = " -> ".join(str(counts[n]) for n in numbers)
    return True, f"{len(found)} iterations, issue counts {trail}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate the self-iteration logs of a batch.")
    ap.add_argument("--batch", required=True)
    ap.add_argument("--min", type=int, default=3, dest="minimum")
    ap.add_argument("--dir", default=str(DEFAULT_DIR))
    args = ap.parse_args(argv)
    ok, msg = check(str(args.batch), args.minimum, Path(args.dir))
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
