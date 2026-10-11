#!/usr/bin/env python3
"""
Print only what an agent needs for one batch: the loop rules + that batch's section.

    python audit/show_batch.py 03          # rules + B03
    python audit/show_batch.py 03 --no-rules
    python audit/show_batch.py --list      # batch titles only
"""

import re
import sys
from pathlib import Path

BACKLOG = Path(__file__).resolve().parent / "BACKLOG.md"


def sections(text: str):
    """Split the backlog on '---' separators into blocks."""
    return [block.strip() for block in re.split(r"^---\s*$", text, flags=re.MULTILINE) if block.strip()]


def rules(text: str) -> str:
    for block in sections(text):
        if "## Rules of the loop" in block:
            return block[block.index("## Rules of the loop"):]
    return ""


def batch(text: str, number: str) -> str:
    for block in sections(text):
        if block.startswith(f"## B{number} "):
            return block
    return ""


def main(argv) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    text = BACKLOG.read_text(encoding="utf-8")
    if "--list" in argv:
        for block in sections(text):
            if re.match(r"## B\d\d ", block):
                ids = re.findall(r"### (AUD-\d+)", block)
                print(f"{block.splitlines()[0][3:]}  [{', '.join(ids)}]")
        return 0
    numbers = [a for a in argv if not a.startswith("--")]
    if not numbers:
        print(__doc__)
        return 2
    number = numbers[0].zfill(2)
    section = batch(text, number)
    if not section:
        print(f"No batch B{number} in {BACKLOG.name}", file=sys.stderr)
        return 1
    if "--no-rules" not in argv:
        print(rules(text) + "\n\n---\n")
    print(section)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
