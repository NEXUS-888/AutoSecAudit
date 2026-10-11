#!/usr/bin/env python3
"""
Block until audit/STATE.md reaches one of the given statuses.

    python audit/wait_for_status.py ready_for_review blocked done --max-wait 540

Prints the status reached and exits 0. Prints "timeout" and exits 3 if --max-wait
seconds pass first (callers simply re-run it). Used by both sides of the audit loop.
"""

import argparse
import re
import sys
import time
from pathlib import Path

STATE = Path(__file__).resolve().parent / "STATE.md"
STATUS_RE = re.compile(r"^status:\s*(\S+)", re.MULTILINE)


def read_status() -> str:
    try:
        match = STATUS_RE.search(STATE.read_text(encoding="utf-8"))
    except OSError:
        return ""
    return match.group(1) if match else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("statuses", nargs="+")
    parser.add_argument("--max-wait", type=float, default=0, help="seconds; 0 = wait forever")
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args()

    deadline = time.monotonic() + args.max_wait if args.max_wait else None
    while True:
        status = read_status()
        if status in args.statuses:
            print(status)
            return 0
        if deadline and time.monotonic() >= deadline:
            print("timeout")
            return 3
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
