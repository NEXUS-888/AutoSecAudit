#!/usr/bin/env python3
"""Keep audit/run_loop.py alive unattended: restart it if it crashes.

    python audit/supervise.py

Stops when the loop finishes (exit 0) or is blocked (exit 2: needs a human decision).
Any other exit is treated as a crash and restarted after a pause.
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_CRASHES = 30
PAUSE_SECONDS = 60


def main() -> int:
    crashes = 0
    while crashes <= MAX_CRASHES:
        code = subprocess.call([sys.executable, "audit/run_loop.py"], cwd=ROOT)
        if code in (0, 2):
            return code
        crashes += 1
        print(f"run_loop.py exited with {code}; restart {crashes}/{MAX_CRASHES} in {PAUSE_SECONDS}s", flush=True)
        time.sleep(PAUSE_SECONDS)
    return 1


if __name__ == "__main__":
    sys.exit(main())
