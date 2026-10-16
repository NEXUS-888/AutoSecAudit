"""
tools/stress_test_module.py MODULE N

Runs a unittest module N times while four busy-loop worker processes load the CPU,
then reports the pass count: "<K> of <N> passes".
"""

import ctypes
import multiprocessing
import os
import subprocess
import sys
import time


def _cpu_burner(stop_event):
    """Busy-loop worker to generate CPU load."""
    if sys.platform == "win32":
        try:
            # BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
            ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00004000)
        except Exception:
            pass
    elif hasattr(os, "nice"):
        try:
            os.nice(10)
        except Exception:
            pass

    while not stop_event.is_set():
        _ = sum(i * i for i in range(25000))
        time.sleep(0.0005)


def main():
    if len(sys.argv) < 3:
        print("Usage: python tools/stress_test_module.py MODULE N", file=sys.stderr, flush=True)
        sys.exit(1)

    module_name = sys.argv[1]
    # Strip .py extension if provided
    if module_name.endswith(".py"):
        module_name = module_name[:-3]

    try:
        n_runs = int(sys.argv[2])
    except ValueError:
        print(f"Error: N must be an integer, got {sys.argv[2]!r}", file=sys.stderr, flush=True)
        sys.exit(1)

    # Start 4 busy-loop CPU worker processes
    stop_event = multiprocessing.Event()
    workers = [
        multiprocessing.Process(target=_cpu_burner, args=(stop_event,), daemon=True)
        for _ in range(4)
    ]

    for w in workers:
        w.start()

    passed = 0
    try:
        for run_idx in range(1, n_runs + 1):
            cmd = [sys.executable, "-m", "unittest", module_name]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                passed += 1
                print(f"Run {run_idx}/{n_runs}: PASS", flush=True)
            else:
                print(f"Run {run_idx}/{n_runs}: FAIL (exit code {result.returncode})", flush=True)
                print(result.stderr[-500:] if result.stderr else result.stdout[-500:], flush=True)
    finally:
        stop_event.set()
        for w in workers:
            w.join(timeout=1.0)
            if w.is_alive():
                w.terminate()

    print(f"{passed} of {n_runs} passes", flush=True)
    if passed != n_runs:
        sys.exit(1)


if __name__ == "__main__":
    main()
