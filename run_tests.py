#!/usr/bin/env python3
"""
Unified Test Runner for AutoSecAudit.
Runs all test modules (test_*.py) and reports comprehensive pass/fail metrics.
Exits with status code 0 if all tests pass, or status code 1 if any test fails.

Speed (the suite is dominated by waiting on sockets, not by CPU):
  * test modules run in parallel worker processes, each with its own data directory
    (AUD-46 isolation is kept: nothing is written to the repo's data/ folder);
  * on Windows a refused loopback connection normally takes 2-4 s to fail (Linux: instant),
    so the workers fail a loopback connect that gets no answer within 0.3 s the same way.

Usage:
    python run_tests.py                 # parallel (default workers: min(3, CPUs))
    python run_tests.py --serial        # one process, the original behaviour
    python run_tests.py --workers 6
    python run_tests.py --no-retry      # do not re-run failed modules alone
Environment:
    AUTOSEC_TEST_WORKERS=N              # same as --workers
    AUTOSEC_TEST_REAL_SOCKETS=1         # disable the loopback fast-fail
"""

import argparse
import concurrent.futures
import glob
import io
import multiprocessing
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest

# Modules that take the longest run first so the pool does not end with one long straggler.
SLOW_FIRST = (
    "test_b25_regression_testbed",
    "test_auto_authenticator",
    "test_b18_accuracy",
    "test_b03_mcp_server",
    "test_b22_form_injection",
    "test_b24_api_discovery_and_recall",
    "test_retest_fixes",
    "test_spa_and_dev_hardening",
)

# These modules assert on timing (request pacing, 50 simultaneous calls, time-limited reads). They are
# reliable on their own and flaky next to other busy processes, so they run alone after the parallel phase.
RUN_ALONE = (
    "test_b09_shared_http_client",
    "test_b19_scanner_robustness",
)

LOOPBACK_PROBE_SECONDS = 0.3


# ---------------------------------------------------------------------------
# Loopback fast-fail (Windows only)
# ---------------------------------------------------------------------------
def _is_loopback(host) -> bool:
    return isinstance(host, str) and (host in ("localhost", "::1") or host.startswith("127."))


def install_fast_loopback_failure() -> None:
    """Make a loopback connect to a port nobody here listens on fail as 'refused' after a moment.

    A port that is closed never answers; Windows keeps retrying such a connect for about two seconds
    before reporting 'connection refused'. The exception raised here is the same type
    (ConnectionRefusedError) that tests already expect from a closed port.

    Ports that a server in this process is listening on are never touched: such a server may be slow
    to answer under load (for example when 50 clients connect to a listen backlog of 5), and a slow
    answer must not look like a refusal.
    """
    if sys.platform != "win32" or os.environ.get("AUTOSEC_TEST_REAL_SOCKETS") == "1":
        return
    if getattr(socket.socket, "_autosec_fast_loopback", False):
        return
    original_connect = socket.socket.connect
    original_listen = socket.socket.listen
    local_ports = set()

    def tracking_listen(self, *args):
        try:
            local_ports.add(self.getsockname()[1])
        except OSError:
            pass
        return original_listen(self, *args)

    def fast_connect(self, address):
        if (isinstance(address, tuple) and len(address) >= 2 and _is_loopback(address[0])
                and address[1] not in local_ports):
            previous = self.gettimeout()
            probe = LOOPBACK_PROBE_SECONDS if previous is None else min(previous, LOOPBACK_PROBE_SECONDS)
            self.settimeout(probe)
            try:
                return original_connect(self, address)
            except socket.timeout:
                if previous is not None and previous <= LOOPBACK_PROBE_SECONDS:
                    raise
                raise ConnectionRefusedError(10061, "Connection refused (fast loopback failure in test runner)")
            finally:
                self.settimeout(previous)
        return original_connect(self, address)

    socket.socket.listen = tracking_listen
    socket.socket.connect = fast_connect
    socket.socket._autosec_fast_loopback = True


# ---------------------------------------------------------------------------
# Worker side
# ---------------------------------------------------------------------------
def _worker_init(base_data_dir: str) -> None:
    os.environ["AUTOSEC_DATA_DIR"] = os.path.join(base_data_dir, f"worker_{os.getpid()}")
    os.makedirs(os.path.join(os.environ["AUTOSEC_DATA_DIR"], "reports"), exist_ok=True)
    if os.getcwd() not in sys.path:
        sys.path.insert(0, os.getcwd())
    install_fast_loopback_failure()


def run_module(module_name: str) -> dict:
    """Run one test module and return a picklable summary."""
    started = time.time()
    stream = io.StringIO()
    try:
        suite = unittest.TestLoader().loadTestsFromName(module_name)
    except Exception as exc:  # import error: reported as a failed module, never silently dropped
        return {"module": module_name, "run": 1, "failures": 0, "errors": 1, "skipped": 0,
                "seconds": time.time() - started, "output": f"ERROR: {module_name} (import)\n{type(exc).__name__}: {exc}\n",
                "ok": False}
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    return {"module": module_name, "run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "seconds": time.time() - started, "output": stream.getvalue(), "ok": result.wasSuccessful()}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def discover_modules() -> list:
    names = sorted(os.path.splitext(os.path.basename(p))[0] for p in glob.glob("test_*.py"))
    first = [n for n in SLOW_FIRST if n in names]
    return first + [n for n in names if n not in first]


def default_workers() -> int:
    env = os.environ.get("AUTOSEC_TEST_WORKERS")
    if env and env.isdigit() and int(env) >= 1:
        return int(env)
    return max(1, min(3, os.cpu_count() or 1))


def run_serial() -> dict:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=".", pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return {"run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "ok": result.wasSuccessful()}


def _crash_result(module: str, exc: Exception) -> dict:
    return {"module": module, "run": 1, "failures": 0, "errors": 1, "skipped": 0, "seconds": 0.0,
            "output": f"ERROR: {module} (worker)\n{type(exc).__name__}: {exc}\n", "ok": False}


def _run_pool(modules: list, workers: int, base_data_dir: str, announce: bool) -> dict:
    """Run the given modules on a pool and return {module: result}."""
    results = {}
    pool = concurrent.futures.ProcessPoolExecutor(max_workers=workers, initializer=_worker_init,
                                                  initargs=(base_data_dir,))
    try:
        futures = {pool.submit(run_module, m): m for m in modules}
        for future in concurrent.futures.as_completed(futures):
            module = futures[future]
            try:
                r = future.result()
            except Exception as exc:  # a worker crashed hard
                r = _crash_result(module, exc)
            results[module] = r
            if announce:
                status = "ok  " if r["ok"] else "FAIL"
                print(f"[{status}] {r['module']:<44} {r['run']:>4} tests  {r['seconds']:6.1f}s", flush=True)
    finally:
        # Every result is in. Tests leave server threads running, and a worker with a live non-daemon
        # thread would make a normal pool shutdown wait for it, so stop the workers directly.
        pool.shutdown(wait=False, cancel_futures=True)
        for child in multiprocessing.active_children():
            child.terminate()
        for child in multiprocessing.active_children():
            child.join(timeout=5)
    return results


def run_parallel(workers: int, base_data_dir: str, retry: bool = True) -> dict:
    modules = discover_modules()
    print(f"Running {len(modules)} test modules on {workers} worker process(es)...", flush=True)
    parallel_modules = [m for m in modules if m not in RUN_ALONE]
    alone_modules = [m for m in modules if m in RUN_ALONE]
    results = _run_pool(parallel_modules, workers, base_data_dir, announce=True)
    for module in alone_modules:
        r = _run_pool([module], 1, base_data_dir, announce=False)[module]
        results[module] = r
        status = "ok  " if r["ok"] else "FAIL"
        print(f"[{status}] {r['module']:<44} {r['run']:>4} tests  {r['seconds']:6.1f}s  (run alone: timing-sensitive)", flush=True)

    flaky = []
    failed = [m for m in modules if not results[m]["ok"]]
    if failed and retry:
        # Several end-to-end tests are sensitive to machine load. Run each failed module once more on
        # its own, with nothing else competing. A real defect fails again; a load flake is reported.
        print(f"\nRe-running {len(failed)} failed module(s) alone: {', '.join(failed)}", flush=True)
        for module in failed:
            again = _run_pool([module], 1, base_data_dir, announce=False)[module]
            if again["ok"]:
                flaky.append(module)
                print(f"[FLAKY] {module} failed under parallel load but passed when run alone "
                      f"({again['run']} tests, {again['seconds']:.1f}s)", flush=True)
            else:
                print(f"[FAIL] {module} failed again when run alone", flush=True)
                print(again["output"], flush=True)
            results[module] = again
    elif failed:
        for module in failed:
            print(results[module]["output"], flush=True)

    totals = {"run": 0, "failures": 0, "errors": 0, "skipped": 0, "ok": True, "flaky": flaky}
    for r in results.values():
        for key in ("run", "failures", "errors", "skipped"):
            totals[key] += r[key]
        totals["ok"] = totals["ok"] and r["ok"]
    return totals


def main():
    parser = argparse.ArgumentParser(description="AutoSecAudit unified test runner")
    parser.add_argument("--serial", action="store_true", help="run every module in this process")
    parser.add_argument("--workers", type=int, default=None, help="number of parallel worker processes")
    parser.add_argument("--no-retry", action="store_true",
                        help="do not re-run failed modules alone (a load-sensitive flake then fails the run)")
    args = parser.parse_args()

    print("=" * 60)
    print("       AUTOSECAUDIT UNIFIED TEST SUITE RUNNER")
    print("=" * 60)

    start_time = time.time()

    # AUD-46: isolate test runs to a temporary data directory so repo data/ is never polluted
    created_temp = False
    temp_data_dir = os.environ.get("AUTOSEC_DATA_DIR")
    if not temp_data_dir:
        temp_data_dir = tempfile.mkdtemp(prefix="autosec_test_data_")
        os.environ["AUTOSEC_DATA_DIR"] = temp_data_dir
        created_temp = True
    os.makedirs(os.path.join(temp_data_dir, "reports"), exist_ok=True)

    try:
        workers = args.workers or default_workers()
        if args.serial or workers <= 1:
            install_fast_loopback_failure()
            totals = run_serial()
        else:
            totals = run_parallel(workers, temp_data_dir, retry=not args.no_retry)

        elapsed = time.time() - start_time

        print("\n" + "=" * 60)
        print("                  TEST RESULTS SUMMARY")
        print("=" * 60)
        print(f"Total Tests Executed : {totals['run']}")
        print(f"Total Failures       : {totals['failures']}")
        print(f"Total Errors         : {totals['errors']}")
        print(f"Total Skipped        : {totals['skipped']}")
        if totals.get("flaky"):
            print(f"Passed only on retry : {', '.join(totals['flaky'])}  (load-sensitive: investigate if frequent)")
        print(f"Execution Time       : {elapsed:.2f} seconds")
        print("=" * 60)

        if totals["ok"]:
            print("SUCCESS: All tests passed successfully!")
            return 0
        print("FAILURE: Some tests failed or encountered errors.")
        return 1
    finally:
        if created_temp:
            os.environ.pop("AUTOSEC_DATA_DIR", None)
            shutil.rmtree(temp_data_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
