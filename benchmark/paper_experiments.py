"""
Reproducible experiments behind the numbers in the paper (Sec. IV).

    python -m benchmark.paper_experiments accuracy --reps 5
    python -m benchmark.paper_experiments scaling  --reps 5
    python -m benchmark.paper_experiments delta
    python -m benchmark.paper_experiments all --reps 5

Every run writes raw per-run JSON to benchmark/results/paper/<experiment>.json so the paper
tables can be regenerated (generate_paper_plots.py reads these files). Targets are the built-in
testbeds bound to 127.0.0.1; nothing else is contacted.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import config
from benchmark.metrics import GroundTruth, compute_metrics
from benchmark.run_benchmark import BenchmarkEngine, resolve_truth_path
from core.pipeline import ScanRequest, run_scan_pipeline
from testsupport import LocalFixtureServer

OUT_DIR = Path(__file__).parent / "results" / "paper"
THREAD_SWEEP = (1, 2, 4, 8, 16)


def host_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "processor": platform.processor(),
        "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        import ctypes

        class _Mem(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("m", ctypes.c_ulong),
                        ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong),
                        ("tpf", ctypes.c_ulonglong), ("apf", ctypes.c_ulonglong),
                        ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong),
                        ("ae", ctypes.c_ulonglong)]
        m = _Mem()
        m.l = ctypes.sizeof(_Mem)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))  # type: ignore[attr-defined]
        info["ram_gb"] = round(m.tp / 2 ** 30, 1)
    except Exception:
        pass
    return info


def _app(name: str):
    if name == "testbed1":
        from testbed.app import app
    else:
        from testbed.app2 import app
    return app


def _login(name: str) -> Dict[str, Any]:
    if name == "testbed2":
        return {"login_user": "admin", "login_pass": "admin", "login_url": "/login"}
    return {}


def scan_once(name: str, app: Any = None, previous: Any = None) -> Dict[str, Any]:
    app = app if app is not None else _app(name)
    with LocalFixtureServer(app) as srv:
        t0 = time.perf_counter()
        req = ScanRequest(target=srv.base_url, profile="full", mock_mode=False,
                          skip_reachability=True, previous_report=previous, **_login(name))
        report, _ = run_scan_pipeline(req, engine_cls=BenchmarkEngine)
        return {"report": report, "seconds": time.perf_counter() - t0}


def _summ(values: List[float]) -> Dict[str, float]:
    return {"n": len(values), "mean": statistics.fmean(values),
            "sd": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values), "max": max(values)}


def _save(name: str, payload: Dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload["host"] = host_info()
    (OUT_DIR / f"{name}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[paper] wrote {OUT_DIR / (name + '.json')}", flush=True)


def accuracy(reps: int) -> None:
    runs: Dict[str, List[Dict[str, Any]]] = {}
    for name in ("testbed1", "testbed2"):
        truth = GroundTruth.from_file(resolve_truth_path(name))
        runs[name] = []
        for i in range(reps):
            r = scan_once(name)
            m = compute_metrics(r["report"].all_findings, truth, duration_seconds=r["seconds"])
            runs[name].append({
                "rep": i + 1, "seconds": round(r["seconds"], 2),
                "raw_alerts": sum(len(sr.findings) for sr in r["report"].scan_results),
                "raw_findings": len(r["report"].all_findings),
                "plugins_run": len(r["report"].scan_results),
                "plugins_ok": sum(1 for sr in r["report"].scan_results if sr.status == "success"),
                "tp": m["true_positives"], "fp": m["false_positives"], "fn": m["false_negatives"],
                "total_real": m["total_real"], "precision": m["precision"], "recall": m["recall"],
                "f1": m["f1"], "unmatched": m["unmatched_items"],
                "false_positive_findings": m["false_positive_findings"],
            })
            print(f"[accuracy] {name} rep {i+1}/{reps}: TP={m['true_positives']}/{m['total_real']} "
                  f"FP={m['false_positives']} {r['seconds']:.1f}s", flush=True)
    _save("accuracy", {"threads": config.THREAD_COUNT, "runs": runs})


def scaling(reps: int) -> None:
    """Same scan of testbed1 for k in THREAD_SWEEP; k is rotated inside each repetition."""
    runs: Dict[str, List[Dict[str, Any]]] = {str(k): [] for k in THREAD_SWEEP}
    original = config.THREAD_COUNT
    try:
        for i in range(reps):
            for k in THREAD_SWEEP:
                config.THREAD_COUNT = k
                cpu0 = time.process_time()
                r = scan_once("testbed1")
                cpu = time.process_time() - cpu0
                runs[str(k)].append({
                    "rep": i + 1, "seconds": round(r["seconds"], 2),
                    "cpu_seconds": round(cpu, 2),
                    "findings": len(r["report"].all_findings),
                })
                print(f"[scaling] rep {i+1}/{reps} k={k}: {r['seconds']:.1f}s "
                      f"findings={len(r['report'].all_findings)}", flush=True)
    finally:
        config.THREAD_COUNT = original
    summary = {k: _summ([x["seconds"] for x in v]) for k, v in runs.items()}
    _save("scaling", {"target": "testbed1", "profile": "full", "runs": runs, "summary": summary})


def _hide(app: Any, prefix: str):
    """WSGI wrapper that answers 404 for one route, simulating a build without that feature."""
    def wsgi(environ, start_response):
        if environ.get("PATH_INFO", "").startswith(prefix):
            start_response("404 NOT FOUND", [("Content-Type", "text/plain")])
            return [b"Not Found"]
        return app(environ, start_response)
    return wsgi


def delta() -> None:
    """v1 = testbed1 without /template; v2 = full; v3 = full without /view.

    Expected from the ground truth: v1->v2 NEW = items at /template (2), FIXED = 0;
    v2->v3 FIXED = items at /view (2), NEW = 0.
    """
    truth = GroundTruth.from_file(resolve_truth_path("testbed1"))
    items = [(i.id, i.endpoint) for i in truth.items]
    exp_new = [i for i, e in items if e == "/template"]
    exp_fixed = [i for i, e in items if e == "/view"]
    base = _app("testbed1")
    v1 = scan_once("testbed1", app=_hide(base, "/template"))
    v2 = scan_once("testbed1", app=base, previous=v1["report"])
    v3 = scan_once("testbed1", app=_hide(base, "/view"), previous=v2["report"])

    def view(rep, key):
        d = rep["report"].delta or {}
        return {"summary": d.get("summary", {}),
                "titles": {k: sorted({(f.get("vuln_type"), f.get("endpoint")) and
                                      f"{f.get('vuln_type')}@{f.get('endpoint')}"
                                      for f in d.get(k, [])}) for k in
                           ("new_issues", "fixed_issues", "unchanged_issues")}}

    out = {"expected_new_items": exp_new, "expected_fixed_items": exp_fixed,
           "v1_findings": len(v1["report"].all_findings),
           "v2_findings": len(v2["report"].all_findings),
           "v3_findings": len(v3["report"].all_findings),
           "v1_to_v2": view(v2, "v2"), "v2_to_v3": view(v3, "v3"),
           "builds": {n: sorted({"vuln_type": f.vuln_type, "endpoint": f.endpoint, "param": f.param,
                                 "method": f.method, "tool": f.tool_name, "fp": (f.fingerprint or "")[:12]}
                                .items().__repr__() for f in r["report"].all_findings)
                      for n, r in (("v1", v1), ("v2", v2), ("v3", v3))}}
    print(json.dumps(out, indent=2), flush=True)
    _save("delta", out)


def main() -> int:
    p = argparse.ArgumentParser(prog="python -m benchmark.paper_experiments")
    p.add_argument("experiment", choices=["accuracy", "scaling", "delta", "all"])
    p.add_argument("--reps", type=int, default=5)
    a = p.parse_args()
    if a.experiment in ("scaling", "all"):
        scaling(a.reps)
    if a.experiment in ("accuracy", "all"):
        accuracy(a.reps)
    if a.experiment in ("delta", "all"):
        delta()
    return 0


if __name__ == "__main__":
    sys.exit(main())
