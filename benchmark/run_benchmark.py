"""
Benchmark runner for AutoSecAudit.
Executes scans against built-in or running local testbeds, compares against ground truth,
and outputs precision/recall/F1 metrics in JSON and Markdown formats.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.engine import Engine
from core.pipeline import ScanRequest, run_scan_pipeline
from core.utils import check_target_reachable, is_target_allowed
from testsupport import LocalFixtureServer
from benchmark.metrics import GroundTruth, compute_metrics

logger = logging.getLogger(__name__)


class BenchmarkEngine(Engine):
    """Engine subclass excluding external binary tools (Nmap, Nikto) to avoid external dependencies."""

    def load_plugins(self, *args: Any, **kwargs: Any) -> int:
        super().load_plugins(*args, **kwargs)
        excluded_tools = {"nmap", "nikto"}
        filtered = []
        for p in self.plugins:
            tool_name = ""
            if hasattr(p, "_get_tool_name"):
                try:
                    tool_name = str(p._get_tool_name()).lower()
                except Exception:
                    pass
            tool_stem = Path(tool_name).stem.lower() if tool_name else ""
            if (
                tool_name in excluded_tools
                or tool_stem in excluded_tools
                or p.__class__.__name__ in ("NmapPlugin", "NiktoPlugin")
            ):
                continue
            filtered.append(p)
        self.plugins = filtered
        return len(self.plugins)


def is_loopback_target(target_url: str) -> Tuple[bool, str]:
    """Verify that a target URL points strictly to a loopback address.

    Accepts 'localhost', '::1', or any IP in 127.0.0.0/8 (e.g. 127.0.0.1, 127.0.0.2).
    Rejects private network IPs (e.g. 192.168.x.x, 10.x.x.x) and non-loopback hostnames.
    """
    if "://" not in target_url:
        parsed = urllib.parse.urlparse(f"http://{target_url}")
    else:
        parsed = urllib.parse.urlparse(target_url)

    host = parsed.hostname
    if not host:
        return False, f"Target '{target_url}' has no valid hostname"

    host_lower = host.lower()
    if host_lower == "localhost":
        return True, ""

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return True, ""
        return False, f"Target host '{host}' is not a loopback target"
    except ValueError:
        # Host is a domain name: resolve to IP addresses
        try:
            addr_info = socket.getaddrinfo(host, None)
            if not addr_info:
                return False, f"Could not resolve host '{host}'"
            for info in addr_info:
                sockaddr = info[4]
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_loopback:
                    return False, f"Target '{target_url}' resolves to non-loopback IP '{ip_str}'"
            return True, ""
        except socket.gaierror as e:
            return False, f"DNS resolution failed for '{host}': {e}"


def resolve_truth_path(truth_name: str) -> Path:
    """Resolve a ground-truth name or path to a valid JSON file path."""
    p = Path(truth_name)
    if p.is_file():
        return p
    default_dir = Path(__file__).parent / "ground_truth"
    candidate = default_dir / f"{truth_name}.json"
    if candidate.is_file():
        return candidate
    candidate_raw = default_dir / truth_name
    if candidate_raw.is_file():
        return candidate_raw
    raise FileNotFoundError(f"Ground-truth file for '{truth_name}' not found at {candidate}")


def run_single_benchmark(
    target_url: str,
    truth_name: str,
    login_user: Optional[str] = None,
    login_pass: Optional[str] = None,
    login_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Run benchmark against a single target URL using specified ground truth.

    Raises:
        ValueError: If target is not a loopback address or arguments are invalid.
        PermissionError: If target is not allowed by AutoSec security policy.
        ConnectionError: If target is unreachable or offline.
        FileNotFoundError: If the specified ground-truth file cannot be found.
    """
    # 1. Enforce strict loopback-only rule
    is_loopback, loopback_err = is_loopback_target(target_url)
    if not is_loopback:
        raise ValueError(f"Target '{target_url}' is not a loopback target: {loopback_err}")

    # 2. Check AutoSec target permission
    allowed, reason = is_target_allowed(target_url)
    if not allowed:
        raise PermissionError(f"Target '{target_url}' is not allowed: {reason}")

    # 3. Verify pre-flight reachability
    reachable, reach_msg = check_target_reachable(target_url, timeout=5.0)
    if not reachable:
        raise ConnectionError(f"Target '{target_url}' is unreachable or offline: {reach_msg}")

    # 4. Load ground truth
    truth_path = resolve_truth_path(truth_name)
    truth = GroundTruth.from_file(truth_path)

    # 5. Execute scan
    start_time = time.time()
    req = ScanRequest(
        target=target_url,
        profile="full",
        login_user=login_user,
        login_pass=login_pass,
        login_url=login_url,
        mock_mode=False,
        skip_reachability=True,
    )
    report, _ = run_scan_pipeline(req, engine_cls=BenchmarkEngine)
    duration = time.time() - start_time

    # 6. Compute metrics
    metrics = compute_metrics(report.all_findings, truth, duration_seconds=duration)
    return {
        "target": truth.target,
        "url": target_url,
        "duration_seconds": round(duration, 2),
        "metrics": metrics,
        "findings_count": len(report.all_findings),
    }


def run_builtin_testbed(target_name: str) -> Dict[str, Any]:
    """Launch built-in testbed sandbox on loopback and benchmark it."""
    if target_name == "testbed1":
        from testbed.app import app as tb1_app
        with LocalFixtureServer(tb1_app) as srv:
            return run_single_benchmark(
                target_url=srv.base_url,
                truth_name="testbed1",
                login_user=None,
                login_pass=None,
                login_url=None,
            )
    elif target_name == "testbed2":
        from testbed.app2 import app as tb2_app
        with LocalFixtureServer(tb2_app) as srv:
            return run_single_benchmark(
                target_url=srv.base_url,
                truth_name="testbed2",
                login_user="admin",
                login_pass="admin",
                login_url="/login",
            )
    else:
        raise ValueError(f"Unknown built-in target '{target_name}'. Choose 'testbed1' or 'testbed2'.")


def format_markdown_table(results: Dict[str, Dict[str, Any]]) -> str:
    """Format benchmark results into a GitHub-flavored Markdown table."""
    lines = [
        "| Target | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score | Scan Duration |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for name, res in results.items():
        m = res.get("metrics", {})
        dur = f"{res.get('duration_seconds', 0.0):.1f}s"
        tp_str = f"{m.get('true_positives', 0)} / {m.get('total_real', 0)}"
        lines.append(
            f"| {name} | {tp_str} | {m.get('false_positives', 0)} | {m.get('false_negatives', 0)} | "
            f"{m.get('precision', 0.0):.2f} | {m.get('recall', 0.0):.2f} | "
            f"{m.get('f1', 0.0):.2f} | {dur} |"
        )
    return "\n".join(lines)


def run_all_benchmarks(
    output_file: Optional[str] = None,
    write_markdown: bool = False,
    targets: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Execute benchmarks for built-in testbed targets and save output."""
    if not targets:
        targets = ["testbed1", "testbed2"]

    results: Dict[str, Dict[str, Any]] = {}
    for t_name in targets:
        print(f"\n[BENCHMARK] Running benchmark against built-in '{t_name}'...", flush=True)
        res = run_builtin_testbed(t_name)
        results[t_name] = res

    # Format Markdown
    md_table = format_markdown_table(results)
    print("\n" + "=" * 60, flush=True)
    print("                 BENCHMARK RESULTS SUMMARY", flush=True)
    print("=" * 60, flush=True)
    print(md_table, flush=True)
    print("=" * 60 + "\n", flush=True)

    # Save JSON results (default to benchmark/results/<UTC date>.json)
    if not output_file:
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        results_dir = Path(__file__).parent / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(results_dir / f"{today_str}.json")

    out_p = Path(output_file)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[BENCHMARK] Results saved to: {out_p}", flush=True)

    # Optional RESULTS.md update
    if write_markdown:
        results_md_path = Path(__file__).parent / "RESULTS.md"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        content = (
            "# AutoSecAudit Precision & Recall Benchmark Results\n\n"
            f"Last updated: `{now_utc}`\n\n"
            f"{md_table}\n\n"
            "Generated automatically by `python -m benchmark.run_benchmark --write-markdown`.\n"
        )
        with open(results_md_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[BENCHMARK] Updated Markdown documentation at: {results_md_path}", flush=True)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AutoSecAudit Precision / Recall Benchmark Harness",
        prog="python -m benchmark.run_benchmark"
    )
    parser.add_argument(
        "--target",
        choices=["testbed1", "testbed2", "all"],
        default="all",
        help="Built-in testbed to benchmark (default: all)"
    )
    parser.add_argument(
        "--url",
        help="URL of an already-running local target (e.g. http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--truth",
        help="Name or path of ground-truth file (e.g. testbed1, pygoat, vampi, vulpy)"
    )
    parser.add_argument("--login-user", help="Username for authenticated scanning")
    parser.add_argument("--login-pass", help="Password for authenticated scanning")
    parser.add_argument("--login-url", help="Login form URL path (e.g. /login)")
    parser.add_argument("--output", help="Custom path to output JSON results file")
    parser.add_argument(
        "--write-markdown",
        action="store_true",
        help="Regenerate committed benchmark/RESULTS.md"
    )

    args = parser.parse_args()

    if args.url:
        if not args.truth:
            print("Error: --truth is required when benchmarking an external target with --url", file=sys.stderr)
            return 1

        print(f"[BENCHMARK] Benchmarking target at {args.url} with truth '{args.truth}'...", flush=True)
        try:
            res = run_single_benchmark(
                target_url=args.url,
                truth_name=args.truth,
                login_user=args.login_user,
                login_pass=args.login_pass,
                login_url=args.login_url,
            )
        except (ValueError, PermissionError, ConnectionError, FileNotFoundError) as err:
            print(f"Error: {err}", file=sys.stderr)
            return 1

        results = {args.truth: res}
        md_table = format_markdown_table(results)
        print("\n" + md_table + "\n", flush=True)

        # Consistent JSON output handling
        output_file = args.output
        if not output_file:
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            results_dir = Path(__file__).parent / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            output_file = str(results_dir / f"{today_str}.json")

        out_p = Path(output_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[BENCHMARK] Results saved to: {out_p}", flush=True)

        if args.write_markdown:
            results_md_path = Path(__file__).parent / "RESULTS.md"
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            content = (
                "# AutoSecAudit Precision & Recall Benchmark Results\n\n"
                f"Last updated: `{now_utc}`\n\n"
                f"{md_table}\n\n"
                "Generated automatically by `python -m benchmark.run_benchmark --write-markdown`.\n"
            )
            with open(results_md_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[BENCHMARK] Updated Markdown documentation at: {results_md_path}", flush=True)

        return 0

    # Built-in target execution
    targets = ["testbed1", "testbed2"] if args.target == "all" else [args.target]
    try:
        run_all_benchmarks(
            output_file=args.output,
            write_markdown=args.write_markdown,
            targets=targets
        )
    except (ValueError, PermissionError, ConnectionError, FileNotFoundError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
