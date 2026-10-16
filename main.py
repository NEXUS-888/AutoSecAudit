#!/usr/bin/env python3
import argparse
import logging
import sys
import os
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

import config
from core.engine import Engine
from core.models import Report, Finding
from core.utils import load_json, validate_target, is_target_allowed, check_target_reachable
from reports.generator import ReportGenerator
from core.pipeline import run_scan_pipeline, ScanRequest

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def prompt_mode_selection(default_mock: bool = True) -> bool:
    """Prompt user interactively in terminal to select Real vs Mock mode."""
    print("\n" + "=" * 60)
    print("             AutoSecAudit Execution Mode")
    print("=" * 60)
    print("  [1] Real Active Scan  — Live HTTP attacks, crawler & active testing (requires online target)")
    print("  [2] Mock Demo Mode    — Offline simulation (no live target required, safe for demonstration)")
    print("=" * 60)
    default_str = "2" if default_mock else "1"
    try:
        choice = input(f"Select mode [1/2] (Press Enter for default: [{default_str}]): ").strip()
        if choice == "1":
            print("\n>>> [MODE SELECTED]: REAL SCAN MODE (Live Requests Enabled)\n")
            return False
        elif choice == "2":
            print("\n>>> [MODE SELECTED]: MOCK DEMO MODE (Simulated, Target Presence Check Bypassed)\n")
            return True
        else:
            selected_str = "Mock Demo" if default_mock else "Real Scan"
            print(f"\n>>> [MODE SELECTED]: {selected_str.upper()} MODE (Default)\n")
            return default_mock
    except (EOFError, KeyboardInterrupt):
        print("\nUsing default mode.")
        return default_mock


def run_scan(target: str, previous_report: str = None, output_json: str = None, output_html: str = None,
             fail_on: str = None, webhook: str = None, openapi: str = None, headers: str = None,
             mock_mode: Optional[bool] = None, profile: str = "full", skip_reachability: bool = False,
             login_user: str = None, login_pass: str = None, login_url: str = None,
             treat_dev_artifacts_as_info: bool = False, sarif: str = None, junit: str = None):
    
    if mock_mode is not None:
        config.MOCK_MODE = mock_mode
        is_demo = mock_mode
    else:
        is_demo = False  # Direct programmatic calls default to real mode unless specified
    
    mode_label = "MOCK DEMO (SIMULATION)" if is_demo else "REAL ACTIVE SCAN"
    logger.info(f"Starting scan for target: {target} [{mode_label}] (profile: {profile})")
    print(f"\n[ENGINE] Target: {target} | Execution Mode: {mode_label} | Profile: {profile.upper()}")
    
    # Password prompt/env resolution for CLI
    if login_user and not login_pass:
        login_pass = os.environ.get("AUTOSEC_LOGIN_PASS")
        if not login_pass:
            import getpass
            try:
                login_pass = getpass.getpass(f"Enter password for {login_user}: ")
            except (EOFError, KeyboardInterrupt):
                print("\nPassword prompt cancelled.")
                return 1

    if login_pass and any(arg.startswith("--login-pass") for arg in sys.argv):
        print("[WARNING] Passing --login-pass via CLI arguments exposes secrets in the process table. Use AUTOSEC_LOGIN_PASS or interactive prompt.")
        logger.warning("Passing --login-pass via CLI arguments exposes secrets in the process table.")

    if not validate_target(target):
        logger.error(f"Invalid target: {target}")
        print(f"Error: Invalid target '{target}'. Please provide a valid URL or IP address.")
        return 1

    if login_url:
        from core.authenticator import validate_login_url
        valid, err_msg = validate_login_url(login_url, target)
        if not valid:
            logger.error(f"Invalid --login-url: {err_msg}")
            print(f"\n[ERROR] {err_msg}")
            return 1
    
    allowed, reason = is_target_allowed(target)
    if not allowed:
        print(f"\n[BLOCKED] SCAN BLOCKED\n")
        print(reason)
        return 1

    # Pre-flight reachability check (ONLY in Real Mode; completely bypassed in Demo Mode)
    if not is_demo and not skip_reachability:
        print(f"[PRE-FLIGHT] Checking target reachability for {target}...")
        reachable, reach_msg = check_target_reachable(target)
        if not reachable:
            logger.error(f"Target unreachable: {target} ({reach_msg})")
            print(f"\n[TARGET OFFLINE] Could not connect to target '{target}'.")
            print(f"Reason: {reach_msg}")
            print("Please ensure your application server is started and accessible before scanning.")
            print("(To run an offline simulation in demo mode, pass --mock or --demo)\n")
            return 1
        print(f"[PRE-FLIGHT] Target online: {reach_msg}")
    elif is_demo:
        print(f"[DEMO MODE] Target presence check bypassed — running offline simulation.\n")

    req = ScanRequest(
        target=target,
        profile=profile,
        mock_mode=is_demo,
        skip_reachability=True,
        login_user=login_user,
        login_pass=login_pass,
        login_url=login_url,
        openapi_spec=openapi,
        previous_report=previous_report,
        output_json=output_json,
        output_html=output_html,
        headers=headers,
        webhook=webhook,
        treat_dev_artifacts_as_info=treat_dev_artifacts_as_info,
    )

    try:
        report, paths = run_scan_pipeline(
            req,
            engine_cls=Engine,
            generator_cls=ReportGenerator,
        )
    except (ValueError, ConnectionError, PermissionError) as e:
        logger.error(f"Scan pipeline error: {e}")
        print(f"\n[ERROR] {e}\n")
        return 1

    json_path = paths.json
    html_path = paths.html

    if sarif:
        from reports.sarif import generate_sarif_report
        generate_sarif_report(report, sarif)

    if junit:
        from reports.junit import generate_junit_report
        generate_junit_report(report, junit, fail_on=fail_on)

    print(f"\n{'='*50}")
    print(f"Scan Complete! [{mode_label}]")
    print(f"{'='*50}")

    if report.coverage and report.coverage.get("degraded"):
        print("\n[WARNING] Scan coverage is degraded! Some plugins timed out, deadline was reached, or request error rate was elevated.")
        logger.warning("[Coverage] Scan coverage is degraded.")

    summary = report.summary or {}
    print(f"Total Findings: {summary.get('total', len(report.all_findings))}")
    print(f"  Critical: {summary.get('critical', 0)}")
    print(f"  High: {summary.get('high', 0)}")
    print(f"  Medium: {summary.get('medium', 0)}")
    print(f"  Low: {summary.get('low', 0)}")
    
    if report.delta:
        print(f"\nDelta Analysis:")
        print(f"  New: {report.delta['summary']['new_count']}")
        print(f"  Fixed: {report.delta['summary']['fixed_count']}")
        print(f"  Unchanged: {report.delta['summary']['unchanged_count']}")
    
    print(f"\nReports:")
    print(f"  JSON: {json_path}")
    print(f"  HTML: {html_path}")
    if sarif:
        print(f"  SARIF: {sarif}")
    if junit:
        print(f"  JUnit: {junit}")

    # CI/CD Gating Check
    if fail_on:
        threshold = fail_on.lower()
        severities = ["info", "low", "medium", "high", "critical"]
        if threshold in severities:
            threshold_idx = severities.index(threshold)
            failed = False
            if report.all_findings:
                for f in report.all_findings:
                    sev = (f.severity or "info").lower()
                    if getattr(f, "original_severity", None) and not treat_dev_artifacts_as_info:
                        sev = f.original_severity.lower()
                    if sev in severities and severities.index(sev) >= threshold_idx:
                        failed = True
                        break
            else:
                for sev, count in report.summary.items():
                    if count > 0 and sev in severities:
                        if severities.index(sev) >= threshold_idx:
                            failed = True
                            break
            if failed:
                print(f"\n[CI/CD GATING] Scan failed: Found findings meeting or exceeding threshold '{fail_on}'")
                return 1

    return 0


def list_plugins():
    engine = Engine()
    count = engine.load_plugins()
    print(f"\nDiscovered {count} Scanner Plugin(s):")
    for idx, plugin in enumerate(engine.plugins, 1):
        print(f"  [{idx:02d}] {plugin.__class__.__name__}")
    print()


def _compute_menu_counts() -> Tuple[int, int]:
    """Compute discovered plugin and test counts dynamically."""
    try:
        eng = Engine(mock_mode=True)
        plugin_count = eng.load_plugins()
    except Exception:
        plugin_count = 14

    try:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(".", pattern="test_*.py")
        test_count = suite.countTestCases()
    except Exception:
        test_count = 80

    return plugin_count, test_count


def interactive_menu():
    """Interactive startup menu when run with no CLI arguments."""
    plugin_count, test_count = _compute_menu_counts()
    while True:
        print("\n" + "=" * 60)
        print("    AutoSecAudit 2.0 — Interactive Security Console")
        print("=" * 60)
        print("  [1] Start Web Dashboard Server (http://localhost:5000)")
        print("  [2] Run CLI Target Security Scan")
        print(f"  [3] List Discovered Scanner Plugins ({plugin_count} Plugins)")
        print("  [4] Run Automated Verification Proof (verify_proof.py)")
        print(f"  [5] Run Full Test Suite ({test_count} Automated Tests)")
        print("  [6] Exit")
        print("=" * 60)
        
        try:
            choice = input("Enter option [1-6]: ").strip()
            if choice == "1":
                mock = prompt_mode_selection(default_mock=True)
                config.MOCK_MODE = mock
                mode_str = "MOCK DEMO" if mock else "REAL SCAN"
                os.environ.setdefault("AUTOSEC_ALLOW_REGISTRATION", "true")
                print(f"\n[STARTING SERVER in {mode_str} MODE] (Registration: ENABLED)")
                print("Open http://localhost:5000 in your browser (Press Ctrl+C to stop)\n")
                from ui.app import app
                app.run(debug=config.DEBUG, host=config.HOST, port=5000)
                break
            elif choice == "2":
                target = input("\nEnter target URL or IP (e.g. http://localhost:8000): ").strip()
                if not target:
                    print("Target cannot be empty.")
                    continue
                mock = prompt_mode_selection(default_mock=True)
                auth_opt = input("Enable Authenticated Deep Scan (Auto-Login)? [y/N]: ").strip().lower()
                user, pwd, l_url = None, None, None
                if auth_opt in ("y", "yes"):
                    user = input("  Enter Username or Email: ").strip()
                    import getpass
                    pwd = getpass.getpass("  Enter Password: ")
                    l_url = input("  Login URL (press Enter for auto-detect): ").strip() or None
                run_scan(target=target, mock_mode=mock, login_user=user, login_pass=pwd, login_url=l_url)
            elif choice == "3":
                list_plugins()
            elif choice == "4":
                import subprocess
                try:
                    subprocess.run([sys.executable, "verify_proof.py"], timeout=180)
                except subprocess.TimeoutExpired:
                    print("\n[ERROR] verify_proof.py timed out after 180s.\n")
            elif choice == "5":
                import subprocess
                try:
                    subprocess.run([sys.executable, "run_tests.py"], timeout=180)
                except subprocess.TimeoutExpired:
                    print("\n[ERROR] run_tests.py timed out after 180s.\n")
            elif choice == "6":
                print("\nExiting AutoSecAudit. Goodbye!\n")
                return 0
            else:
                print("Invalid option. Please enter 1-6.")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting AutoSecAudit.")
            return 0


def main():
    parser = argparse.ArgumentParser(
        description="AutoSecAudit 2.0 - Intelligent Security Auditing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("target", help="Target URL or IP address")
    scan_parser.add_argument("-p", "--previous", help="Path to previous report for delta comparison")
    scan_parser.add_argument("--json", help="Output JSON file path")
    scan_parser.add_argument("--html", help="Output HTML file path")
    scan_parser.add_argument("--sarif", help="Output SARIF 2.1.0 file path for CI/CD pipelines")
    scan_parser.add_argument("--junit", help="Output JUnit XML file path for CI/CD test reporting")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Fail CI/CD pipeline if findings equal or exceed severity threshold")
    scan_parser.add_argument("--webhook", help="URL for Slack/Discord webhook alerts")
    scan_parser.add_argument("--openapi", help="Path or URL to OpenAPI/Swagger spec")
    scan_parser.add_argument("--headers", help="Custom HTTP headers (format 'Header1: val1; Header2: val2')")
    scan_parser.add_argument("--login-user", help="Username or email for automated authentication")
    scan_parser.add_argument("--login-pass", help="Password for automated authentication")
    scan_parser.add_argument("--login-url", help="Explicit login URL path (auto-detected if omitted)")
    scan_parser.add_argument("--profile", choices=["full", "owasp", "api", "recon"], default="full", help="Select scan profile: full (all), owasp (OWASP Top 10), api (API Security), recon (Passive Recon)")
    scan_parser.add_argument("--skip-reachability-check", action="store_true", help="Skip pre-flight target reachability check")
    scan_parser.add_argument("--treat-dev-artifacts-as-info", action="store_true", help="Treat dev environment artifact findings as Informational in CI/CD gating")
    scan_mode_group = scan_parser.add_mutually_exclusive_group()
    scan_mode_group.add_argument("--real", action="store_true", help="Force REAL active scanning mode (requires target online)")
    scan_mode_group.add_argument("--mock", "--demo", dest="mock", action="store_true", help="Force MOCK demo mode (offline simulation, no live target needed)")
    
    subparsers.add_parser("plugins", help="List available plugins")
    
    server_parser = subparsers.add_parser("server", help="Start the web interface")
    server_mode_group = server_parser.add_mutually_exclusive_group()
    server_mode_group.add_argument("--real", action="store_true", help="Force REAL active scanning mode")
    server_mode_group.add_argument("--mock", "--demo", dest="mock", action="store_true", help="Force MOCK demo mode")
    server_reg_group = server_parser.add_mutually_exclusive_group()
    server_reg_group.add_argument("--allow-registration", action="store_true", default=None, help="Enable self-registration on the dashboard (default: enabled)")
    server_reg_group.add_argument("--disable-registration", action="store_true", default=None, help="Disable self-registration on the dashboard")

    testbed_parser = subparsers.add_parser("testbed", help="Launch the local vulnerable sandbox testbed")
    testbed_parser.add_argument("--port", type=int, default=8080, help="Port to run testbed on (default: 8080)")
    testbed_parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    testbed_parser.add_argument("--app", choices=["1", "2", "app", "app2"], default="app", help="Select testbed app (app or app2, default: app)")
    testbed_parser.add_argument("--app2", action="store_true", help="Launch testbed app2 instead of app")
    
    benchmark_parser = subparsers.add_parser("benchmark", help="Run precision and recall benchmark harness")
    benchmark_parser.add_argument("--target", choices=["testbed1", "testbed2", "all"], default="all", help="Target testbed (default: all)")
    benchmark_parser.add_argument("--url", help="URL of an already-running local target (e.g. http://127.0.0.1:8000)")
    benchmark_parser.add_argument("--truth", help="Name or path of ground-truth file (e.g. testbed1, pygoat, vampi, vulpy)")
    benchmark_parser.add_argument("--login-user", help="Username for authenticated scanning")
    benchmark_parser.add_argument("--login-pass", help="Password for authenticated scanning")
    benchmark_parser.add_argument("--login-url", help="Login form URL path (e.g. /login)")
    benchmark_parser.add_argument("--output", help="Custom path to output JSON results file")
    benchmark_parser.add_argument("--write-markdown", action="store_true", help="Regenerate committed benchmark/RESULTS.md")
    
    args = parser.parse_args()
    
    # If run with no arguments in interactive terminal, launch interactive menu
    if not args.command:
        if sys.stdin.isatty():
            return interactive_menu()
        else:
            parser.print_help()
            return 0
    
    # Determine mock mode from flags or interactive prompt
    mock_mode = None
    if getattr(args, "real", False):
        mock_mode = False
    elif getattr(args, "mock", False):
        mock_mode = True
    elif sys.stdin.isatty() and args.command in ("scan", "server"):
        mock_mode = prompt_mode_selection(default_mock=config.MOCK_MODE)
    elif args.command == "scan":
        mock_mode = False  # Non-interactive CLI scan without flags defaults to REAL scan
    
    if mock_mode is not None:
        config.MOCK_MODE = mock_mode

    if args.command == "scan":
        profile = getattr(args, "profile", "full")
        skip_reach = getattr(args, "skip_reachability_check", False)
        return run_scan(
            args.target, args.previous, args.json, args.html, args.fail_on,
            args.webhook, args.openapi, args.headers, mock_mode=mock_mode,
            profile=profile, skip_reachability=skip_reach,
            login_user=getattr(args, "login_user", None),
            login_pass=getattr(args, "login_pass", None),
            login_url=getattr(args, "login_url", None),
            treat_dev_artifacts_as_info=getattr(args, "treat_dev_artifacts_as_info", False),
            sarif=getattr(args, "sarif", None),
            junit=getattr(args, "junit", None)
        )

    elif args.command == "plugins":
        list_plugins()
        return 0
    elif args.command == "testbed":
        if getattr(args, "app2", False) or getattr(args, "app", "app") in ("2", "app2"):
            from testbed.app2 import run_testbed as run_testbed2
            run_testbed2(host=args.host, port=args.port)
        else:
            from testbed.app import run_testbed
            run_testbed(host=args.host, port=args.port)
        return 0
    elif args.command == "server":
        if getattr(args, "disable_registration", False):
            os.environ["AUTOSEC_ALLOW_REGISTRATION"] = "false"
        elif getattr(args, "allow_registration", False):
            os.environ["AUTOSEC_ALLOW_REGISTRATION"] = "true"
        else:
            os.environ.setdefault("AUTOSEC_ALLOW_REGISTRATION", "true")
        from ui.app import app
        mode_str = "MOCK DEMO" if config.MOCK_MODE else "REAL ACTIVE SCAN"
        reg_str = "ENABLED" if os.environ.get("AUTOSEC_ALLOW_REGISTRATION", "").lower() in ("true", "1", "yes") else "DISABLED"
        print("\n" + "=" * 60)
        print(f"Starting AutoSecAudit Web Dashboard [{mode_str} MODE] (Registration: {reg_str})...")
        print("Open http://localhost:5000 in your browser")
        print("=" * 60 + "\n")
        app.run(debug=config.DEBUG, host=config.HOST, port=5000)
        return 0
    elif args.command == "benchmark":
        from benchmark.run_benchmark import main as run_benchmark_main
        sys.argv = [sys.argv[0] + " benchmark"] + sys.argv[2:]
        return run_benchmark_main()
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())

