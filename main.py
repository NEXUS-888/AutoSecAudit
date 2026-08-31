#!/usr/bin/env python3
import argparse
import logging
import sys
import os
from pathlib import Path
from typing import Optional

import config
from core.engine import Engine
from core.models import Report, Finding
from core.utils import load_json, validate_target, is_target_allowed
from reports.generator import ReportGenerator
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper
from intelligence.delta import DeltaAnalyzer

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
    print("  [1] Real Scan Mode  — Live HTTP attacks, crawler & injections")
    print("  [2] Mock Demo Mode  — Simulated findings (safe for presentation)")
    print("=" * 60)
    default_str = "2" if default_mock else "1"
    try:
        choice = input(f"Select mode [1/2] (Press Enter for default: [{default_str}]): ").strip()
        if choice == "1":
            print("\n>>> [MODE SELECTED]: REAL SCAN MODE (Live Requests Enabled)\n")
            return False
        elif choice == "2":
            print("\n>>> [MODE SELECTED]: MOCK DEMO MODE (Simulated)\n")
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
             mock_mode: Optional[bool] = None, profile: str = "full"):
    
    if mock_mode is not None:
        config.MOCK_MODE = mock_mode
    
    mode_label = "MOCK DEMO" if config.MOCK_MODE else "REAL ACTIVE SCAN"
    logger.info(f"Starting scan for target: {target} [{mode_label}] (profile: {profile})")
    print(f"\n[ENGINE] Target: {target} | Execution Mode: {mode_label} | Profile: {profile.upper()}")
    
    if not validate_target(target):
        logger.error(f"Invalid target: {target}")
        print(f"Error: Invalid target '{target}'. Please provide a valid URL or IP address.")
        return 1
    
    allowed, reason = is_target_allowed(target)
    if not allowed:
        print(f"\n[BLOCKED] SCAN BLOCKED\n")
        print(reason)
        return 1
    
    # Process custom headers
    header_dict = {}
    if headers:
        for h in headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()

    engine = Engine(mock_mode=config.MOCK_MODE, profile=profile)
    loaded = engine.load_plugins()
    print(f"Loaded {loaded} plugin(s) for profile '{profile}'")
    
    if not engine.set_target(target):
        return 1

    # OpenAPI import if specified
    if openapi:
        from core.openapi import OpenAPIImporter
        importer = OpenAPIImporter(openapi, headers=header_dict)
        if importer.load_spec():
            imported_eps = importer.get_endpoints()
            print(f"Imported {len(imported_eps)} endpoint(s) from OpenAPI spec")
            engine.crawler_data["injectable_endpoints"] = imported_eps
    
    if previous_report:
        if engine.set_previous_report(previous_report):
            print(f"Loaded previous report: {previous_report}")
        else:
            print(f"Warning: Could not load previous report")
    
    print(f"Running scan on {engine.target}...")
    engine.run_plugins()
    report = engine.generate_report()
    
    print(f"\nApplying intelligence layer...")
    
    correlator = Correlator()
    report.all_findings = correlator.link_related(report.all_findings)
    
    enricher = Enricher()
    report.all_findings = enricher.enrich(report.all_findings)
    
    mapper = ComplianceMapper()
    report.all_findings = mapper.map_findings(report.all_findings)
    
    if engine.previous_report:
        previous_data = engine.previous_report
        if "all_findings" in previous_data:
            from core.models import Finding
            import dataclasses
            _valid_fields = {fld.name for fld in dataclasses.fields(Finding)}
            prev_findings = [Finding(**{k: v for k, v in f.items() if k in _valid_fields}) for f in previous_data.get("all_findings", [])]
            prev_report = Report(
                target=previous_data.get("target", ""),
                timestamp=previous_data.get("timestamp", ""),
                all_findings=prev_findings
            )
            delta = DeltaAnalyzer().compare(report, prev_report)
            report.delta = delta
    
    report.summary = engine._generate_summary(report.all_findings)
    
    json_path = engine.save_report(report, output_json)
    print(f"JSON report saved: {json_path}")
    
    generator = ReportGenerator()
    html_path = generator.generate_report(report)
    print(f"HTML report saved: {html_path}")
    
    # Webhook Notification
    if webhook:
        from core.notifications import WebhookNotifier
        notifier = WebhookNotifier(webhook)
        notifier.send_notification(report.summary, report.target)

    print(f"\n{'='*50}")
    print(f"Scan Complete! [{mode_label}]")
    print(f"{'='*50}")
    print(f"Target: {report.target}")
    print(f"Total Findings: {report.summary['total']}")
    print(f"  Critical: {report.summary['critical']}")
    print(f"  High: {report.summary['high']}")
    print(f"  Medium: {report.summary['medium']}")
    print(f"  Low: {report.summary['low']}")
    
    if report.delta:
        print(f"\nDelta Analysis:")
        print(f"  New: {report.delta['summary']['new_count']}")
        print(f"  Fixed: {report.delta['summary']['fixed_count']}")
        print(f"  Unchanged: {report.delta['summary']['unchanged_count']}")
    
    print(f"\nReports:")
    print(f"  JSON: {json_path}")
    print(f"  HTML: {html_path}")

    # CI/CD Gating Check
    if fail_on:
        threshold = fail_on.lower()
        severities = ["info", "low", "medium", "high", "critical"]
        if threshold in severities:
            threshold_idx = severities.index(threshold)
            failed = False
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


def interactive_menu():
    """Interactive startup menu when run with no CLI arguments."""
    while True:
        print("\n" + "=" * 60)
        print("    AutoSecAudit 2.0 — Interactive Security Console")
        print("=" * 60)
        print("  [1] Start Web Dashboard Server (http://localhost:5000)")
        print("  [2] Run CLI Target Security Scan")
        print("  [3] List Discovered Scanner Plugins (14 Plugins)")
        print("  [4] Run Automated Verification Proof (verify_proof.py)")
        print("  [5] Run Full Test Suite (80 Automated Tests)")
        print("  [6] Exit")
        print("=" * 60)
        
        try:
            choice = input("Enter option [1-6]: ").strip()
            if choice == "1":
                mock = prompt_mode_selection(default_mock=True)
                config.MOCK_MODE = mock
                mode_str = "MOCK DEMO" if mock else "REAL SCAN"
                print(f"\n[STARTING SERVER in {mode_str} MODE]")
                print("Open http://localhost:5000 in your browser (Press Ctrl+C to stop)\n")
                from ui.app import app
                app.run(debug=config.DEBUG, host="0.0.0.0", port=5000)
                break
            elif choice == "2":
                target = input("\nEnter target URL or IP (e.g. http://localhost:8000): ").strip()
                if not target:
                    print("Target cannot be empty.")
                    continue
                mock = prompt_mode_selection(default_mock=True)
                run_scan(target=target, mock_mode=mock)
            elif choice == "3":
                list_plugins()
            elif choice == "4":
                import subprocess
                subprocess.run([sys.executable, "verify_proof.py"])
            elif choice == "5":
                import subprocess
                subprocess.run([sys.executable, "run_tests.py"])
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
    
    # Global mode flags
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--real", action="store_true", help="Force REAL active scanning mode")
    mode_group.add_argument("--mock", action="store_true", help="Force MOCK demo mode")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("target", help="Target URL or IP address")
    scan_parser.add_argument("-p", "--previous", help="Path to previous report for delta comparison")
    scan_parser.add_argument("--json", help="Output JSON file path")
    scan_parser.add_argument("--html", help="Output HTML file path")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Fail CI/CD pipeline if findings equal or exceed severity threshold")
    scan_parser.add_argument("--webhook", help="URL for Slack/Discord webhook alerts")
    scan_parser.add_argument("--openapi", help="Path or URL to OpenAPI/Swagger spec")
    scan_parser.add_argument("--headers", help="Custom HTTP headers (format 'Header1: val1; Header2: val2')")
    scan_parser.add_argument("--profile", choices=["full", "owasp", "api", "recon"], default="full", help="Select scan profile: full (all), owasp (OWASP Top 10), api (API Security), recon (Passive Recon)")
    scan_mode_group = scan_parser.add_mutually_exclusive_group()
    scan_mode_group.add_argument("--real", action="store_true", help="Force REAL active scanning mode")
    scan_mode_group.add_argument("--mock", action="store_true", help="Force MOCK demo mode")
    
    subparsers.add_parser("plugins", help="List available plugins")
    
    server_parser = subparsers.add_parser("server", help="Start the web interface")
    server_mode_group = server_parser.add_mutually_exclusive_group()
    server_mode_group.add_argument("--real", action="store_true", help="Force REAL active scanning mode")
    server_mode_group.add_argument("--mock", action="store_true", help="Force MOCK demo mode")

    testbed_parser = subparsers.add_parser("testbed", help="Launch the local vulnerable sandbox testbed")
    testbed_parser.add_argument("--port", type=int, default=8080, help="Port to run testbed on (default: 8080)")
    testbed_parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    
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
    
    if mock_mode is not None:
        config.MOCK_MODE = mock_mode

    if args.command == "scan":
        profile = getattr(args, "profile", "full")
        return run_scan(args.target, args.previous, args.json, args.html, args.fail_on, args.webhook, args.openapi, args.headers, mock_mode=config.MOCK_MODE, profile=profile)

    elif args.command == "plugins":
        list_plugins()
        return 0
    elif args.command == "testbed":
        from testbed.app import run_testbed
        run_testbed(host=args.host, port=args.port)
        return 0
    elif args.command == "server":
        from ui.app import app
        mode_str = "MOCK DEMO" if config.MOCK_MODE else "REAL ACTIVE SCAN"
        print("\n" + "=" * 60)
        print(f"Starting AutoSecAudit Web Dashboard [{mode_str} MODE]...")
        print("Open http://localhost:5000 in your browser")
        print("=" * 60 + "\n")
        app.run(debug=config.DEBUG, host="0.0.0.0", port=5000)
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())

