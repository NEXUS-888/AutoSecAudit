#!/usr/bin/env python3
import argparse
import logging
import sys
import os
from pathlib import Path

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


def run_scan(target: str, previous_report: str = None, output_json: str = None, output_html: str = None,
             fail_on: str = None, webhook: str = None, openapi: str = None, headers: str = None):
    logger.info(f"Starting scan for target: {target}")
    
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

    engine = Engine()
    loaded = engine.load_plugins()
    print(f"Loaded {loaded} plugin(s)")
    
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
            prev_findings = [Finding(**f) for f in previous_data.get("all_findings", [])]
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
    print(f"Scan Complete!")
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
    print(f"Loaded {count} plugin(s):")
    for plugin in engine.plugins:
        print(f"  - {plugin.__class__.__name__}")


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
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Fail CI/CD pipeline if findings equal or exceed severity threshold")
    scan_parser.add_argument("--webhook", help="URL for Slack/Discord webhook alerts")
    scan_parser.add_argument("--openapi", help="Path or URL to OpenAPI/Swagger spec")
    scan_parser.add_argument("--headers", help="Custom HTTP headers (format 'Header1: val1; Header2: val2')")
    
    subparsers.add_parser("plugins", help="List available plugins")
    
    subparsers.add_parser("server", help="Start the web interface")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        return run_scan(args.target, args.previous, args.json, args.html, args.fail_on, args.webhook, args.openapi, args.headers)

    elif args.command == "plugins":
        list_plugins()
        return 0
    elif args.command == "server":
        from ui.app import app
        print("Starting AutoSecAudit web interface...")
        print("Open http://localhost:5000 in your browser")
        app.run(debug=config.DEBUG, host="0.0.0.0", port=5000)
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
