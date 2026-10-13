"""
Unified Security Scan Pipeline for AutoSecAudit.
Consolidates scope check, plugin discovery/execution, intelligence post-processing,
and report generation across CLI, Web UI (async/sync), and MCP server.
"""

import logging
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import config
from core.engine import Engine
from core.models import Finding, Report
from core.utils import (
    validate_target,
    is_target_allowed,
    check_target_reachable,
    load_json,
    generate_report_id,
)
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper
from intelligence.remediation import enrich_with_remediation
from intelligence.delta import DeltaAnalyzer
from reports.generator import ReportGenerator

logger = logging.getLogger(__name__)


class PipelinePaths(dict):
    """
    Container for report file paths returned by run_scan_pipeline.
    Supports attribute access (paths.json, paths.html), dict lookup (paths['json'], paths['html']),
    and tuple unpacking (json_path, html_path = paths).
    """

    def __init__(self, json_path: str = "", html_path: str = ""):
        super().__init__(json=json_path, html=html_path)
        self.json = json_path
        self.html = html_path

    def __iter__(self):
        yield self.json
        yield self.html

    def __getitem__(self, item):
        if isinstance(item, int):
            return (self.json, self.html)[item]
        return super().__getitem__(item)


class ScanCancelledError(RuntimeError):
    """Raised when a running scan is cancelled or timed out."""
    pass


@dataclass
class ScanRequest:
    """Configuration for a security scan execution."""
    target: str
    profile: str = "full"
    mock_mode: bool = False
    skip_reachability: bool = False
    reachability_timeout: float = 5.0
    login_user: Optional[str] = None
    login_pass: Optional[str] = None
    login_url: Optional[str] = None
    openapi_spec: Optional[str] = None
    previous_report: Optional[Union[str, Dict[str, Any], Report]] = None
    output_json: Optional[str] = None
    output_html: Optional[str] = None
    headers: Optional[Union[str, Dict[str, str]]] = None
    progress_callback: Optional[Callable[..., Any]] = None
    cancel_check: Optional[Callable[[], bool]] = None
    webhook: Optional[str] = None
    report_id: Optional[str] = None
    treat_dev_artifacts_as_info: bool = False
    owner: Optional[str] = None


def run_scan_pipeline(
    request: Union[ScanRequest, Dict[str, Any], str, None] = None,
    **kwargs
) -> Tuple[Report, PipelinePaths]:
    """
    Execute the unified scanning pipeline.

    Order of operations:
    1. Scope check (validate target, check permission, optional reachability)
    2. Load plugins for profile
    3. Set target & custom headers
    4. Auth configuration (if credentials provided)
    5. OpenAPI endpoint import (if spec provided)
    6. Run plugins & crawler
    7. Generate raw report
    8. Delta comparison (if previous report provided)
    9. Correlator (link related findings)
    10. Enricher (CVE / CVSS intelligence)
    11. ComplianceMapper (OWASP, CWE, PCI-DSS mapping)
    12. Remediation (actionable remediation advice)
    13. Summary recalculation
    14. Save JSON + HTML reports
    """
    # 0. Normalize inputs
    if isinstance(request, str):
        target = request
        req_dict = kwargs
    elif isinstance(request, ScanRequest):
        req_dict = {k: v for k, v in request.__dict__.items()}
        req_dict.update(kwargs)
        target = req_dict.get("target", "")
    elif isinstance(request, dict):
        req_dict = dict(request)
        req_dict.update(kwargs)
        target = req_dict.get("target", "")
    else:
        req_dict = kwargs
        target = req_dict.get("target", "")

    profile = (req_dict.get("profile") or "full").lower()
    mock_mode = bool(req_dict.get("mock_mode", False))
    skip_reachability = bool(req_dict.get("skip_reachability", False))
    login_user = req_dict.get("login_user")
    login_pass = req_dict.get("login_pass")
    login_url = req_dict.get("login_url")
    openapi_spec = req_dict.get("openapi_spec")
    previous_report = req_dict.get("previous_report")
    output_json = req_dict.get("output_json")
    output_html = req_dict.get("output_html")
    headers = req_dict.get("headers")
    progress_callback = req_dict.get("progress_callback")
    webhook = req_dict.get("webhook")
    report_id = req_dict.get("report_id")
    owner = req_dict.get("owner") or kwargs.get("owner")
    cancel_check = req_dict.get("cancel_check") or kwargs.get("cancel_check")
    reachability_timeout = float(req_dict.get("reachability_timeout", 5.0))
    treat_dev_artifacts_as_info = bool(req_dict.get("treat_dev_artifacts_as_info", False))

    def emit(stage: str, message: str, progress: int = 0, detail: str = "", status: Optional[str] = None):
        if progress_callback:
            try:
                import inspect
                sig = inspect.signature(progress_callback)
                param_count = len(sig.parameters)
                if param_count >= 5:
                    progress_callback(stage, message, progress, detail, status)
                elif param_count == 4:
                    progress_callback(stage, message, progress, detail)
                elif param_count == 3:
                    progress_callback(stage, message, progress)
                elif param_count == 2:
                    progress_callback(stage, message)
                else:
                    progress_callback(stage, message, progress, detail, status)
            except Exception as ex:
                logger.debug(f"Progress callback invocation error: {ex}")

    # 1. Scope check
    emit("init", f"Verifying target scope: {target}...", 5)
    if not validate_target(target):
        emit("error", f"Invalid target URL or IP: {target}", 0, status="error")
        raise ValueError(f"Invalid target '{target}'. Please provide a valid URL or IP address.")

    allowed, allow_reason = is_target_allowed(target)
    if not allowed:
        emit("error", f"Target not allowed: {allow_reason}", 0, status="error")
        raise PermissionError(f"Target not allowed: {allow_reason}")

    if not mock_mode and not skip_reachability:
        emit("init", f"Checking pre-flight target reachability for {target}...", 8)
        reachable, reach_msg = check_target_reachable(target, timeout=reachability_timeout)
        if not reachable:
            emit("error", f"Target is offline or unreachable: {reach_msg}", 0, status="error")
            raise ConnectionError(f"Target is offline or unreachable: {reach_msg}")

    # Parse headers if string
    header_dict = {}
    if headers:
        if isinstance(headers, dict):
            header_dict = headers
        elif isinstance(headers, str):
            for h in headers.split(";"):
                if ":" in h:
                    k, v = h.split(":", 1)
                    header_dict[k.strip()] = v.strip()

    engine_cls = req_dict.get("engine_cls") or kwargs.get("engine_cls") or Engine
    generator_cls = req_dict.get("generator_cls") or kwargs.get("generator_cls") or ReportGenerator

    # 2. Load plugins
    mode_label = "MOCK DEMO" if mock_mode else "REAL ACTIVE SCAN"
    emit("init", f"Initializing {mode_label} engine [{profile.upper()} profile]...", 10)
    engine = engine_cls(mock_mode=mock_mode, profile=profile)
    if report_id and hasattr(engine, "report_id"):
        engine.report_id = report_id
    if header_dict and hasattr(engine, "set_custom_headers"):
        engine.set_custom_headers(header_dict)

    loaded_count = engine.load_plugins(profile=profile)
    logger.info(f"Loaded {loaded_count} plugin(s) for profile '{profile}'")

    # 3. Set target
    if not engine.set_target(target, check_reachable=False):
        emit("error", f"Failed to set target '{target}'", 0, status="error")
        raise ValueError(f"Failed to set target '{target}'")

    # 4. Auth
    if login_user and login_pass:
        engine.set_auth_credentials(login_user, login_pass, login_url=login_url)
        emit("auth", f"Attempting automated login to {target} as {login_user}...", 12)

    # 5. OpenAPI
    if openapi_spec:
        from core.openapi import OpenAPIImporter
        importer = OpenAPIImporter(openapi_spec, headers=header_dict)
        if importer.load_spec():
            imported_eps = importer.get_endpoints()
            engine.add_endpoints(imported_eps)
            emit("init", f"Imported {len(imported_eps)} endpoints from OpenAPI spec", 14)

    # Checkpoint 1: Before plugins
    if cancel_check and cancel_check():
        logger.warning("Scan cancelled or timed out before plugins; halting.")
        raise ScanCancelledError("Scan cancelled or timed out before plugins.")

    # 6. Run plugins
    emit("crawling", "Crawling target for endpoints...", 16)
    emit("scanning", "Starting plugin execution...", 20)
    engine.run_plugins()
    if hasattr(engine, "auth_result") and engine.auth_result:
        if engine.auth_result.success:
            emit("auth", f"Authenticated! Captured session ({len(engine.auth_result.cookies)} cookies).", 25)
        else:
            emit("auth", f"Auth note: {engine.auth_result.message}. Scanned public surface.", 25)

    if hasattr(engine, "crawl_result") and engine.crawl_result:
        cr = engine.crawl_result
        emit("crawling", f"Discovered {len(cr.endpoints)} endpoints, {len(cr.forms)} forms", 30,
             f"Visited {cr.pages_visited} pages")

    total_findings = sum(len(sr.findings) for sr in getattr(engine, "scan_results", []))
    emit("scanning", f"All {len(engine.scan_results)} plugins complete — {total_findings} raw findings", 55)

    # Checkpoint 2: After plugins
    if cancel_check and cancel_check():
        logger.warning("Scan cancelled or timed out after plugins; halting.")
        raise ScanCancelledError("Scan cancelled or timed out after plugins.")

    # 7. Generate report
    emit("processing", "Generating raw report...", 60)
    report = engine.generate_report()
    rep_id = getattr(report, "report_id", None)
    if not rep_id or not isinstance(rep_id, str):
        rep_id = report_id or generate_report_id()
        if hasattr(report, "report_id"):
            report.report_id = rep_id
    elif report_id:
        report.report_id = report_id

    if owner is not None:
        report.owner = owner
    report.treat_dev_artifacts_as_info = treat_dev_artifacts_as_info

    # Checkpoint 3: After report generation
    if cancel_check and cancel_check():
        logger.warning("Scan cancelled or timed out after report generation; halting.")
        raise ScanCancelledError("Scan cancelled or timed out after report generation.")

    # 8. Correlator (before delta: stored reports hold merged findings, so compare merged with merged)
    emit("enriching", "Correlating findings...", 65)
    correlator = Correlator()
    report.all_findings = correlator.merge_canonical(report.all_findings)
    report.all_findings = correlator.link_related(report.all_findings)

    # 9. Delta comparison
    if previous_report:
        emit("processing", "Running delta analysis...", 70)
        prev_report_obj = None
        if isinstance(previous_report, Report):
            prev_report_obj = previous_report
        elif isinstance(previous_report, dict):
            prev_report_obj = Report.from_dict(previous_report)
        elif isinstance(previous_report, str) and os.path.exists(previous_report):
            data = load_json(previous_report)
            if data:
                prev_report_obj = Report.from_dict(data)

        if prev_report_obj:
            delta = DeltaAnalyzer().compare(report, prev_report_obj)
            report.delta = delta
            report.previous_report_path = str(previous_report) if isinstance(previous_report, str) else None

    # 10. Enricher
    emit("enriching", "Enriching findings with CVE data...", 75)
    enricher = Enricher(mock_mode=mock_mode)
    report.all_findings = enricher.enrich(report.all_findings)

    # 11. ComplianceMapper
    emit("enriching", "Mapping compliance standards...", 80)
    mapper = ComplianceMapper()
    report.all_findings = mapper.map_findings(report.all_findings)

    # 12. Remediation
    emit("enriching", "Adding remediation guidance...", 85)
    report.all_findings = enrich_with_remediation(report.all_findings)

    # 13. Summary
    report.summary = engine._generate_summary(report.all_findings)
    emit("processing", "Summary statistics calculated", 88)

    # Checkpoint 4: Before saving
    if cancel_check and cancel_check():
        logger.warning("Scan cancelled or timed out before saving reports; halting.")
        raise ScanCancelledError("Scan cancelled or timed out before saving reports.")

    # 14. Save JSON + HTML
    emit("saving", "Saving JSON report...", 90)
    save_result = engine.save_report(report, file_path=output_json)
    if isinstance(save_result, (tuple, list)):
        json_path = str(save_result[0])
    else:
        json_path = str(save_result)

    emit("saving", "Generating HTML report...", 95)
    generator = generator_cls()
    if output_html:
        gen_result = generator.generate_html(report, output_path=output_html)
    else:
        gen_result = generator.generate_report(report)
    if isinstance(gen_result, (tuple, list)):
        html_path = str(gen_result[0])
    else:
        html_path = str(gen_result)

    # Webhook
    if webhook:
        try:
            from core.notifications import WebhookNotifier
            notifier = WebhookNotifier(webhook)
            notifier.send_notification(report.summary, report.target)
        except Exception as e:
            logger.warning(f"Webhook notification failed: {e}")

    rep_name = Path(json_path).stem.replace("scan_", "").replace("report_", "")
    emit("done", f"Scan complete — {len(report.all_findings)} findings", 100, detail=rep_name, status="done")

    paths = PipelinePaths(json_path=json_path, html_path=html_path)
    return report, paths
