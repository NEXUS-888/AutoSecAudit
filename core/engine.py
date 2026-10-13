import logging
import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Any, Optional
import time
import dataclasses
from concurrent.futures import ThreadPoolExecutor, wait
import threading
import urllib.parse
from datetime import datetime

import config
from core.models import ScanResult, Finding, Report
from core.utils import (
    validate_target,
    normalize_target,
    get_timestamp,
    generate_report_id,
    save_json,
    check_target_reachable,
    is_target_allowed,
)
from core.crawler import WebCrawler
from core.spa_detector import SPADetector
from core.http_client import ScanHttpClient
from core.politeness import PolitenessEngine, DEFAULT_REQUEST_INTERVAL_MS
from core.timing import global_timing_controller

logger = logging.getLogger(__name__)


class Engine:
    """Core scanning engine that orchestrates plugin execution."""

    def __init__(
        self,
        mock_mode: Optional[bool] = None,
        profile: str = "full",
        request_interval_ms: Optional[int] = None,
        politeness: Optional[PolitenessEngine] = None,
    ):
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self.profile = profile.lower() if profile else "full"
        self.plugins: List[Any] = []
        self.scan_results: List[ScanResult] = []
        self.target: str = ""
        self.spa_detector: Optional[SPADetector] = None
        self._lock = threading.Lock()

        if politeness is not None:
            client_politeness = politeness
            if request_interval_ms is not None:
                client_politeness.request_interval_ms = request_interval_ms
        elif request_interval_ms is not None:
            client_politeness = PolitenessEngine(request_interval_ms=request_interval_ms)
        else:
            client_politeness = PolitenessEngine(request_interval_ms=DEFAULT_REQUEST_INTERVAL_MS)

        self.timing_controller = global_timing_controller
        self.http_client = ScanHttpClient(
            target=self.target,
            mock_mode=self.mock_mode,
            politeness=client_politeness,
            timing_controller=self.timing_controller,
        )
        self.scan_timeout: Optional[int] = None
        self.previous_report: Optional[Dict[str, Any]] = None
        self.crawl_result = None  # populated by run_plugins
        self.imported_endpoints: List[Dict[str, Any]] = []
        self.explicit_openapi: bool = False
        self.scan_start_time: float = 0.0
        self.scan_duration_seconds: float = 0.0
        self.per_plugin_seconds: Dict[str, float] = {}
        self.plugins_timed_out: int = 0
        self.plugins_skipped: int = 0
        self.scan_deadline_hit: bool = False
        self.dev_environment: Optional[str] = None
        self.auth_credentials: Optional[Dict[str, Any]] = None
        self.auth_result: Optional[Any] = None
        self.custom_headers: Dict[str, str] = {}

    def add_endpoints(self, endpoints: List[Dict[str, Any]], explicit: bool = True) -> None:
        """Add endpoints (e.g. from OpenAPI spec) to be scanned by plugins."""
        if explicit:
            self.explicit_openapi = True
        if not endpoints:
            return
        self.imported_endpoints.extend(endpoints)
        # Update any currently loaded plugins with merged & deduped list
        for plugin in self.plugins:
            current = getattr(plugin, "discovered_endpoints", []) or []
            merged = []
            seen = set()
            for ep in current + endpoints:
                if isinstance(ep, dict):
                    key = (str(ep.get("method", "GET")).upper(), str(ep.get("path", "")), str(ep.get("param", "")))
                    if key not in seen:
                        seen.add(key)
                        merged_ep = dict(ep)
                        merged_ep["method"] = str(ep.get("method", "GET")).upper()
                        merged.append(merged_ep)
            plugin.set_discovered_endpoints(merged)

    def _probe_and_import_openapi(self) -> List[Dict[str, Any]]:
        """Probe common OpenAPI/Swagger paths on the target origin and import endpoints."""
        probe_paths = [
            "/openapi.json",
            "/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api-docs",
            "/openapi.yaml",
        ]
        from core.openapi import OpenAPIImporter

        for path in probe_paths:
            try:
                target_url = urllib.parse.urljoin(self.target, path)
                resp = self.http_client.request("GET", target_url)
                if resp is None or resp.status_code != 200:
                    continue

                spec_data = None
                try:
                    spec_data = resp.json()
                except Exception:
                    try:
                        import yaml
                        spec_data = yaml.safe_load(resp.text)
                    except Exception:
                        pass

                if isinstance(spec_data, dict) and ("paths" in spec_data or "swagger" in spec_data or "openapi" in spec_data):
                    importer = OpenAPIImporter(spec_data=spec_data)
                    endpoints = importer.get_endpoints()
                    if endpoints:
                        logger.info(f"Auto-probed OpenAPI spec at {path}, discovered {len(endpoints)} endpoints")
                        return endpoints
            except Exception as exc:
                logger.debug(f"[Engine] OpenAPI probe failed for {path}: {exc}")

        return []

    def set_auth_credentials(self, username: str, password: str, login_url: Optional[str] = None) -> None:
        """Configure test credentials for automated login."""
        self.auth_credentials = {
            "username": username,
            "password": password,
            "login_url": login_url
        }
        logger.info(f"Configured automated login credentials for user: {username}")

    def set_custom_headers(self, headers: Dict[str, str]) -> None:
        """Set custom HTTP headers across all scans."""
        self.custom_headers = dict(headers)

    def set_profile(self, profile: str) -> None:
        """Set active scan profile."""
        self.profile = profile.lower() if profile else "full"
        logger.info(f"Engine scan profile set to: {self.profile}")

    def load_plugins(self, plugins_dir: Optional[str] = None, profile: Optional[str] = None) -> int:
        """Dynamically load all plugins from the plugins directory."""
        if profile:
            self.profile = profile.lower()
        if plugins_dir is None:
            plugins_dir = config.PLUGINS_DIR
        
        plugins_path = Path(plugins_dir)
        if not plugins_path.exists():
            logger.warning(f"Plugins directory not found: {plugins_dir}")
            return 0

        self.plugins = []
        loaded_count = 0
        for importer, modname, _ in pkgutil.iter_modules([str(plugins_path)]):
            if modname == "base_plugin" or modname.startswith("_") or modname == "mock_plugin":
                continue
            
            try:
                module = importlib.import_module(f"plugins.{modname}")
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        hasattr(attr, "__bases__") and 
                        attr.__name__ != "BaseScanner" and
                        self._is_scanner_class(attr)):
                        plugin_instance = attr(mock_mode=self.mock_mode)
                        self.plugins.append(plugin_instance)
                        logger.info(f"Loaded plugin: {attr.__name__}")
                        loaded_count += 1
            except Exception as e:
                logger.error(f"Failed to load plugin {modname}: {e}")

        # Filter by profile if configured
        profile_config = getattr(config, "SCAN_PROFILES", {}).get(self.profile)
        if profile_config and profile_config.get("plugins") is not None:
            allowed = set(profile_config["plugins"])
            self.plugins = [p for p in self.plugins if p.__class__.__name__ in allowed]
            logger.info(f"Applied scan profile '{self.profile}': {len(self.plugins)} plugins selected out of {loaded_count}")
        else:
            logger.info(f"Loaded {loaded_count} plugin(s) [profile: {self.profile}]")
            
        return len(self.plugins)

    def _is_scanner_class(self, cls: Any) -> bool:
        """Check if class is a subclass of BaseScanner but not BaseScanner itself."""
        try:
            from plugins.base_plugin import BaseScanner
            return issubclass(cls, BaseScanner) and cls != BaseScanner
        except ImportError:
            return False

    def set_target(self, target: str, check_reachable: bool = False) -> bool:
        """Set and validate the target. Optionally verify target reachability."""
        if not validate_target(target):
            logger.error(f"Invalid target: {target}")
            return False

        allowed, reason = is_target_allowed(target)
        if not allowed:
            logger.error(f"Target not allowed: {target} - {reason}")
            return False
        
        normalized = normalize_target(target)
        if check_reachable and not self.mock_mode:
            import core.utils as _utils
            reachable, reason = _utils.check_target_reachable(normalized)
            if not reachable:
                logger.error(f"Target unreachable: {normalized} - {reason}")
                return False

        self.target = normalized
        self.http_client.set_target(self.target)
        logger.info(f"Target set: {self.target}")
        return True

    def setup_shared_http_client(
        self,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        """Configure shared ScanHttpClient and inject into all loaded plugins."""
        self.http_client.set_target(self.target)
        combined_headers = dict(self.custom_headers)
        if auth_headers:
            combined_headers.update(auth_headers)
        self.http_client.set_auth(headers=combined_headers, cookies=auth_cookies)

        for plugin in self.plugins:
            if hasattr(plugin, "set_http_client"):
                plugin.set_http_client(self.http_client)
            if hasattr(plugin, "set_auth"):
                plugin.set_auth(headers=combined_headers, cookies=auth_cookies)
            if self.spa_detector and hasattr(plugin, "set_spa_detector"):
                plugin.set_spa_detector(self.spa_detector)

    def calibrate_spa_detector(self, target: Optional[str] = None) -> Optional[SPADetector]:
        """Calibrate SPA soft-404 detector once for target and inject into loaded plugins."""
        tgt = target or self.target
        if not tgt:
            return None
        try:
            base_url = tgt.split("?")[0].rstrip("/")
            session = self.http_client.session if self.http_client else None
            self.spa_detector = SPADetector(base_url=base_url, session=session)
            for plugin in self.plugins:
                if hasattr(plugin, "set_spa_detector"):
                    plugin.set_spa_detector(self.spa_detector)
            return self.spa_detector
        except Exception as e:
            logger.debug(f"[Engine] SPA calibration failed for {tgt}: {e}")
            return None

    def set_previous_report(self, report_path: str) -> bool:
        """Load a previous scan report for delta comparison."""
        from core.utils import load_json
        data = load_json(report_path)
        if data:
            self.previous_report = data
            logger.info(f"Loaded previous report: {report_path}")
            return True
        return False

    def run_plugins(self) -> List[ScanResult]:
        """Execute all loaded plugins in parallel using threading."""
        if not self.plugins:
            logger.warning("No plugins loaded")
            return []

        if not self.target:
            logger.error("No target set")
            return []

        self.scan_results = []
        self.scan_start_time = time.monotonic()
        self.per_plugin_seconds = {}
        self.plugins_timed_out = 0
        self.plugins_skipped = 0
        self.scan_deadline_hit = False
        timeout = self.scan_timeout if self.scan_timeout is not None else getattr(config, "SCAN_DEADLINE_SECONDS", 300)
        if self.http_client:
            self.http_client.requests_total = 0
            self.http_client.requests_failed = 0
            self.http_client.requests_skipped_deadline = 0
            self.http_client.deadline = self.scan_start_time + timeout
        timestamp = get_timestamp()

        # Automated Authentication if credentials configured
        auth_cookies = {}
        auth_headers = dict(self.custom_headers)

        if self.auth_credentials and not self.mock_mode and self.target:
            try:
                from core.authenticator import AutoAuthenticator
                authenticator = AutoAuthenticator(
                    base_url=self.target,
                    username=self.auth_credentials["username"],
                    password=self.auth_credentials["password"],
                    login_url=self.auth_credentials.get("login_url")
                )
                self.auth_result = authenticator.authenticate()
                if self.auth_result.success:
                    logger.info(f"Automated authentication successful on {self.target} - session captured.")
                    auth_cookies.update(self.auth_result.cookies)
                    auth_headers.update(self.auth_result.headers)
                else:
                    logger.warning(f"Automated authentication failed on {self.target}: {self.auth_result.message}")
            except Exception as e:
                logger.error(f"Error during automated login: {e}", exc_info=True)

        # Setup shared HTTP client early so crawler and openapi probe can use it
        self.setup_shared_http_client(auth_headers=auth_headers, auth_cookies=auth_cookies)

        # Run web crawler first to discover real endpoints (including authenticated paths)
        crawler = WebCrawler(
            max_pages=getattr(config, "CRAWL_MAX_PAGES", 100),
            max_depth=getattr(config, "CRAWL_MAX_DEPTH", 4),
            max_seconds=getattr(config, "CRAWL_MAX_SECONDS", 60),
            mock_mode=self.mock_mode,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies
        )
        self.crawl_result = crawler.crawl(self.target)
        discovered = self.crawl_result.get_injectable_endpoints()
        login_endpoints = self.crawl_result.get_login_endpoints()
        logger.info(f"Crawler discovered {len(discovered)} injectable endpoints, {len(login_endpoints)} login paths")

        # Detect dev environment (e.g. Vite, Webpack, Next.js dev servers)
        if not self.mock_mode and self.target:
            try:
                import requests
                from core.dev_detector import detect_dev_environment
                resp = requests.get(self.target, headers=auth_headers, timeout=(2.0, 4.0), verify=False)
                self.dev_environment = detect_dev_environment(resp.text, dict(resp.headers))
                if self.dev_environment:
                    logger.warning(f"Target identified as dev environment: {self.dev_environment}. Artifact findings will be tagged.")
            except Exception as exc:
                logger.debug(f"Dev environment detection failed: {exc}")

        # Probe and auto-import OpenAPI specs if no spec was explicitly provided
        if not self.explicit_openapi and not self.imported_endpoints and not self.mock_mode and self.target:
            probed_endpoints = self._probe_and_import_openapi()
            if probed_endpoints:
                self.imported_endpoints.extend(probed_endpoints)

        # Merge crawler endpoints with imported OpenAPI endpoints (dedupe on method+path+param)
        all_endpoints = []
        seen_keys = set()
        for ep in (discovered or []) + (self.imported_endpoints or []):
            if isinstance(ep, dict):
                m = str(ep.get("method", "GET")).upper()
                p = str(ep.get("path", ""))
                param = str(ep.get("param", ""))
                key = (m, p, param)
                if key not in seen_keys:
                    seen_keys.add(key)
                    merged_ep = dict(ep)
                    merged_ep["method"] = m
                    merged_ep["path"] = p
                    merged_ep["param"] = param
                    all_endpoints.append(merged_ep)

        # Calibrate SPA soft-404 detector once in real mode and share across plugins
        if not self.mock_mode and self.target and not self.spa_detector:
            self.calibrate_spa_detector()

        # Update discovered endpoints, dev environment, and spa detector on plugins
        for plugin in self.plugins:
            plugin.set_discovered_endpoints(all_endpoints)
            if self.dev_environment and hasattr(plugin, "set_dev_environment"):
                plugin.set_dev_environment(self.dev_environment)
            if self.spa_detector and hasattr(plugin, "set_spa_detector"):
                plugin.set_spa_detector(self.spa_detector)

        timeout = self.scan_timeout if self.scan_timeout is not None else getattr(config, "SCAN_DEADLINE_SECONDS", 300)
        time_elapsed = time.monotonic() - self.scan_start_time
        remaining_timeout = max(0.01, timeout - time_elapsed)
        if self.http_client:
            self.http_client.deadline = self.scan_start_time + timeout

        logger.info(f"Running {len(self.plugins)} plugins on {self.target} (timeout: {timeout}s)")

        executor = ThreadPoolExecutor(max_workers=config.THREAD_COUNT)
        try:
            future_to_plugin = {
                executor.submit(self._execute_plugin, plugin): plugin 
                for plugin in self.plugins
            }

            done, not_done = wait(future_to_plugin.keys(), timeout=remaining_timeout)

            if not_done:
                self.scan_deadline_hit = True
                self.plugins_timed_out = len(not_done)

            for future in done:
                plugin = future_to_plugin[future]
                try:
                    result = future.result()
                    if result:
                        status = result.get("status", "success")
                        error = result.get("error")
                        if status == "skipped":
                            self.plugins_skipped += 1
                        scan_result = ScanResult(
                            tool_name=result.get("tool_name", plugin.__class__.__name__),
                            target=self.target,
                            timestamp=timestamp,
                            findings=self._dict_to_findings(result.get("findings", [])),
                            raw_output=result.get("raw_output", ""),
                            status=status,
                            error=error
                        )
                        self.scan_results.append(scan_result)
                        if status == "failed":
                            logger.warning(f"Plugin {plugin.__class__.__name__} reported failure: {error}")
                        elif status == "skipped":
                            logger.info(f"Plugin {plugin.__class__.__name__} skipped: {error}")
                        else:
                            logger.info(f"Plugin {plugin.__class__.__name__} completed with {len(scan_result.findings)} findings")
                except Exception as e:
                    logger.error(f"Plugin {plugin.__class__.__name__} failed: {e}", exc_info=True)
                    self.scan_results.append(ScanResult(
                        tool_name=plugin.__class__.__name__,
                        target=self.target,
                        timestamp=timestamp,
                        findings=[],
                        raw_output=f"Plugin failed: {str(e)}",
                        status="failed",
                        error=str(e)
                    ))

            for future in not_done:
                plugin = future_to_plugin[future]
                logger.error(f"Plugin {plugin.__class__.__name__} timed out after {timeout}s")
                self.scan_results.append(ScanResult(
                    tool_name=plugin.__class__.__name__,
                    target=self.target,
                    timestamp=timestamp,
                    findings=[],
                    raw_output=f"Plugin timed out after {timeout}s",
                    status="timeout",
                    error=f"Timeout after {timeout}s"
                ))
        finally:
            self.scan_duration_seconds = round(time.monotonic() - self.scan_start_time, 4)
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)

        return self.scan_results

    def _execute_plugin(self, plugin: Any) -> Dict[str, Any]:
        """Execute a single plugin and return results."""
        start_t = time.monotonic()
        try:
            plugin.configure(self.target)
            output = plugin.get_standardized_output()
            output.setdefault("status", "success")
            output.setdefault("error", None)
            return output
        except Exception as e:
            logger.error(f"Error executing {plugin.__class__.__name__}: {e}", exc_info=True)
            return {
                "tool_name": plugin.__class__.__name__,
                "findings": [],
                "status": "failed",
                "error": str(e),
                "raw_output": f"Plugin failed with error: {str(e)}"
            }
        finally:
            elapsed = time.monotonic() - start_t
            p_name = getattr(plugin, "_get_tool_name", lambda: plugin.__class__.__name__)() or plugin.__class__.__name__
            with self._lock:
                self.per_plugin_seconds[p_name] = round(elapsed, 4)

    def _dict_to_findings(self, findings_data: List[Dict]) -> List[Finding]:
        """Convert dictionary data to Finding objects."""
        finding_fields = {f.name: f for f in dataclasses.fields(Finding)}
        findings = []
        for f in findings_data:
            kwargs = {}
            for name, field_def in finding_fields.items():
                if name in f:
                    kwargs[name] = f[name]
                elif name == "host":
                    kwargs["host"] = self.target or ""
                elif name == "confidence":
                    kwargs["confidence"] = "medium"
                elif name == "port":
                    kwargs["port"] = 0
                elif name == "id":
                    kwargs["id"] = ""
                elif name == "title":
                    kwargs["title"] = ""
                elif name == "severity":
                    kwargs["severity"] = "Medium"
                elif name == "description":
                    kwargs["description"] = ""
                elif name == "raw_output":
                    kwargs["raw_output"] = ""
                elif field_def.default is not dataclasses.MISSING:
                    kwargs[name] = field_def.default
                elif field_def.default_factory is not dataclasses.MISSING:
                    kwargs[name] = field_def.default_factory()

            if not kwargs.get("host") and self.target:
                kwargs["host"] = self.target
            if not kwargs.get("confidence"):
                kwargs["confidence"] = "medium"

            findings.append(Finding(**kwargs))
        return findings

    @property
    def throttled_requests(self) -> int:
        return self.http_client.throttled_count if hasattr(self, "http_client") else 0

    def generate_report(self) -> Report:
        """Generate the final aggregated report."""
        all_findings = []
        for scan_result in self.scan_results:
            all_findings.extend(scan_result.findings)

        summary = self._generate_summary(all_findings)

        auth_status = None
        if self.auth_result:
            auth_status = "Authenticated" if self.auth_result.success else f"Auth Failed ({self.auth_result.message})"
        elif self.custom_headers:
            auth_status = "Custom Headers"

        throttled = self.http_client.throttled_count if hasattr(self, "http_client") else 0

        rep_id = getattr(self, "report_id", None) or generate_report_id()
        self.report_id = rep_id

        total_reqs = self.http_client.requests_total if hasattr(self, "http_client") else 0
        failed_reqs = self.http_client.requests_failed if hasattr(self, "http_client") else 0
        skipped_deadline = self.http_client.requests_skipped_deadline if hasattr(self, "http_client") else 0

        deadline_hit = bool(getattr(self, "scan_deadline_hit", False) or skipped_deadline > 0)
        plugins_timed_out = self.plugins_timed_out
        high_failures = False
        if total_reqs > 0:
            fail_skip_ratio = (failed_reqs + skipped_deadline) / total_reqs
            if fail_skip_ratio > 0.05:
                high_failures = True

        degraded = bool(deadline_hit or plugins_timed_out > 0 or high_failures)

        if self.crawl_result is not None:
            crawl_info = {
                "pages_visited": getattr(self.crawl_result, "pages_visited", 0),
                "forms": len(getattr(self.crawl_result, "forms", []) or []),
                "fetch_failures": getattr(self.crawl_result, "fetch_failures", 0),
                "start_ok": getattr(self.crawl_result, "start_ok", True),
            }
        else:
            crawl_info = {
                "pages_visited": 0,
                "forms": 0,
                "fetch_failures": 0,
                "start_ok": True,
            }

        coverage = {
            "requests_total": total_reqs,
            "requests_failed": failed_reqs,
            "requests_skipped_deadline": skipped_deadline,
            "plugins_timed_out": plugins_timed_out,
            "plugins_skipped": self.plugins_skipped,
            "crawl": crawl_info,
            "duration_seconds": self.scan_duration_seconds,
            "per_plugin_seconds": dict(self.per_plugin_seconds),
            "degraded": degraded,
        }

        report = Report(
            target=self.target,
            timestamp=get_timestamp(),
            scan_results=self.scan_results,
            all_findings=all_findings,
            summary=summary,
            previous_report_path=None,
            dev_environment=self.dev_environment,
            auth_status=auth_status,
            throttled_requests=throttled,
            report_id=rep_id,
            coverage=coverage,
        )

        return report

    def _generate_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Generate summary statistics from findings."""
        throttled = self.http_client.throttled_count if hasattr(self, "http_client") else 0
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "throttled_requests": throttled,
        }
        
        for f in findings:
            severity = f.severity.lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary

    def save_report(self, report: Report, file_path: Optional[str] = None) -> str:
        """Save report to JSON file."""
        if file_path is None:
            rep_id = getattr(report, "report_id", None)
            if not rep_id or not isinstance(rep_id, str):
                rep_id = getattr(self, "report_id", None)
            if not rep_id or not isinstance(rep_id, str):
                rep_id = generate_report_id()
            if hasattr(report, "report_id"):
                report.report_id = rep_id
            file_path = f"{config.REPORTS_DIR}/scan_{rep_id}.json"
        
        save_json(report.to_dict(), str(file_path))
        logger.info(f"Report saved to {file_path}")
        return str(file_path)

    def run(self, target: str, profile: Optional[str] = None, check_reachable: bool = True) -> Report:
        """Convenience method to load plugins, set target, execute scan, and generate report."""
        if profile:
            self.profile = profile.lower()
        self.load_plugins(profile=self.profile)
        if not self.set_target(target, check_reachable=check_reachable):
            raise ConnectionError(f"Target '{target}' is invalid or unreachable.")
        self.run_plugins()
        report = self.generate_report()
        self.save_report(report)
        return report


