import logging
import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import config
from core.models import ScanResult, Finding, Report
from core.utils import (
    validate_target,
    normalize_target,
    get_timestamp,
    save_json,
    check_target_reachable,
    is_target_allowed,
)
from core.crawler import WebCrawler

logger = logging.getLogger(__name__)


class Engine:
    """Core scanning engine that orchestrates plugin execution."""

    def __init__(self, mock_mode: Optional[bool] = None, profile: str = "full"):
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self.profile = profile.lower() if profile else "full"
        self.plugins: List[Any] = []
        self.scan_results: List[ScanResult] = []
        self.target: str = ""
        self.previous_report: Optional[Dict[str, Any]] = None
        self.crawl_result = None  # populated by run_plugins
        self.crawler_data: Dict[str, Any] = {}  # populated by OpenAPI importer
        self.dev_environment: Optional[str] = None
        self.auth_credentials: Optional[Dict[str, Any]] = None
        self.auth_result: Optional[Any] = None
        self.custom_headers: Dict[str, str] = {}

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
        logger.info(f"Target set: {self.target}")
        return True

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

        # Run web crawler first to discover real endpoints (including authenticated paths)
        crawler = WebCrawler(
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

        # Pass discovered endpoints, dev environment, and auth context to all plugins
        for plugin in self.plugins:
            plugin.set_discovered_endpoints(discovered)
            if self.dev_environment and hasattr(plugin, "set_dev_environment"):
                plugin.set_dev_environment(self.dev_environment)
            if hasattr(plugin, "set_auth"):
                plugin.set_auth(headers=auth_headers, cookies=auth_cookies)

        logger.info(f"Running {len(self.plugins)} plugins on {self.target}")

        with ThreadPoolExecutor(max_workers=config.THREAD_COUNT) as executor:
            future_to_plugin = {
                executor.submit(self._execute_plugin, plugin): plugin 
                for plugin in self.plugins
            }
            
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                try:
                    result = future.result(timeout=config.SCAN_TIMEOUT)
                    if result:
                        status = result.get("status", "success")
                        error = result.get("error")
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
                except TimeoutError:
                    logger.error(f"Plugin {plugin.__class__.__name__} timed out after {config.SCAN_TIMEOUT}s")
                    self.scan_results.append(ScanResult(
                        tool_name=plugin.__class__.__name__,
                        target=self.target,
                        timestamp=timestamp,
                        findings=[],
                        raw_output=f"Plugin timed out after {config.SCAN_TIMEOUT}s",
                        status="timeout",
                        error=f"Timeout after {config.SCAN_TIMEOUT}s"
                    ))
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

        return self.scan_results

    def _execute_plugin(self, plugin: Any) -> Dict[str, Any]:
        """Execute a single plugin and return results."""
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

    def _dict_to_findings(self, findings_data: List[Dict]) -> List[Finding]:
        """Convert dictionary data to Finding objects."""
        findings = []
        for f in findings_data:
            finding = Finding(
                id=f.get("id", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "Medium"),
                host=f.get("host", self.target),
                port=f.get("port", 0),
                description=f.get("description", ""),
                raw_output=f.get("raw_output", ""),
                cve_id=f.get("cve_id"),
                cvss_score=f.get("cvss_score"),
                references=f.get("references"),
                owasp_tag=f.get("owasp_tag"),
                tool_name=f.get("tool_name"),
                confidence=f.get("confidence", "medium"),
                remediation=f.get("remediation")
            )
            findings.append(finding)
        return findings

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

        report = Report(
            target=self.target,
            timestamp=get_timestamp(),
            scan_results=self.scan_results,
            all_findings=all_findings,
            summary=summary,
            previous_report_path=None,
            dev_environment=self.dev_environment,
            auth_status=auth_status
        )

        return report

    def _generate_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Generate summary statistics from findings."""
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for f in findings:
            severity = f.severity.lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary

    def save_report(self, report: Report, file_path: Optional[str] = None) -> str:
        """Save report to JSON file."""
        if file_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = f"{config.REPORTS_DIR}/scan_{timestamp}.json"
        
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


