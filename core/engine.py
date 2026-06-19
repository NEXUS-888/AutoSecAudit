import logging
import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import config
from core.models import ScanResult, Finding, Report
from core.utils import validate_target, normalize_target, get_timestamp, save_json

logger = logging.getLogger(__name__)


class Engine:
    """Core scanning engine that orchestrates plugin execution."""

    def __init__(self, mock_mode: Optional[bool] = None):
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self.plugins: List[Any] = []
        self.scan_results: List[ScanResult] = []
        self.target: str = ""
        self.previous_report: Optional[Dict[str, Any]] = None

    def load_plugins(self, plugins_dir: Optional[str] = None) -> int:
        """Dynamically load all plugins from the plugins directory."""
        if plugins_dir is None:
            plugins_dir = config.PLUGINS_DIR
        
        plugins_path = Path(plugins_dir)
        if not plugins_path.exists():
            logger.warning(f"Plugins directory not found: {plugins_dir}")
            return 0

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

        logger.info(f"Loaded {loaded_count} plugin(s)")
        return loaded_count

    def _is_scanner_class(self, cls: Any) -> bool:
        """Check if class is a subclass of BaseScanner but not BaseScanner itself."""
        try:
            from plugins.base_plugin import BaseScanner
            return issubclass(cls, BaseScanner) and cls != BaseScanner
        except ImportError:
            return False

    def set_target(self, target: str) -> bool:
        """Set and validate the target."""
        if not validate_target(target):
            logger.error(f"Invalid target: {target}")
            return False
        
        self.target = normalize_target(target)
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
                        scan_result = ScanResult(
                            tool_name=result.get("tool_name", plugin.__class__.__name__),
                            target=self.target,
                            timestamp=timestamp,
                            findings=self._dict_to_findings(result.get("findings", [])),
                            raw_output=result.get("raw_output", "")
                        )
                        self.scan_results.append(scan_result)
                        logger.info(f"Plugin {plugin.__class__.__name__} completed with {len(scan_result.findings)} findings")
                except TimeoutError:
                    logger.error(f"Plugin {plugin.__class__.__name__} timed out after {config.SCAN_TIMEOUT}s")
                except Exception as e:
                    logger.error(f"Plugin {plugin.__class__.__name__} failed: {e}")

        return self.scan_results

    def _execute_plugin(self, plugin: Any) -> Dict[str, Any]:
        """Execute a single plugin and return results."""
        try:
            plugin.configure(self.target)
            return plugin.get_standardized_output()
        except Exception as e:
            logger.error(f"Error executing {plugin.__class__.__name__}: {e}")
            return {"tool_name": plugin.__class__.__name__, "findings": []}

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

        report = Report(
            target=self.target,
            timestamp=get_timestamp(),
            scan_results=self.scan_results,
            all_findings=all_findings,
            summary=summary,
            previous_report_path=None
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
