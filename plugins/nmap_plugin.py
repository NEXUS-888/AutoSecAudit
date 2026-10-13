import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import logging
import re
from urllib.parse import urlsplit
from typing import Dict, Any, List, Optional

import config
from plugins.base_plugin import BaseScanner
from core.utils import format_severity

logger = logging.getLogger(__name__)


class NmapPlugin(BaseScanner):
    """Nmap scanner plugin for port scanning and service detection."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.raw_output: str = ""

    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        host = self._extract_host(self.target or "")
        if not host or host.startswith("-"):
            logger.warning(f"Invalid or option-like Nmap target host '{host}', skipping scan")
            return

        tool_name = self._get_tool_name()
        if not self.check_tool_available(tool_name):
            logger.warning(f"Nmap not available, skipping scan")
            return

        cmd = self._build_command()

        try:
            logger.info(f"Running Nmap: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            self.raw_output = result.stdout
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            self.raw_output = ""
        except Exception as e:
            logger.error(f"Nmap execution error: {e}")
            self.raw_output = ""

    def parse_output(self) -> Dict[str, Any]:
        findings = []
        
        if not self.raw_output:
            return {"tool_name": "nmap", "findings": []}

        try:
            root = ET.fromstring(self.raw_output)
            
            for host in root.findall(".//host"):
                host_addr = host.find("address")
                host_addr = host_addr.get("addr") if host_addr is not None else self.target

                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    
                    service = port.find("service")
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        product = service.get("product", "")
                        version = service.get("version", "")
                        extrainfo = service.get("extrainfo", "")
                        
                        state = port.find("state")
                        state_attr = state.get("state") if state is not None else "unknown"

                        if state_attr == "open":
                            port_str = str(port_id)
                            severity = self._assess_severity(service_name, port_str)
                            
                            finding_id = f"NMAP-{port_str}"
                            title = f"Open Port {port_str}/{protocol} - {service_name}"
                            description = f"Service: {service_name}"
                            if product:
                                description += f" ({product}"
                                if version:
                                    description += f" {version}"
                                description += ")"
                            if extrainfo:
                                description += f" | Extra: {extrainfo}"

                            findings.append({
                                "id": finding_id,
                                "title": title,
                                "severity": severity,
                                "host": host_addr,
                                "port": int(port_id) if port_id else 0,
                                "description": description,
                                "raw_output": self.raw_output[:1000],
                                "tool_name": "nmap",
                                "vuln_type": "port_scan",
                                "endpoint": f"{port_str}/{protocol}",
                                "param": port_str,
                                "method": (protocol or "tcp").upper(),
                                "evidence": f"Port {port_str}/{protocol} open ({service_name})",
                            })

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        except Exception as e:
            logger.error(f"Nmap parse error: {e}")

        return {"tool_name": "nmap", "findings": findings}

    def _is_ipv6(self, host: str) -> bool:
        if not host:
            return False
        clean = host.strip("[]").split("%")[0]
        try:
            return isinstance(ipaddress.ip_address(clean), ipaddress.IPv6Address)
        except ValueError:
            return ":" in clean

    def _build_command(self) -> List[str]:
        """Nmap command line. Scans only the target's port unless a full scan is opted into."""
        host = self._extract_host(self.target or "")
        cmd = [config.NMAP_PATH, "-sV", "-oX", "-", "-T4"]
        if self._is_ipv6(host):
            cmd.append("-6")
        if not getattr(config, "NMAP_FULL_SCAN", False):
            cmd += ["-p", str(self._extract_port(self.target or ""))]
        cmd += ["--", host]
        return cmd

    def _parsed_target(self, target: str):
        target = (target or "").strip()
        if not target:
            return urlsplit("")
        if not re.match(r"^[a-z][a-z0-9+.-]*://", target, re.IGNORECASE):
            try:
                if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address):
                    target = f"http://[{target}]"
                else:
                    target = f"http://{target}"
            except ValueError:
                target = f"http://{target}"
        return urlsplit(target)

    def _extract_host(self, target: str) -> str:
        return self._parsed_target(target).hostname or ""

    def _extract_port(self, target: str) -> int:
        parsed = self._parsed_target(target)
        try:
            port = parsed.port
        except ValueError:
            port = None
        return port or (443 if parsed.scheme.lower() == "https" else 80)

    def _assess_severity(self, service: str, port: str) -> str:
        service = service.lower()
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            return "Info"
        
        high_risk_services = ["ssh", "ftp", "telnet", "smb", "mysql", "postgresql", 
                              "oracle", "mssql", "redis", "mongodb"]
        high_risk_ports = [21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 27017]
        
        if service in high_risk_services or port_num in high_risk_ports:
            return "Medium"
        
        if port_num < 1024:
            return "Low"
        return "Info"

    def _get_tool_name(self) -> str:
        return config.NMAP_PATH

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "nmap",
            "findings": [
                {
                    "id": "NMAP-80",
                    "title": "Open Port 80/tcp - http",
                    "severity": "Low",
                    "host": self._extract_host(self.target),
                    "port": 80,
                    "description": "Service: http (Apache httpd 2.4.41)",
                    "raw_output": "Mock Nmap XML output - port 80 open",
                    "tool_name": "nmap",
                    "vuln_type": "port_scan",
                    "endpoint": "80/tcp",
                    "param": "80",
                    "method": "TCP",
                    "evidence": "Port 80/tcp open - http",
                },
                {
                    "id": "NMAP-443",
                    "title": "Open Port 443/tcp - https",
                    "severity": "Low",
                    "host": self._extract_host(self.target),
                    "port": 443,
                    "description": "Service: https (Apache httpd 2.4.41)",
                    "raw_output": "Mock Nmap XML output - port 443 open",
                    "tool_name": "nmap",
                    "vuln_type": "port_scan",
                    "endpoint": "443/tcp",
                    "param": "443",
                    "method": "TCP",
                    "evidence": "Port 443/tcp open - https",
                },
                {
                    "id": "NMAP-22",
                    "title": "Open Port 22/tcp - ssh",
                    "severity": "Medium",
                    "host": self._extract_host(self.target),
                    "port": 22,
                    "description": "Service: ssh (OpenSSH 8.2)",
                    "raw_output": "Mock Nmap XML output - port 22 open",
                    "tool_name": "nmap",
                    "vuln_type": "port_scan",
                    "endpoint": "22/tcp",
                    "param": "22",
                    "method": "TCP",
                    "evidence": "Port 22/tcp open - ssh",
                }
            ]
        }
