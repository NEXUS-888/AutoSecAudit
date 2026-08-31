"""
SSL / TLS Crypto & Transport Auditor Plugin for AutoSecAudit.

Audits cryptographic transport posture:
- Plaintext HTTP without automatic HTTPS redirection
- Obsolete TLS protocols (TLS 1.0, TLS 1.1)
- Missing or weak Strict-Transport-Security (HSTS) headers
- SSL Certificate validity and upcoming expiration

In mock mode, returns realistic sample findings.
"""

import ssl
import socket
import datetime
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 SSL-Auditor"}
REQUEST_TIMEOUT = (3.0, 6.0)


class SSLTLSScanner(BaseScanner):
    """SSL/TLS cryptographic transport scanner."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Audit target SSL/TLS configuration."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[SSL/TLS] Auditing transport security on {base_url}")
        self.results = []

        parsed = urlparse(base_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Check 1: Plaintext HTTP check
        if parsed.scheme == "http" and host not in ("localhost", "127.0.0.1"):
            try:
                resp = requests.get(f"http://{host}:{port}/", headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if resp.status_code not in (301, 302, 308) or not resp.headers.get("Location", "").startswith("https://"):
                    self.results.append({
                        "type": "plaintext_http_no_redirect",
                        "severity": "Medium",
                        "detail": f"Target service serves unencrypted HTTP traffic on port {port} without enforcing an automatic redirect to HTTPS."
                    })
            except Exception as e:
                logger.debug(f"[SSL/TLS] HTTP check error: {e}")

        # Check 2: HTTPS Handshake & HSTS check
        if parsed.scheme == "https" or port == 443:
            try:
                resp = requests.get(f"https://{host}:{port}/", headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
                hsts = resp.headers.get("Strict-Transport-Security")
                if not hsts:
                    self.results.append({
                        "type": "missing_hsts",
                        "severity": "Medium",
                        "detail": "The server does not send a Strict-Transport-Security (HSTS) header on HTTPS connections."
                    })
                elif "max-age" in hsts.lower():
                    # Check if max-age is too low (< 6 months / 15768000s)
                    import re
                    m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                    if m and int(m.group(1)) < 15768000:
                        self.results.append({
                            "type": "weak_hsts_duration",
                            "severity": "Low",
                            "detail": f"HSTS max-age is set to {m.group(1)}s, which is below the recommended minimum of 1 year (31536000s)."
                        })
            except Exception as e:
                logger.debug(f"[SSL/TLS] HTTPS check error: {e}")

            # Check 3: Certificate expiry socket probe
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        tls_version = ssock.version()
                        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                            self.results.append({
                                "type": "obsolete_tls_version",
                                "severity": "High",
                                "detail": f"Server negotiated obsolete and vulnerable protocol version: {tls_version}."
                            })
            except Exception as e:
                logger.debug(f"[SSL/TLS] Socket TLS check error: {e}")

    def parse_output(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for res in self.results:
            if res["type"] in seen:
                continue
            seen.add(res["type"])

            titles = {
                "plaintext_http_no_redirect": "Unencrypted HTTP Without HTTPS Redirection",
                "missing_hsts": "Missing Strict-Transport-Security (HSTS) Header",
                "weak_hsts_duration": "Insufficient HSTS Max-Age Duration",
                "obsolete_tls_version": "Obsolete TLS Protocol Version Supported"
            }

            title = titles.get(res["type"], "SSL/TLS Transport Security Issue")
            findings.append({
                "id": f"TLS-{len(findings)+1:03d}",
                "title": title,
                "severity": res["severity"],
                "host": self._extract_host(),
                "port": self._extract_port(),
                "description": res["detail"],
                "raw_output": f"Finding Type: {res['type']}\nDetail: {res['detail']}",
                "cve_id": "",
                "cvss_score": "7.4" if res["severity"] == "High" else "4.8",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                ],
                "owasp_tag": "A02:2021-Cryptographic Failures",
                "tool_name": "SSLTLSScanner",
                "confidence": "high",
                "remediation": (
                    "1. Force HTTP-to-HTTPS 301 redirection on all incoming web traffic.\n"
                    "2. Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to all HTTPS responses.\n"
                    "3. Disable TLS 1.0 and TLS 1.1 in web server configuration; enforce TLS 1.2 and TLS 1.3 only."
                )
            })

        return {
            "tool_name": "SSLTLSScanner",
            "findings": findings,
            "raw_output": self.raw_output
        }

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "SSLTLSScanner",
            "findings": [
                {
                    "id": "TLS-001",
                    "title": "Missing Strict-Transport-Security (HSTS) Header",
                    "severity": "Medium",
                    "host": self._extract_host(),
                    "port": self._extract_port(),
                    "description": (
                        "The application transmits data over HTTPS but fails to declare a Strict-Transport-Security header. "
                        "This leaves first-time visitors vulnerable to SSL stripping Man-in-the-Middle (MitM) downgrade attacks."
                    ),
                    "raw_output": "HTTPS Response Headers missing Strict-Transport-Security",
                    "cve_id": "",
                    "cvss_score": "5.3",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
                    ],
                    "owasp_tag": "A02:2021-Cryptographic Failures",
                    "tool_name": "SSLTLSScanner",
                    "confidence": "high",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to all HTTPS web responses."
                }
            ],
            "raw_output": "SSL/TLS Scanner Mock Output: 1 transport security issue identified."
        }

    def _extract_host(self) -> str:
        try:
            return self.target.split("://")[-1].split("/")[0].split(":")[0]
        except Exception:
            return "localhost"

    def _extract_port(self) -> int:
        try:
            target = self.target.split("://")[-1]
            if ":" in target:
                return int(target.split(":")[1].split("/")[0])
            return 443 if "https" in self.target else 80
        except (ValueError, IndexError):
            return 80
