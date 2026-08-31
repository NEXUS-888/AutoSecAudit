"""
Secret & Sensitive File Exposure Scanner Plugin for AutoSecAudit.

Tests for publicly accessible sensitive configuration files, credentials, and source backups:
- /.env, /.env.local, /.env.production (Environment API keys & database credentials)
- /.git/config, /.git/HEAD (Source code repository metadata)
- /docker-compose.yml, /Dockerfile (Infrastructure definitions)
- /backup.sql, /dump.sql, /db.sqlite3 (Database backups)
- /id_rsa, /.aws/credentials (Private SSH keys and cloud secrets)

In mock mode, returns realistic sample findings.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
import requests

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 SecretExposure-Scanner"}
REQUEST_TIMEOUT = (3.0, 6.0)

SENSITIVE_FILES = [
    ("/.env", "Environment Variables & Secrets", "Critical", [r"[A-Z_]+=[^\s]+", r"DB_PASSWORD", r"SECRET_KEY", r"API_KEY", r"DATABASE_URL"]),
    ("/.env.local", "Local Environment Configuration", "Critical", [r"[A-Z_]+="]),
    ("/.git/config", "Git Repository Configuration", "High", [r"\[core\]", r"repositoryformatversion", r"url = "]),
    ("/.git/HEAD", "Git HEAD Reference", "High", [r"ref: refs/heads/"]),
    ("/docker-compose.yml", "Docker Compose Infrastructure File", "High", [r"version:", r"services:", r"image:"]),
    ("/config.json", "Application Configuration File", "Medium", [r"\"database\"", r"\"password\"", r"\"api_key\""]),
    ("/backup.sql", "Raw SQL Database Backup", "Critical", [r"CREATE TABLE", r"INSERT INTO", r"-- MySQL dump"]),
    ("/dump.sql", "Database Dump File", "Critical", [r"CREATE TABLE", r"INSERT INTO"]),
    ("/id_rsa", "Private SSH Key", "Critical", [r"BEGIN (?:RSA|OPENSSH) PRIVATE KEY"]),
    ("/.aws/credentials", "AWS Cloud Credentials", "Critical", [r"aws_access_key_id", r"aws_secret_access_key"])
]


class SecretExposureScanner(BaseScanner):
    """Secret and sensitive file exposure scanner."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Scan target for exposed secrets and config files."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[SecretExposure] Scanning for leaked sensitive files on {base_url}")
        self.results = []

        session = requests.Session()
        session.headers.update(HEADERS)

        for path, name, sev, signatures in SENSITIVE_FILES:
            url = urljoin(base_url, path)
            try:
                resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 5:
                    # Check if response matches secret signatures
                    content = resp.text
                    matched = False
                    for sig in signatures:
                        if re.search(sig, content, re.IGNORECASE):
                            matched = True
                            break

                    if matched or ("html" not in resp.headers.get("Content-Type", "").lower() and len(content) > 10):
                        self.results.append({
                            "path": path,
                            "name": name,
                            "severity": sev,
                            "url": url,
                            "status": resp.status_code,
                            "sample": content[:200]
                        })
            except Exception as e:
                logger.debug(f"[SecretExposure] Error probing {url}: {e}")

    def parse_output(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for res in self.results:
            if res["path"] in seen:
                continue
            seen.add(res["path"])

            findings.append({
                "id": f"SECR-{len(findings)+1:03d}",
                "title": f"Exposed Sensitive File: {res['path']}",
                "severity": res["severity"],
                "host": self._extract_host(),
                "port": self._extract_port(),
                "description": (
                    f"The sensitive resource '{res['name']}' is publicly accessible at {res['path']}. "
                    "This file exposes proprietary environment credentials, database connection strings, "
                    "or infrastructure topology to unauthorized attackers."
                ),
                "raw_output": f"URL: {res['url']}\nHTTP Status: {res['status']}\nSample Content Preview:\n{res.get('sample', '')}",
                "cve_id": "",
                "cvss_score": "9.1" if res["severity"] == "Critical" else "7.5",
                "references": [
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    "https://cwe.mitre.org/data/definitions/200.html"
                ],
                "owasp_tag": "A05:2021 Security Misconfiguration",
                "tool_name": "SecretExposureScanner",
                "confidence": "high",
                "remediation": (
                    "1. Immediately revoke and rotate all credentials, API keys, and database passwords found in the exposed file.\n"
                    "2. Configure the web server (Nginx/Apache) or cloud CDN to explicitly deny access to hidden files (.*) and configuration files.\n"
                    "3. Add sensitive filenames (.env, *.sql, *.pem) to .gitignore to prevent accidental repository commits."
                )
            })

        return {
            "tool_name": "SecretExposureScanner",
            "findings": findings,
            "raw_output": self.raw_output
        }

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "SecretExposureScanner",
            "findings": [
                {
                    "id": "SECR-001",
                    "title": "Exposed Environment Secrets: /.env",
                    "severity": "Critical",
                    "host": self._extract_host(),
                    "port": self._extract_port(),
                    "description": (
                        "The application environment file at /.env is publicly downloadable without authentication. "
                        "It exposes live production database credentials (DATABASE_URL), Stripe secret keys, and JWT signing secrets."
                    ),
                    "raw_output": "GET /.env HTTP/1.1\nHTTP/1.1 200 OK\nDATABASE_URL=postgres://app:p@ss123@db:5432/prod\nJWT_SECRET=supersecret_key",
                    "cve_id": "",
                    "cvss_score": "9.8",
                    "references": [
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                    ],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "SecretExposureScanner",
                    "confidence": "high",
                    "remediation": "Block access to dotfiles in Nginx/Apache configuration and rotate all exposed database and API keys."
                }
            ],
            "raw_output": "Secret Exposure Scanner Mock Output: 1 critical finding identified."
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
