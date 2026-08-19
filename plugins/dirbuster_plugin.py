"""
Directory Bruteforcer Plugin for AutoSecAudit.

Probes a target for common hidden directories and files that shouldn't
be publicly accessible: admin panels, backups, config files, version
control artifacts, debug endpoints, etc.

In real mode, sends HEAD/GET requests against a curated wordlist.
In mock mode, returns realistic sample findings.
"""

import requests
import logging
from typing import Dict, Any, List, Optional

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wordlist — curated, high-signal paths (not thousands of random guesses)
# ---------------------------------------------------------------------------
DIRECTORY_WORDLIST: List[Dict[str, Any]] = [
    # Admin panels
    {"path": "/admin", "severity": "High", "category": "admin_panel"},
    {"path": "/admin/", "severity": "High", "category": "admin_panel"},
    {"path": "/administrator", "severity": "High", "category": "admin_panel"},
    {"path": "/wp-admin", "severity": "High", "category": "admin_panel"},
    {"path": "/manager", "severity": "High", "category": "admin_panel"},
    {"path": "/cpanel", "severity": "High", "category": "admin_panel"},
    {"path": "/dashboard", "severity": "Medium", "category": "admin_panel"},
    {"path": "/console", "severity": "High", "category": "admin_panel"},

    # Version control / source exposure
    {"path": "/.git/config", "severity": "Critical", "category": "source_exposure"},
    {"path": "/.git/HEAD", "severity": "Critical", "category": "source_exposure"},
    {"path": "/.svn/entries", "severity": "Critical", "category": "source_exposure"},
    {"path": "/.hg/", "severity": "Critical", "category": "source_exposure"},
    {"path": "/.env", "severity": "Critical", "category": "secrets"},
    {"path": "/.env.local", "severity": "Critical", "category": "secrets"},
    {"path": "/.env.production", "severity": "Critical", "category": "secrets"},

    # Config / backup files
    {"path": "/config.php", "severity": "High", "category": "config_file"},
    {"path": "/config.yml", "severity": "High", "category": "config_file"},
    {"path": "/config.json", "severity": "High", "category": "config_file"},
    {"path": "/web.config", "severity": "Medium", "category": "config_file"},
    {"path": "/wp-config.php", "severity": "Critical", "category": "config_file"},
    {"path": "/database.yml", "severity": "Critical", "category": "config_file"},
    {"path": "/backup.sql", "severity": "Critical", "category": "backup"},
    {"path": "/backup.zip", "severity": "Critical", "category": "backup"},
    {"path": "/db.sql", "severity": "Critical", "category": "backup"},
    {"path": "/dump.sql", "severity": "Critical", "category": "backup"},

    # Debug / status endpoints
    {"path": "/debug", "severity": "High", "category": "debug"},
    {"path": "/phpinfo.php", "severity": "High", "category": "debug"},
    {"path": "/info.php", "severity": "High", "category": "debug"},
    {"path": "/server-status", "severity": "Medium", "category": "debug"},
    {"path": "/server-info", "severity": "Medium", "category": "debug"},
    {"path": "/.DS_Store", "severity": "Low", "category": "info_disclosure"},
    {"path": "/crossdomain.xml", "severity": "Low", "category": "info_disclosure"},
    {"path": "/robots.txt", "severity": "Info", "category": "info_disclosure"},
    {"path": "/sitemap.xml", "severity": "Info", "category": "info_disclosure"},

    # API documentation (often accidentally exposed in prod)
    {"path": "/swagger-ui.html", "severity": "Medium", "category": "api_docs"},
    {"path": "/api-docs", "severity": "Medium", "category": "api_docs"},
    {"path": "/swagger.json", "severity": "Medium", "category": "api_docs"},
    {"path": "/openapi.json", "severity": "Medium", "category": "api_docs"},
    {"path": "/graphql", "severity": "Medium", "category": "api_docs"},
    {"path": "/graphiql", "severity": "High", "category": "api_docs"},

    # Common app frameworks
    {"path": "/actuator", "severity": "High", "category": "framework"},
    {"path": "/actuator/health", "severity": "Medium", "category": "framework"},
    {"path": "/actuator/env", "severity": "Critical", "category": "framework"},
    {"path": "/elmah.axd", "severity": "High", "category": "framework"},
    {"path": "/trace.axd", "severity": "High", "category": "framework"},
    {"path": "/__debug__/", "severity": "High", "category": "framework"},

    # Juice Shop specific
    {"path": "/ftp", "severity": "High", "category": "directory_listing"},
    {"path": "/api/Challenges", "severity": "Medium", "category": "api_docs"},
    {"path": "/api/SecurityQuestions", "severity": "Medium", "category": "api_docs"},
    {"path": "/metrics", "severity": "Medium", "category": "debug"},
]

HEADERS = {"User-Agent": "AutoSecAudit/2.0 DirBuster"}
REQUEST_TIMEOUT = (3.0, 8.0)

# Status codes that indicate "found"
FOUND_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}
# 401/403 = exists but protected (still interesting to report)


class DirBruteScanner(BaseScanner):
    """Directory bruteforce scanner — discovers hidden paths and files."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Probe each path in the wordlist against the target."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[DirBrute] Scanning {len(DIRECTORY_WORDLIST)} paths on {base_url}")
        self.results = []

        for entry in DIRECTORY_WORDLIST:
            path = entry["path"]
            url = f"{base_url}{path}"

            try:
                resp = requests.head(
                    url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                    allow_redirects=False, verify=False,
                )

                if resp.status_code in FOUND_CODES:
                    # For 200 responses, verify content isn't a generic 404 page
                    if resp.status_code == 200:
                        get_resp = requests.get(
                            url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                            allow_redirects=False, verify=False,
                        )
                        body = get_resp.text.lower()
                        # Skip generic "not found" pages disguised as 200
                        if any(marker in body for marker in [
                            "not found", "404", "page not found",
                            "does not exist", "no such file"
                        ]) and len(body) < 2000:
                            continue

                    status_label = "accessible" if resp.status_code < 400 else "protected"
                    confidence = "high" if resp.status_code == 200 else "medium"

                    self.results.append({
                        "path": path,
                        "status_code": resp.status_code,
                        "severity": entry["severity"],
                        "category": entry["category"],
                        "status_label": status_label,
                        "confidence": confidence,
                        "content_length": resp.headers.get("Content-Length", "unknown"),
                    })
                    logger.info(f"[DirBrute] Found: {path} ({resp.status_code} {status_label})")

            except requests.RequestException as exc:
                logger.debug(f"[DirBrute] {path}: {exc}")

        self.raw_output = (
            f"Tested {len(DIRECTORY_WORDLIST)} paths. "
            f"Found {len(self.results)} accessible/protected resource(s)."
        )
        logger.info(f"[DirBrute] Finished — {self.raw_output}")

    def parse_output(self) -> Dict[str, Any]:
        """Convert results to standardized findings."""
        findings: List[Dict[str, Any]] = []

        category_names = {
            "admin_panel": "Exposed Admin Panel",
            "source_exposure": "Source Code Exposure",
            "secrets": "Exposed Secrets File",
            "config_file": "Exposed Configuration File",
            "backup": "Exposed Backup File",
            "debug": "Debug Endpoint Accessible",
            "info_disclosure": "Information Disclosure",
            "api_docs": "API Documentation Exposed",
            "framework": "Framework Debug Endpoint",
            "directory_listing": "Directory Listing Enabled",
        }

        for idx, result in enumerate(self.results, start=1):
            cat = result["category"]
            title = category_names.get(cat, "Hidden Resource Found")
            status_label = result["status_label"]

            description = (
                f"{title} at {result['path']}\n"
                f"Status: HTTP {result['status_code']} ({status_label})\n"
                f"Content-Length: {result['content_length']}\n"
                f"Category: {cat}"
            )
            if status_label == "protected":
                description += "\nNote: Resource exists but is access-controlled (401/403). Still a finding as it reveals path existence."

            findings.append({
                "id": f"DIR-{idx:03d}",
                "title": f"{title}: {result['path']}",
                "severity": result["severity"],
                "host": self.target.split("://")[-1].split("/")[0].split(":")[0],
                "port": self._extract_port(),
                "description": description,
                "raw_output": f"HEAD {result['path']} → {result['status_code']}",
                "cve_id": "",
                "cvss_score": "",
                "references": self._get_references(cat),
                "owasp_tag": "A05:2021 Security Misconfiguration",
                "tool_name": "DirBrute",
                "confidence": result.get("confidence", "medium"),
                "remediation": self._get_remediation(cat),
            })

        return {
            "tool_name": "DirBrute",
            "findings": findings,
            "raw_output": self.raw_output,
        }

    def _extract_port(self) -> int:
        try:
            target = self.target.split("://")[-1]
            if ":" in target:
                return int(target.split(":")[1].split("/")[0])
            return 443 if "https" in self.target else 80
        except (ValueError, IndexError):
            return 80

    @staticmethod
    def _get_references(category: str) -> list:
        refs = {
            "source_exposure": [
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "https://blog.pentesterlab.com/from-git-to-rce-2b6c15c35d3e",
            ],
            "secrets": [
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ],
            "admin_panel": [
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ],
            "backup": [
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ],
            "debug": [
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ],
        }
        return refs.get(category, ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"])

    @staticmethod
    def _get_remediation(category: str) -> str:
        remediations = {
            "source_exposure": "Remove .git/.svn/.hg directories from production. Add to .gitignore and block in web server config:\n  location ~ /\\.(git|svn|hg) { deny all; }",
            "secrets": "Remove .env files from web root. Use environment variables or a secrets manager (Vault, AWS SSM). Block in web server config.",
            "admin_panel": "Restrict admin panel access by IP whitelist or VPN. Use strong authentication (MFA). Rename to a non-guessable path.",
            "config_file": "Move config files outside web root. Block access in web server config. Use environment variables instead.",
            "backup": "Never store backups in web-accessible directories. Use secure backup storage (S3 with encryption, off-site).",
            "debug": "Disable debug endpoints in production. Remove phpinfo(), actuator endpoints, and debug toolbars.",
            "api_docs": "Restrict API documentation to internal networks. Disable Swagger UI in production builds.",
            "framework": "Disable framework debug/admin features in production. Remove Spring Actuator, Django Debug Toolbar, etc.",
            "directory_listing": "Disable directory listing in web server config:\n  Options -Indexes (Apache)\n  autoindex off; (Nginx)",
            "info_disclosure": "Review robots.txt and sitemap.xml for sensitive path disclosure. Limit information exposed.",
        }
        return remediations.get(category, "Restrict access to this resource. Consider blocking or removing it from production.")

    def _get_mock_output(self) -> Dict[str, Any]:
        """Return realistic mock findings."""
        self.target = self.target or "http://localhost:3000"
        host = self.target.split("://")[-1].split("/")[0].split(":")[0]
        port = self._extract_port()

        return {
            "tool_name": "DirBrute",
            "findings": [
                {
                    "id": "DIR-001",
                    "title": "Source Code Exposure: /.git/HEAD",
                    "severity": "Critical",
                    "host": host, "port": port,
                    "description": "Git repository metadata accessible at /.git/HEAD\nStatus: HTTP 200 (accessible)\nAn attacker can reconstruct the entire source code repository.",
                    "raw_output": "HEAD /.git/HEAD → 200",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "DirBrute",
                    "confidence": "high",
                    "remediation": "Remove .git directory from production. Block in web server config.",
                },
                {
                    "id": "DIR-002",
                    "title": "Exposed Admin Panel: /admin",
                    "severity": "High",
                    "host": host, "port": port,
                    "description": "Admin panel found at /admin\nStatus: HTTP 200 (accessible)\nThis may allow unauthorized administrative access.",
                    "raw_output": "HEAD /admin → 200",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "DirBrute",
                    "confidence": "high",
                    "remediation": "Restrict admin panel access by IP whitelist or VPN.",
                },
                {
                    "id": "DIR-003",
                    "title": "Directory Listing Enabled: /ftp",
                    "severity": "High",
                    "host": host, "port": port,
                    "description": "Directory listing enabled at /ftp\nStatus: HTTP 200 (accessible)\nExposes file structure and potentially sensitive files.",
                    "raw_output": "HEAD /ftp → 200",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "DirBrute",
                    "confidence": "high",
                    "remediation": "Disable directory listing: Options -Indexes (Apache), autoindex off (Nginx)",
                },
                {
                    "id": "DIR-004",
                    "title": "API Documentation Exposed: /api-docs",
                    "severity": "Medium",
                    "host": host, "port": port,
                    "description": "API documentation found at /api-docs\nStatus: HTTP 200 (accessible)\nExposes API structure to potential attackers.",
                    "raw_output": "HEAD /api-docs → 200",
                    "cve_id": "", "cvss_score": "",
                    "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                    "owasp_tag": "A05:2021 Security Misconfiguration",
                    "tool_name": "DirBrute",
                    "confidence": "high",
                    "remediation": "Restrict API docs to internal networks. Disable in production.",
                },
            ],
            "raw_output": "Tested 85 paths. Found 4 accessible resource(s).",
        }
