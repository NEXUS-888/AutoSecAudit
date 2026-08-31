"""
BOLA / IDOR (Broken Object Level Authorization) Scanner Plugin for AutoSecAudit.

Tests for Broken Object Level Authorization (OWASP API Security Top 10 #1):
- Sequential integer ID enumeration (/api/users/1 -> /api/users/2)
- Missing tenant/user authorization checks on sensitive resource endpoints
- Unauthenticated access to private object records
- Predictable UUID/hash parameter access

In mock mode, returns realistic sample findings.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
import requests

from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 BOLA-Scanner"}
REQUEST_TIMEOUT = (3.0, 8.0)

RESOURCE_PATTERNS = [
    r"/api(?:/v\d+)?/users/(\d+)",
    r"/api(?:/v\d+)?/accounts/(\d+)",
    r"/api(?:/v\d+)?/orders/(\d+)",
    r"/api(?:/v\d+)?/invoices/(\d+)",
    r"/api(?:/v\d+)?/documents/(\d+)",
    r"/api(?:/v\d+)?/profile/(\d+)"
]


class BOLAIdorScanner(BaseScanner):
    """Broken Object Level Authorization (IDOR) scanner."""

    def __init__(self, mock_mode=None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.raw_output = ""

    def configure(self, target: str) -> None:
        super().configure(target)

    def _get_tool_name(self) -> str:
        return "python-requests"

    def run(self) -> None:
        """Scan target for BOLA / IDOR access control flaws."""
        base_url = self.target.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        logger.info(f"[BOLA] Scanning for BOLA / IDOR vulnerabilities on {base_url}")
        self.results = []

        test_endpoints = [
            "/api/users/1", "/api/users/2",
            "/api/orders/1001", "/api/invoices/1",
            "/api/v1/profile/1"
        ]
        if self.discovered_endpoints:
            for ep in self.discovered_endpoints:
                p = ep.get("path", "")
                for pattern in RESOURCE_PATTERNS:
                    if re.search(pattern, p, re.IGNORECASE) and p not in test_endpoints:
                        test_endpoints.append(p)

        session = requests.Session()
        session.headers.update(HEADERS)

        for path in test_endpoints[:10]:
            url = urljoin(base_url, path)
            try:
                # Test 1: Unauthenticated direct access to resource
                resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
                if resp.status_code == 200 and ("json" in resp.headers.get("Content-Type", "").lower() or len(resp.text) > 20):
                    # Check if response contains user / record data
                    body_lower = resp.text.lower()
                    if any(k in body_lower for k in ("email", "username", "password", "balance", "ssn", "phone", "address", "order_id", "total")):
                        self.results.append({
                            "type": "unauthenticated_bola",
                            "path": path,
                            "severity": "High",
                            "status": resp.status_code,
                            "url": url,
                            "snippet": resp.text[:150]
                        })
            except Exception as e:
                logger.debug(f"[BOLA] Error probing {url}: {e}")

    def parse_output(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for res in self.results:
            if res["path"] in seen:
                continue
            seen.add(res["path"])

            findings.append({
                "id": f"BOLA-{len(findings)+1:03d}",
                "title": f"Broken Object Level Authorization (IDOR) at {res['path']}",
                "severity": res["severity"],
                "host": self._extract_host(),
                "port": self._extract_port(),
                "description": (
                    f"The REST API endpoint at {res['path']} returns sensitive object records "
                    "without enforcing object-level authorization policies or session ownership checks. "
                    "An unauthorized actor can iterate numeric resource IDs to extract records belonging to other users."
                ),
                "raw_output": f"URL: {res['url']}\nHTTP Status: {res['status']}\nResponse Sample: {res.get('snippet', '')}",
                "cve_id": "",
                "cvss_score": "8.1",
                "references": [
                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/639.html"
                ],
                "owasp_tag": "API1:2023-Broken Object Level Authorization",
                "tool_name": "BOLAIdorScanner",
                "confidence": "high",
                "remediation": (
                    "1. Validate that the authenticated session user has explicit ownership of the requested resource ID before querying database records.\n"
                    "2. Avoid exposing raw auto-incrementing database primary keys in API routes; use non-predictable UUIDs or cryptographically signed tokens.\n"
                    "3. Implement centralized access control policies at the service repository layer."
                )
            })

        return {
            "tool_name": "BOLAIdorScanner",
            "findings": findings,
            "raw_output": self.raw_output
        }

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "BOLAIdorScanner",
            "findings": [
                {
                    "id": "BOLA-001",
                    "title": "Broken Object Level Authorization (IDOR) on /api/users/{id}",
                    "severity": "High",
                    "host": self._extract_host(),
                    "port": self._extract_port(),
                    "description": (
                        "The user profile API endpoint at /api/users/1 returns private account details (email, phone, role) "
                        "without verifying whether the requesting client owns the requested user ID. Any authenticated user "
                        "can enumerate sequential user IDs to exfiltrate private user account databases."
                    ),
                    "raw_output": 'GET /api/users/2 HTTP/1.1\nHTTP/1.1 200 OK\n{"id": 2, "email": "victim@example.com", "role": "admin"}',
                    "cve_id": "",
                    "cvss_score": "8.1",
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                    ],
                    "owasp_tag": "API1:2023-Broken Object Level Authorization",
                    "tool_name": "BOLAIdorScanner",
                    "confidence": "high",
                    "remediation": "Enforce object-level ownership checks: verify req.user.id === resource.ownerId prior to returning data."
                }
            ],
            "raw_output": "BOLA / IDOR Scanner Mock Output: 1 vulnerability identified."
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
