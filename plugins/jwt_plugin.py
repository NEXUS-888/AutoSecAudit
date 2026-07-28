import base64
import json
import logging
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from core.utils import format_severity
from plugins.base_plugin import BaseScanner

logger = logging.getLogger(__name__)
JWT_PATTERN = re.compile(r"(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")


class JWTScanner(BaseScanner):
    """Inspect exposed JWTs for unsafe algorithm and lifecycle claims."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode)
        self.results: List[Dict[str, Any]] = []

    def configure(self, target: str) -> None:
        self.target = target
        self._tool_available = True

    def _get_tool_name(self) -> str:
        return "python-requests"

    @staticmethod
    def _decode(segment: str) -> Dict[str, Any]:
        try:
            padded = segment + "=" * (-len(segment) % 4)
            value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            return {}

    def _inspect(self, token: str, source: str) -> None:
        header, claims, _ = token.split(".")
        header_data, claims_data = self._decode(header), self._decode(claims)
        algorithm = str(header_data.get("alg", "")).lower()
        issues = []
        if algorithm == "none":
            issues.append(("JWT accepts alg=none", "Critical"))
        if "exp" not in claims_data:
            issues.append(("JWT has no expiration claim", "Medium"))
        elif isinstance(claims_data["exp"], (int, float)) and claims_data["exp"] < datetime.now(timezone.utc).timestamp():
            issues.append(("JWT is expired but still exposed", "Low"))
        for title, severity in issues:
            self.results.append({"title": title, "severity": severity, "source": source, "algorithm": algorithm,
                                 "claims": claims_data, "evidence": token[:180]})

    def run(self) -> None:
        self.results = []
        base = self.target if self.target.startswith(("http://", "https://")) else f"http://{self.target}"
        sources = [("target response", base)]
        for endpoint in self.discovered_endpoints[:10]:
            sources.append((endpoint.get("path", "/"), urllib.parse.urljoin(base.rstrip("/") + "/", endpoint.get("path", "/").lstrip("/"))))
        seen = set()
        for source, url in sources:
            try:
                response = requests.get(url, headers={"User-Agent": "AutoSecAudit/2.0"}, timeout=8, verify=False)
            except requests.RequestException as exc:
                logger.debug("JWT request failed: %s", exc)
                continue
            candidates = JWT_PATTERN.findall(" ".join([response.text, str(dict(response.headers)), str(response.cookies)]))
            for token in candidates:
                if token not in seen:
                    seen.add(token)
                    try:
                        self._inspect(token, source)
                    except ValueError:
                        continue

    def parse_output(self) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(self.target if self.target.startswith("http") else f"http://{self.target}")
        host, port = parsed.hostname or "unknown", parsed.port or (443 if parsed.scheme == "https" else 80)
        findings = [{"id": f"JWT-{i:03d}", "title": r["title"], "severity": format_severity(r["severity"]), "host": host, "port": port,
            "description": f"{r['title']} was observed in {r['source']}. Header algorithm: {r['algorithm']}.", "raw_output": r["evidence"],
            "owasp_tag": "A02:2021 Cryptographic Failures", "tool_name": "jwt_scanner", "confidence": "high" if r["severity"] == "Critical" else "medium",
            "remediation": "Use an allowlisted asymmetric algorithm, verify signatures with the expected key, require issuer/audience claims, and enforce a short expiration with refresh-token rotation."}
            for i, r in enumerate(self.results, 1)]
        return {"tool_name": "jwt_scanner", "findings": findings}

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target)
        return {"tool_name": "jwt_scanner", "findings": [{"id": "JWT-001", "title": "JWT accepts alg=none", "severity": "Critical", "host": host, "port": port,
            "description": "A session token uses the unsigned none algorithm and lacks signature protection.", "raw_output": "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
            "owasp_tag": "A02:2021 Cryptographic Failures", "tool_name": "jwt_scanner", "confidence": "high"},
            {"id": "JWT-002", "title": "JWT has no expiration claim", "severity": "Medium", "host": host, "port": port,
             "description": "A JWT was observed without an exp claim, allowing indefinite validity if accepted by the server.", "raw_output": "claims: {sub: 1}",
             "owasp_tag": "A02:2021 Cryptographic Failures", "tool_name": "jwt_scanner", "confidence": "medium"}]}

    def _parse_target(self, target: str):
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}", parsed.hostname or "unknown", parsed.port or (443 if parsed.scheme == "https" else 80)
