"""
GraphQL Security Scanner Plugin for AutoSecAudit.

Tests for GraphQL vulnerabilities:
1. Endpoint discovery across common paths (/graphql, /api/graphql, /graphiql, /query, /v1/graphql)
   and any crawler-discovered endpoints containing "graphql".
2. Introspection check:
   - If disabled: reports a single informational finding ("GraphQL endpoint found") and stops.
   - If enabled: reports "GraphQL Introspection Enabled", extracts query-type fields taking
     String or ID arguments, and probes each argument for SQLi and XSS vulnerabilities.
3. Injection probing:
   - SQLi: benign error signatures and status-differential checks.
   - XSS: unescaped reflection check.
   - Baseline-comparison verification.
4. Strict safety constraints:
   - ONLY query operations are ever sent (NEVER mutation or subscription).
   - Requests go to target origin only.
   - Caps: maximum of 20 arguments across the schema, and at most 6 payloads per argument.
   - No depth, alias, or batching abuse requests.
"""

import logging
import json
import re
import difflib
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Callable
import requests

from plugins.base_plugin import BaseScanner
from plugins import sqli_plugin
from plugins import xss_plugin
from core.utils import format_severity

logger = logging.getLogger(__name__)

GRAPHQL_NAME_REGEX = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")

GRAPHQL_DISCOVERY_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/query",
    "/v1/graphql",
]

# Standard read-only introspection query requesting queryType fields and argument types
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType {
      name
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}
""".strip()

# Benign payloads (at most 6 payloads per argument: 3 SQLi + 3 XSS = 6 payloads)
SQLI_PAYLOADS = [
    "'",
    "' OR 1=1--",
    "1' AND '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
]


class GraphQLScanner(BaseScanner):
    """GraphQL vulnerability scanner plugin."""

    def __init__(self, mock_mode: Optional[bool] = None):
        super().__init__(mock_mode=mock_mode)
        self.results: List[Dict[str, Any]] = []
        self.discovered_endpoints: List[Any] = []

    def _get_tool_name(self) -> str:
        return "python-requests"

    def configure(self, target: str) -> None:
        super().configure(target)

    def parse_output(self) -> Dict[str, Any]:
        """Convert results to standardized findings."""
        return {
            "tool_name": "GraphQLScanner",
            "findings": self.results,
            "raw_output": json.dumps(self.results, indent=2),
            "status": "completed",
        }

    def _get_mock_output(self) -> Dict[str, Any]:
        _, host, port = self._parse_target(self.target or "http://127.0.0.1")
        mock_findings = [
            {
                "id": "GQL-001",
                "title": "GraphQL Introspection Enabled (/graphql)",
                "severity": "Medium",
                "host": host,
                "port": port,
                "description": (
                    "The GraphQL endpoint at /graphql responds to introspection queries, "
                    "revealing the full schema including types, queries, and mutations."
                ),
                "raw_output": '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                "evidence": "POST /graphql with IntrospectionQuery returned schema",
                "cwe_id": "CWE-200",
                "owasp_tag": "A01:2021 Broken Access Control",
                "vuln_type": "graphql_introspection",
                "endpoint": "/graphql",
                "param": None,
                "method": "POST",
                "confidence": "high",
            },
            {
                "id": "GQL-002",
                "title": "SQL Injection in GraphQL Query (sql_query.id)",
                "severity": "Critical",
                "host": host,
                "port": port,
                "description": "GraphQL query field 'sql_query' argument 'id' is vulnerable to SQL injection.",
                "raw_output": "you have an error in your sql syntax near '' OR 1=1--'",
                "evidence": "Payload: ' OR 1=1-- -> SQL error pattern leaked in response",
                "cwe_id": "CWE-89",
                "owasp_tag": "A03:2021 Injection",
                "vuln_type": "sqli",
                "endpoint": "/graphql",
                "param": "sql_query.id",
                "method": "POST",
                "confidence": "high",
            },
            {
                "id": "GQL-003",
                "title": "Cross-Site Scripting (XSS) in GraphQL Query (xss_query.comment)",
                "severity": "High",
                "host": host,
                "port": port,
                "description": "GraphQL query field 'xss_query' argument 'comment' reflects unescaped user input.",
                "raw_output": "<div class='comment-output'><script>alert(1)</script></div>",
                "evidence": "Payload <script>alert(1)</script> reflected unescaped in response",
                "cwe_id": "CWE-79",
                "owasp_tag": "A03:2021 Injection",
                "vuln_type": "xss",
                "endpoint": "/graphql",
                "param": "xss_query.comment",
                "method": "POST",
                "confidence": "high",
            },
        ]
        return {
            "tool_name": "GraphQLScanner",
            "findings": mock_findings,
            "raw_output": json.dumps(mock_findings, indent=2),
            "status": "completed",
        }

    def _next_id(self) -> str:
        return f"GQL-{len(self.results) + 1:03d}"

    def _add_finding(
        self,
        title: str,
        severity: str,
        host: str,
        port: int,
        description: str,
        raw_output: str,
        owasp_tag: str,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        vuln_type: str = "graphql",
        endpoint: Optional[str] = None,
        param: Optional[str] = None,
        method: Optional[str] = None,
        evidence: Optional[str] = None,
        confidence: str = "high",
    ) -> None:
        finding: Dict[str, Any] = {
            "id": self._next_id(),
            "title": title,
            "severity": format_severity(severity),
            "host": host,
            "port": port,
            "description": description,
            "raw_output": (raw_output[:1000] if raw_output else ""),
            "owasp_tag": owasp_tag,
            "tool_name": "GraphQLScanner",
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "param": param,
            "method": method or "POST",
            "evidence": evidence or ((raw_output[:500] if raw_output else "")),
            "confidence": confidence,
        }
        if cwe_id:
            finding["cwe_id"] = cwe_id
        if cve_id:
            finding["cve_id"] = cve_id
        self.results.append(finding)

    def _check_status_differential(
        self,
        baseline: Dict[str, Any],
        resp_single: Optional[requests.Response],
        probe_func: Callable[[str], Optional[requests.Response]],
    ) -> bool:
        """
        Check for error status differential (reusing sqli_plugin paired verification):
        1. baseline ("safe123") -> normal response (< 500)
        2. lone quote ("'") -> 5xx (>= 500) (reused from error-signature check)
        3. doubled quote ("''") -> normal response (< 500) (single probe)
        All three must hold.
        """
        if baseline.get("status_code", 200) >= 500:
            return False
        if resp_single is None or resp_single.status_code < 500:
            return False
        resp_double = probe_func("''")
        if resp_double is None or resp_double.status_code >= 500:
            return False
        return True

    def _get_graphql_baseline(
        self, endpoint_url: str, field_name: str, arg_name: str, returns_object: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Fetch baseline responses and statistical metrics for a GraphQL query argument."""
        cache_key = f"graphql:{endpoint_url}:{field_name}:{arg_name}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        safe_val = "safe123"
        ctrl_val = "ctrl_abc"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        selection = " { __typename }" if returns_object else ""

        def _make_body(val):
            return {
                "query": f'query {{ {field_name}({arg_name}: {json.dumps(val)}){selection} }}',
                "variables": {arg_name: val},
            }

        resp1 = self._safe_request("POST", endpoint_url, json_data=_make_body(safe_val), headers=headers)
        if resp1 is None:
            return None
        resp2 = self._safe_request("POST", endpoint_url, json_data=_make_body(safe_val), headers=headers)
        resp_ctrl = self._safe_request("POST", endpoint_url, json_data=_make_body(ctrl_val), headers=headers)

        text1 = resp1.text or ""
        text2 = (resp2.text if resp2 is not None else text1) or ""
        ctrl_text = (resp_ctrl.text if resp_ctrl is not None else text1) or ""

        status1 = resp1.status_code
        status2 = resp2.status_code if resp2 is not None else status1
        ctrl_status = resp_ctrl.status_code if resp_ctrl is not None else status1

        len1 = len(text1)
        len2 = len(text2)
        ctrl_len = len(ctrl_text)

        lengths = [len1, len2]
        length_spread = abs(len1 - len2)
        variance_ratio = length_spread / max(1, min(lengths))
        sample_similarity = difflib.SequenceMatcher(None, text1[:2000], text2[:2000]).ratio()

        baseline = {
            "status_code": status1,
            "length": len1,
            "content": text1[:2000],
            "safe_value": safe_val,
            "control_value": ctrl_val,
            "control_status": ctrl_status,
            "control_length": ctrl_len,
            "control_content": ctrl_text[:2000],
            "status_codes": [status1, status2],
            "lengths": lengths,
            "length_spread": length_spread,
            "variance_ratio": variance_ratio,
            "sample_similarity": sample_similarity,
            "samples": [
                {"status_code": status1, "length": len1, "content": text1[:2000]},
                {"status_code": status2, "length": len2, "content": text2[:2000]},
            ],
            "url": endpoint_url,
            "param": f"{field_name}.{arg_name}",
            "method": "POST",
        }
        self._baseline_cache[cache_key] = baseline
        return baseline

    def run(self) -> None:
        """Execute GraphQL discovery, introspection verification, and argument probing."""
        base_url = (self.target or "").rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        parsed_target = urllib.parse.urlparse(base_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        host = parsed_target.hostname or "127.0.0.1"
        port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

        self.results = []

        # -------------------------------------------------------------
        # Phase 1: Endpoint Discovery (5 spec paths + discovered paths)
        # -------------------------------------------------------------
        discovered_paths: List[str] = []
        for ep in getattr(self, "discovered_endpoints", []) or []:
            p = ""
            if isinstance(ep, dict):
                p = ep.get("path") or ep.get("endpoint") or ep.get("url") or ""
            elif isinstance(ep, str):
                p = ep
            if p:
                parsed_p = urllib.parse.urlparse(p)
                path_only = parsed_p.path or p
                if "graphql" in path_only.lower():
                    if parsed_p.netloc and f"{parsed_p.scheme}://{parsed_p.netloc}" != target_origin:
                        continue
                    norm_path = "/" + path_only.lstrip("/")
                    if norm_path not in discovered_paths:
                        discovered_paths.append(norm_path)

        # Give discovered paths priority, followed by the 5 spec paths; never truncate discovered paths
        candidate_paths = discovered_paths + [p for p in GRAPHQL_DISCOVERY_PATHS if p not in discovered_paths]

        active_endpoint = None
        for path in candidate_paths:
            endpoint_url = urllib.parse.urljoin(target_origin, path)
            # Origin safety check
            parsed_ep = urllib.parse.urlparse(endpoint_url)
            if f"{parsed_ep.scheme}://{parsed_ep.netloc}" != target_origin:
                continue

            resp = self._safe_request(
                "POST",
                endpoint_url,
                json_data={"query": "{__typename}"},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=(3.0, 8.0),
            )
            if resp is not None and resp.status_code in (200, 400):
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        if "data" in data and isinstance(data["data"], dict) and "__typename" in data["data"]:
                            active_endpoint = path
                            break
                        elif "errors" in data and isinstance(data["errors"], list):
                            err_str = str(data["errors"]).lower()
                            if any(k in err_str for k in ("graphql", "syntax error", "cannot query", "must provide an operation", "no query string")):
                                active_endpoint = path
                                break
                except Exception:
                    pass

        if not active_endpoint:
            logger.info(f"[GraphQLScanner] No GraphQL endpoint discovered on {target_origin}")
            return

        logger.info(f"[GraphQLScanner] Discovered GraphQL endpoint at {active_endpoint}")
        endpoint_url = urllib.parse.urljoin(target_origin, active_endpoint)

        # -------------------------------------------------------------
        # Phase 2: Introspection Check
        # -------------------------------------------------------------
        intro_resp = self._safe_request(
            "POST",
            endpoint_url,
            json_data={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=(3.0, 8.0),
        )

        introspection_enabled = False
        schema_data = None
        if intro_resp is not None and intro_resp.status_code == 200:
            try:
                body = intro_resp.json()
                if isinstance(body, dict) and "data" in body and isinstance(body["data"], dict):
                    schema_data = body["data"].get("__schema")
                    if isinstance(schema_data, dict) and "queryType" in schema_data:
                        introspection_enabled = True
            except Exception:
                pass

        if not introspection_enabled:
            # Report informational finding and stop argument probing
            self._add_finding(
                title="GraphQL endpoint found",
                severity="Info",
                host=host,
                port=port,
                description=f"GraphQL endpoint discovered at {active_endpoint}. Schema introspection is disabled.",
                raw_output="GraphQL introspection disabled",
                evidence=f"Endpoint: {active_endpoint}",
                cwe_id="CWE-200",
                owasp_tag="A05:2021 Security Misconfiguration",
                vuln_type="graphql_endpoint",
                endpoint=active_endpoint,
                method="POST",
                confidence="high",
            )
            return

        # Introspection enabled: report finding
        query_type_name = schema_data.get("queryType", {}).get("name", "Query") if isinstance(schema_data, dict) else "Query"
        self._add_finding(
            title=f"GraphQL Introspection Enabled ({active_endpoint})",
            severity="Medium",
            host=host,
            port=port,
            description=(
                f"The GraphQL endpoint at {active_endpoint} responds to introspection queries, "
                "revealing the full schema. Disable introspection in production."
            ),
            raw_output=f"GraphQL introspection enabled at {active_endpoint}. Schema queryType: {query_type_name}",
            evidence=f"Introspection schema retrieved at {active_endpoint}",
            cwe_id="CWE-200",
            owasp_tag="A01:2021 Broken Access Control",
            vuln_type="graphql_introspection",
            endpoint=active_endpoint,
            param=None,
            method="POST",
            confidence="high",
        )

        # -------------------------------------------------------------
        # Phase 3: Extract Query Fields with String/ID Arguments
        # -------------------------------------------------------------
        def _field_returns_object(f: Dict[str, Any]) -> bool:
            t = f.get("type") or {}
            while t:
                kind = t.get("kind")
                if kind == "OBJECT":
                    return True
                if kind in ("NON_NULL", "LIST"):
                    t = t.get("ofType") or {}
                else:
                    break
            return False

        query_fields = schema_data.get("queryType", {}).get("fields", []) or []
        target_args: List[Tuple[str, str, bool]] = []

        for field in query_fields:
            field_name = field.get("name")
            if not field_name or field_name.startswith("__") or not GRAPHQL_NAME_REGEX.match(field_name):
                continue
            returns_obj = _field_returns_object(field)
            for arg in field.get("args", []) or []:
                arg_name = arg.get("name")
                if not arg_name or not GRAPHQL_NAME_REGEX.match(arg_name):
                    continue
                arg_type = arg.get("type", {}) or {}
                type_name = arg_type.get("name")
                if not type_name and arg_type.get("kind") == "NON_NULL":
                    type_name = arg_type.get("ofType", {}).get("name")
                if type_name in ("String", "ID"):
                    target_args.append((field_name, arg_name, returns_obj))
                    if len(target_args) >= 20:  # Cap at 20 arguments
                        break
            if len(target_args) >= 20:
                break

        # -------------------------------------------------------------
        # Phase 4: Argument Probing (SQLi and XSS, capped at 6 payloads per arg)
        # -------------------------------------------------------------
        for field_name, arg_name, returns_obj in target_args[:20]:
            baseline = self._get_graphql_baseline(endpoint_url, field_name, arg_name, returns_object=returns_obj)
            if not baseline:
                continue

            selection = " { __typename }" if returns_obj else ""

            def probe_func(val: str) -> Optional[requests.Response]:
                body = {
                    "query": f'query {{ {field_name}({arg_name}: {json.dumps(val)}){selection} }}',
                    "variables": {arg_name: val},
                }
                return self._safe_request(
                    "POST",
                    endpoint_url,
                    json_data=body,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=(3.0, 8.0),
                )

            payloads_sent = 0

            def send_payload(payload_str: str) -> Optional[requests.Response]:
                nonlocal payloads_sent
                if payloads_sent >= 6:
                    return None
                payloads_sent += 1
                return probe_func(payload_str)

            # 4a. SQLi Probing (error-based and paired differential, max 3 payloads)
            sqli_reported = False
            resp_quote = send_payload("'")
            if resp_quote is not None:
                matched_pattern = sqli_plugin.SQLiScanner._check_sql_errors(resp_quote.text)
                if matched_pattern:
                    is_verified, confidence = self._verify_against_baseline(baseline, resp_quote, payload="'")
                    if is_verified:
                        self._add_finding(
                            title=f"SQL Injection in GraphQL Query ({field_name}.{arg_name})",
                            severity="Critical",
                            host=host,
                            port=port,
                            description=f"GraphQL query field '{field_name}' argument '{arg_name}' is vulnerable to SQL injection.",
                            raw_output=resp_quote.text[:500],
                            evidence=f"Payload: ' -> SQL error pattern '{matched_pattern}' leaked in response",
                            cwe_id="CWE-89",
                            owasp_tag="A03:2021 Injection",
                            vuln_type="sqli",
                            endpoint=active_endpoint,
                            param=f"{field_name}.{arg_name}",
                            method="POST",
                            confidence=confidence,
                        )
                        sqli_reported = True

            if not sqli_reported:
                resp_tautology = send_payload("' OR 1=1--")
                if resp_tautology is not None:
                    matched_pattern = sqli_plugin.SQLiScanner._check_sql_errors(resp_tautology.text)
                    if matched_pattern:
                        is_verified, confidence = self._verify_against_baseline(baseline, resp_tautology, payload="' OR 1=1--")
                        if is_verified:
                            self._add_finding(
                                title=f"SQL Injection in GraphQL Query ({field_name}.{arg_name})",
                                severity="Critical",
                                host=host,
                                port=port,
                                description=f"GraphQL query field '{field_name}' argument '{arg_name}' is vulnerable to SQL injection.",
                                raw_output=resp_tautology.text[:500],
                                evidence=f"Payload: ' OR 1=1-- -> SQL error pattern '{matched_pattern}' leaked in response",
                                cwe_id="CWE-89",
                                owasp_tag="A03:2021 Injection",
                                vuln_type="sqli",
                                endpoint=active_endpoint,
                                param=f"{field_name}.{arg_name}",
                                method="POST",
                                confidence=confidence,
                            )
                            sqli_reported = True

            # If not reported via error signature, check paired status-differential reusing resp_quote
            if not sqli_reported:
                if self._check_status_differential(baseline, resp_quote, send_payload):
                    self._add_finding(
                        title=f"SQL Injection in GraphQL Query ({field_name}.{arg_name})",
                        severity="Critical",
                        host=host,
                        port=port,
                        description=f"GraphQL query field '{field_name}' argument '{arg_name}' is vulnerable to SQL injection (status differential).",
                        raw_output=resp_quote.text[:500] if resp_quote else "HTTP 500 on quotation probe",
                        evidence="Paired status-differential confirmed: lone quote (') triggered HTTP 5xx, while doubled quote ('') returned normal response.",
                        cwe_id="CWE-89",
                        owasp_tag="A03:2021 Injection",
                        vuln_type="sqli",
                        endpoint=active_endpoint,
                        param=f"{field_name}.{arg_name}",
                        method="POST",
                        confidence="high",
                    )
                    sqli_reported = True

            # 4b. XSS Probing (at most 3 payloads, respecting 6 payload cap)
            for xss_payload in XSS_PAYLOADS:
                if payloads_sent >= 6:
                    break
                probe_resp = send_payload(xss_payload)
                if probe_resp is None:
                    continue

                if xss_plugin.XSSScanner._payload_reflected(xss_payload, probe_resp.text):
                    if xss_payload in baseline.get("content", "") or xss_payload in baseline.get("control_content", ""):
                        continue
                    resp_ct = probe_resp.headers.get("Content-Type", "").lower()
                    is_html_ct = "text/html" in resp_ct or "application/xhtml+xml" in resp_ct
                    text_without_payload = probe_resp.text.replace(xss_payload, "")
                    is_html_context = bool(re.search(r'<[a-zA-Z\/][^>]*>', text_without_payload))
                    if is_html_ct or is_html_context:
                        is_verified, confidence = self._verify_against_baseline(baseline, probe_resp)
                        if is_verified:
                            self._add_finding(
                                title=f"Cross-Site Scripting (XSS) in GraphQL Query ({field_name}.{arg_name})",
                                severity="High",
                                host=host,
                                port=port,
                                description=f"GraphQL query field '{field_name}' argument '{arg_name}' reflects unescaped user input.",
                                raw_output=probe_resp.text[:500],
                                evidence=f"Payload {xss_payload} reflected unescaped in response",
                                cwe_id="CWE-79",
                                owasp_tag="A03:2021 Injection",
                                vuln_type="xss",
                                endpoint=active_endpoint,
                                param=f"{field_name}.{arg_name}",
                                method="POST",
                                confidence=confidence,
                            )
                            break
