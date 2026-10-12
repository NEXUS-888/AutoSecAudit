#!/usr/bin/env python3
"""
AutoSecAudit MCP Server (Model Context Protocol).

Enables AI Coding Assistants (Cursor, Claude Code, VS Code, Antigravity) to:
1. Run automated DAST security scans on local development servers (e.g. http://localhost:3000).
2. Fetch vulnerabilities translated into Plain-English Real Danger Assessments.
3. Retrieve framework-specific code remediation recipes (Node.js, Python, Nginx, WAF).
4. Verify code fixes with targeted re-scans.
"""

import sys
import os
import json
import logging
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from core.models import Finding, Report
from core.engine import Engine
from intelligence.danger_engine import calculate_security_posture, analyze_real_danger
from intelligence.recipes import get_fix_recipes, generate_dev_ticket_markdown

# Configure logging to stderr so stdout is purely reserved for JSON-RPC MCP messages
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s - [AutoSec-MCP] %(levelname)s - %(message)s"
)
logger = logging.getLogger("mcp_server")


# ---------------------------------------------------------------------------
# MCP Protocol Constants & Tool Definitions
# ---------------------------------------------------------------------------
PROTOCOL_VERSION = "2024-11-05"

TOOLS_MANIFEST = [
    {
        "name": "autosec_scan",
        "description": "Trigger an automated security scan against a web application target URL (e.g., http://localhost:3000). Returns scan summary, executive threat grade, and report ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The URL or host to scan (e.g. 'http://localhost:3000' or 'http://127.0.0.1:8000')"
                },
                "mock": {
                    "type": "boolean",
                    "description": "Whether to run in demo/mock mode (fast, simulated findings) or real active network scan mode. Defaults to true.",
                    "default": True
                },
                "profile": {
                    "type": "string",
                    "enum": ["full", "owasp", "api", "recon"],
                    "description": "Scan profile: 'full' (all 19 plugins), 'owasp' (OWASP Top 10), 'api' (API & Microservices), 'recon' (Passive Recon). Defaults to 'full'.",
                    "default": "full"
                },
                "skip_reachability": {
                    "type": "boolean",
                    "description": "Whether to bypass target reachability checks. Defaults to false.",
                    "default": False
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "autosec_get_findings",
        "description": "Retrieve security findings from a recent scan report, enriched with Plain-English Danger Assessments (what is broken, what an attacker can do, business risk) and technical payloads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_id": {
                    "type": "string",
                    "description": "The report ID or timestamp (e.g. '20260831_194634'). If omitted, retrieves findings from the latest scan."
                },
                "view": {
                    "type": "string",
                    "enum": ["business", "technical", "both"],
                    "description": "Format mode: 'business' for non-technical danger lens, 'technical' for raw payloads, 'both' for complete context.",
                    "default": "both"
                }
            }
        }
    },
    {
        "name": "autosec_get_fix_recipe",
        "description": "Get copy-pasteable code patches and WAF rules to fix a specific vulnerability across Node.js/Express, Python/Flask/Django, and Nginx/WAF.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_title": {
                    "type": "string",
                    "description": "Vulnerability title or keyword (e.g. 'SQL Injection', 'CORS Wildcard', 'Directory Listing', 'Missing Security Headers')"
                },
                "framework": {
                    "type": "string",
                    "enum": ["nodejs", "python", "nginx", "waf", "all"],
                    "description": "Target technology stack. Defaults to 'all'.",
                    "default": "all"
                }
            },
            "required": ["finding_title"]
        }
    },
    {
        "name": "autosec_verify_fix",
        "description": "Re-test a target endpoint to verify if a security fix resolved the finding without running a full multi-minute audit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The target URL to verify (e.g. 'http://localhost:3000')"
                },
                "vulnerability_type": {
                    "type": "string",
                    "enum": ["sqli", "cors", "headers", "auth", "dirbrute"],
                    "description": "The vulnerability type to verify."
                },
                "mock": {
                    "type": "boolean",
                    "description": "Whether to run in mock mode. Defaults to false.",
                    "default": False
                }
            },
            "required": ["target", "vulnerability_type"]
        }
    }
]


# ---------------------------------------------------------------------------
# Tool Implementations
# ---------------------------------------------------------------------------
def handle_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target", "http://localhost:3000")
    mock_mode = args.get("mock", True)
    profile = args.get("profile", "full")
    skip_reachability = args.get("skip_reachability", False)

    from core.pipeline import run_scan_pipeline, ScanRequest

    logger.info(f"Starting MCP scan for target: {target} (mock={mock_mode}, profile={profile})")
    try:
        req = ScanRequest(
            target=target,
            mock_mode=mock_mode,
            profile=profile,
            skip_reachability=skip_reachability,
        )
        report, paths = run_scan_pipeline(req)
    except (ConnectionError, ValueError, PermissionError) as e:
        logger.error(f"Scan failed for target {target}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "target": target,
        }

    report_dict = report.to_dict()
    findings = report_dict.get("all_findings") or report_dict.get("findings") or []
    posture = calculate_security_posture(findings)

    return {
        "status": "success",
        "target": target,
        "mode": "MOCK DEMO" if mock_mode else "ACTIVE SCAN",
        "profile": profile,
        "timestamp": report.timestamp,
        "report_id": getattr(report, "report_id", None) or report_dict.get("report_id"),
        "executive_grade": posture["grade"],
        "grade_label": posture["grade_label"],
        "executive_summary": posture["summary"],
        "total_findings": len(findings),
        "critical_count": posture["critical_count"],
        "high_count": posture["high_count"],
        "medium_count": posture["medium_count"],
        "low_count": posture["low_count"],
        "threat_matrix": posture["threat_matrix"],
        "findings": findings,
    }


def handle_get_findings(args: Dict[str, Any]) -> Dict[str, Any]:
    report_id = args.get("report_id")
    view = args.get("view", "both")

    reports_dir = Path(config.REPORTS_DIR)
    if not reports_dir.exists():
        return {"error": "No scan reports found. Run autosec_scan first."}

    target_file = None
    if report_id is not None:
        if not isinstance(report_id, str) or not re.fullmatch(r"[\w-]+", report_id):
            return {"error": "Invalid report_id format."}
        clean_id = report_id.replace("scan_", "").replace(".json", "")
        candidate = reports_dir / f"scan_{clean_id}.json"
        if candidate.exists():
            target_file = candidate
        else:
            return {"error": f"Report '{report_id}' not found."}

    if not target_file:
        all_reports = sorted(reports_dir.glob("scan_*.json"), key=os.path.getmtime, reverse=True)
        if not all_reports:
            return {"error": "No scan reports found."}
        target_file = all_reports[0]

    with open(target_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_findings = data.get("all_findings") or data.get("findings") or []
    posture = calculate_security_posture(raw_findings)

    enriched_findings = []
    for f in raw_findings:
        danger = analyze_real_danger(f)
        recipes = get_fix_recipes(f)

        item = {
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "description": f.get("description"),
            "host": f.get("host"),
            "port": f.get("port"),
            "confidence": f.get("confidence", "medium"),
            "raw_output": f.get("raw_output"),
            "cwe_id": f.get("cwe_id") or f.get("cwe"),
        }

        if view in ("business", "both"):
            item["business_danger"] = {
                "category": danger["category_title"],
                "what_is_broken": danger["what_is_broken"],
                "what_attacker_can_do": danger["what_attacker_can_do"],
                "business_impact": danger["business_impact"],
                "fix_time": danger["estimated_fix_time"],
            }

        if view in ("technical", "both"):
            item["technical_details"] = {
                "id": f.get("id"),
                "tool": f.get("tool_name"),
                "owasp": f.get("owasp_tag"),
                "cwe_id": f.get("cwe_id") or f.get("cwe"),
                "confidence": f.get("confidence", "medium"),
                "description": f.get("description"),
                "raw_output": f.get("raw_output"),
                "remediation_advice": f.get("remediation"),
            }
            item["code_fix_recipes"] = recipes

        enriched_findings.append(item)

    return {
        "report_id": target_file.stem.replace("scan_", ""),
        "executive_grade": posture["grade"],
        "grade_label": posture["grade_label"],
        "executive_summary": posture["summary"],
        "threat_matrix": posture["threat_matrix"],
        "findings_count": len(enriched_findings),
        "findings": enriched_findings,
    }


def handle_get_fix_recipe(args: Dict[str, Any]) -> Dict[str, Any]:
    finding_title = args.get("finding_title", "Security Vulnerability")
    framework = args.get("framework", "all").lower()

    dummy_finding = {"title": finding_title}
    danger = analyze_real_danger(dummy_finding)
    recipes = get_fix_recipes(dummy_finding)
    dev_ticket = generate_dev_ticket_markdown(dummy_finding)

    result = {
        "finding": finding_title,
        "plain_english_danger": danger["what_attacker_can_do"],
        "business_impact": danger["business_impact"],
        "markdown_dev_ticket": dev_ticket,
    }

    if framework == "all":
        result["recipes"] = recipes
    elif framework in recipes:
        result["recipe"] = recipes[framework]
    else:
        result["recipe"] = recipes

    return result


VULN_TYPE_TO_PLUGINS: Dict[str, List[str]] = {
    "sqli": ["SQLiScanner"],
    "cors": ["CORSScanner"],
    "headers": ["MisconfigScanner", "SSLTLSScanner"],
    "auth": ["AuthScanner", "JWTScanner"],
    "dirbrute": ["DirBruteScanner"],
}

VULN_TYPE_TO_TOOLS: Dict[str, set] = {
    "sqli": {"sqliscanner", "sqli_scanner", "sqli"},
    "cors": {"corsscanner", "cors_scanner", "cors"},
    "headers": {"misconfigscanner", "misconfig_scanner", "ssltlsscanner", "ssl_tls_scanner", "headers"},
    "auth": {"authscanner", "auth_scanner", "jwtscanner", "jwt_scanner", "auth"},
    "dirbrute": {"dirbrutescanner", "dir_brute_scanner", "dirbrute", "dirbuster"},
}


def handle_verify_fix(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target", "http://localhost:3000")
    vuln_type = (args.get("vulnerability_type") or "").lower()
    mock_mode = args.get("mock", False)

    from core.utils import check_target_reachable, is_target_allowed

    # 1. Validate vulnerability_type against mapped types
    if not vuln_type or vuln_type not in VULN_TYPE_TO_PLUGINS:
        return {
            "target": target,
            "vulnerability_type": vuln_type,
            "verified": False,
            "status": "ERROR",
            "error": f"Unknown or unsupported vulnerability_type '{vuln_type}'. Allowed types: {list(VULN_TYPE_TO_PLUGINS.keys())}",
            "remaining_findings_count": 0,
            "message": f"Unsupported vulnerability_type '{vuln_type}'.",
        }

    # 2. Target scope check
    allowed, allow_msg = is_target_allowed(target)
    if not allowed:
        return {
            "target": target,
            "vulnerability_type": vuln_type,
            "verified": False,
            "status": "ERROR",
            "error": f"Target not allowed: {allow_msg}",
            "remaining_findings_count": 0,
            "message": f"Target '{target}' is not allowed for scanning.",
        }

    # 3. Target reachability check
    if not mock_mode:
        reachable, reach_msg = check_target_reachable(target)
        if not reachable:
            return {
                "target": target,
                "vulnerability_type": vuln_type,
                "verified": False,
                "status": "ERROR",
                "error": f"Target unreachable: {reach_msg}",
                "remaining_findings_count": 0,
                "message": f"Target '{target}' is offline or unreachable: {reach_msg}",
            }

    # 4. Filter plugins for vulnerability_type and execute via stable API directly
    target_plugin_classes = VULN_TYPE_TO_PLUGINS[vuln_type]
    target_tools = VULN_TYPE_TO_TOOLS.get(vuln_type, {vuln_type})

    try:
        engine = Engine(mock_mode=mock_mode)
        engine.load_plugins()
        engine.plugins = [p for p in engine.plugins if p.__class__.__name__ in target_plugin_classes]

        if not engine.set_target(target, check_reachable=(not mock_mode)):
            return {
                "target": target,
                "vulnerability_type": vuln_type,
                "verified": False,
                "status": "ERROR",
                "error": f"Failed to set target '{target}'.",
                "remaining_findings_count": 0,
                "message": f"Target '{target}' is invalid or could not be set.",
            }

        scan_results = engine.run_plugins()
        report = engine.generate_report()
    except Exception as e:
        logger.error(f"Error during verify_fix scan: {e}")
        return {
            "target": target,
            "vulnerability_type": vuln_type,
            "verified": False,
            "status": "ERROR",
            "error": str(e),
            "remaining_findings_count": 0,
            "message": f"Verification failed with error: {e}",
        }

    # 5. Check plugin execution errors
    if not scan_results or len(engine.plugins) == 0:
        return {
            "target": target,
            "vulnerability_type": vuln_type,
            "verified": False,
            "status": "ERROR",
            "error": f"No plugins executed for vulnerability type '{vuln_type}'.",
            "remaining_findings_count": 0,
            "message": f"No plugins executed for '{vuln_type}'.",
        }

    for sr in scan_results:
        if sr.status != "success":
            return {
                "target": target,
                "vulnerability_type": vuln_type,
                "verified": False,
                "status": "ERROR",
                "error": f"Plugin {sr.tool_name} returned status '{sr.status}': {sr.error}",
                "remaining_findings_count": 0,
                "message": f"Plugin execution error: {sr.error or sr.status}",
            }

    # 6. Match remaining findings by plugin/tool, not title substring
    report_dict = report.to_dict()
    all_findings = report_dict.get("all_findings") or report_dict.get("findings") or []

    matching = []
    for f in all_findings:
        tool_name = (f.get("tool_name") or "").lower().replace("-", "_")
        if any(t in tool_name for t in target_tools) or f.get("tool_name") in target_plugin_classes:
            matching.append(f)

    is_resolved = len(matching) == 0

    return {
        "target": target,
        "vulnerability_type": vuln_type,
        "verified": is_resolved,
        "status": "RESOLVED" if is_resolved else "STILL_VULNERABLE",
        "remaining_findings_count": len(matching),
        "message": f"Verification completed for '{vuln_type}'. Status: {'RESOLVED' if is_resolved else 'ACTIVE FINDINGS REMAIN'}.",
        "findings": matching,
    }


# ---------------------------------------------------------------------------
# MCP JSON-RPC Request Router
# ---------------------------------------------------------------------------
def process_mcp_message(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    msg_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": "autosecaudit-mcp",
                    "version": "2.0.0"
                }
            }
        }

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS_MANIFEST
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            if tool_name == "autosec_scan":
                content = handle_scan(arguments)
            elif tool_name == "autosec_get_findings":
                content = handle_get_findings(arguments)
            elif tool_name == "autosec_get_fix_recipe":
                content = handle_get_fix_recipe(arguments)
            elif tool_name == "autosec_verify_fix":
                content = handle_verify_fix(arguments)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}
                }

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {"type": "text", "text": json.dumps(content, indent=2)}
                    ]
                }
            }
        except Exception as ex:
            logger.exception(f"Error executing tool {tool_name}: {ex}")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": True,
                    "content": [
                        {"type": "text", "text": f"Error executing {tool_name}: {str(ex)}"}
                    ]
                }
            }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    else:
        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"}
            }
        return None


def run_stdio_server():
    """Run standard stdio MCP JSON-RPC Server loop."""
    logger.info("AutoSecAudit MCP Server started. Listening on stdio...")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = process_mcp_message(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received: {line}")
        except Exception as e:
            logger.exception(f"Unexpected error: {e}")


if __name__ == "__main__":
    run_stdio_server()
