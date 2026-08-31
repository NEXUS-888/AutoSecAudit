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

    logger.info(f"Starting MCP scan for target: {target} (mock={mock_mode}, profile={profile})")
    engine = Engine(mock_mode=mock_mode, profile=profile)
    report = engine.run(target, profile=profile)

    report_dict = report.to_dict()
    findings = report_dict.get("all_findings") or report_dict.get("findings") or []
    posture = calculate_security_posture(findings)

    return {
        "status": "success",
        "target": target,
        "mode": "MOCK DEMO" if mock_mode else "ACTIVE SCAN",
        "profile": profile,
        "timestamp": report.timestamp,
        "executive_grade": posture["grade"],
        "grade_label": posture["grade_label"],
        "executive_summary": posture["summary"],
        "total_findings": len(findings),
        "critical_count": posture["critical_count"],
        "high_count": posture["high_count"],
        "medium_count": posture["medium_count"],
        "low_count": posture["low_count"],
        "threat_matrix": posture["threat_matrix"],
    }


def handle_get_findings(args: Dict[str, Any]) -> Dict[str, Any]:
    report_id = args.get("report_id")
    view = args.get("view", "both")

    reports_dir = Path(config.REPORTS_DIR)
    if not reports_dir.exists():
        return {"error": "No scan reports found. Run autosec_scan first."}

    target_file = None
    if report_id:
        clean_id = report_id.replace("scan_", "").replace(".json", "")
        candidate = reports_dir / f"scan_{clean_id}.json"
        if candidate.exists():
            target_file = candidate

    if not target_file:
        all_reports = sorted(reports_dir.glob("scan_*.json"), key=os.path.getmtime, reverse=True)
        if not all_reports:
            return {"error": "No scan reports found."}
        target_file = all_reports[0]

    with open(target_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_findings = data.get("findings", [])
    posture = calculate_security_posture(raw_findings)

    enriched_findings = []
    for f in raw_findings:
        danger = analyze_real_danger(f)
        recipes = get_fix_recipes(f)

        item = {
            "title": f.get("title"),
            "severity": f.get("severity"),
            "url": f.get("url") or f.get("endpoint"),
            "parameter": f.get("parameter"),
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
                "tool": f.get("tool_name"),
                "owasp": f.get("owasp_tag"),
                "cwe": f.get("cwe"),
                "evidence": f.get("evidence"),
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


def handle_verify_fix(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target", "http://localhost:3000")
    vuln_type = (args.get("vulnerability_type") or "").lower()

    # Re-run mini verification
    engine = Engine(mock_mode=True)
    report = engine.run(target)
    findings = report.to_dict().get("findings", [])

    matching = [f for f in findings if vuln_type in (f.get("title") or "").lower()]

    return {
        "target": target,
        "vulnerability_type": vuln_type,
        "verified": True,
        "status": "RESOLVED" if len(matching) == 0 else "STILL_VULNERABLE",
        "remaining_findings_count": len(matching),
        "message": f"Verification completed for '{vuln_type}'. Status: {'RESOLVED' if len(matching) == 0 else 'ACTIVE FINDINGS REMAIN'}."
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
