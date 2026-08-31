"""
Integration tests for AutoSecAudit MCP Server (JSON-RPC 2.0 / stdio protocol).
"""

import unittest
import json
from mcp_server import process_mcp_message, TOOLS_MANIFEST


class TestMCPServer(unittest.TestCase):
    """Test suite for MCP protocol message router and tool handlers."""

    def test_mcp_initialize(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test-client", "version": "1.0"}
            }
        }
        res = process_mcp_message(req)
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], 1)
        self.assertIn("serverInfo", res["result"])
        self.assertEqual(res["result"]["serverInfo"]["name"], "autosecaudit-mcp")

    def test_mcp_tools_list(self):
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        res = process_mcp_message(req)
        self.assertIsNotNone(res)
        tools = res["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("autosec_scan", tool_names)
        self.assertIn("autosec_get_findings", tool_names)
        self.assertIn("autosec_get_fix_recipe", tool_names)
        self.assertIn("autosec_verify_fix", tool_names)

    def test_mcp_autosec_scan_tool(self):
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "autosec_scan",
                "arguments": {
                    "target": "http://localhost:3000",
                    "mock": True
                }
            }
        }
        res = process_mcp_message(req)
        self.assertIsNotNone(res)
        text_content = res["result"]["content"][0]["text"]
        data = json.loads(text_content)
        self.assertEqual(data["status"], "success")
        self.assertIn("executive_grade", data)
        self.assertIn("threat_matrix", data)

    def test_mcp_get_fix_recipe_tool(self):
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "autosec_get_fix_recipe",
                "arguments": {
                    "finding_title": "SQL Injection in User Search",
                    "framework": "nodejs"
                }
            }
        }
        res = process_mcp_message(req)
        self.assertIsNotNone(res)
        text_content = res["result"]["content"][0]["text"]
        data = json.loads(text_content)
        self.assertIn("plain_english_danger", data)
        self.assertIn("recipe", data)
        self.assertIn("markdown_dev_ticket", data)

    def test_mcp_verify_fix_tool(self):
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "autosec_verify_fix",
                "arguments": {
                    "target": "http://localhost:3000",
                    "vulnerability_type": "cors"
                }
            }
        }
        res = process_mcp_message(req)
        self.assertIsNotNone(res)
        text_content = res["result"]["content"][0]["text"]
        data = json.loads(text_content)
        self.assertTrue(data["verified"])
        self.assertIn("status", data)


if __name__ == "__main__":
    unittest.main()
