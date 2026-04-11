from plugins.base_plugin import BaseScanner
from typing import Dict, Any


class MockPlugin(BaseScanner):
    """Mock scanner plugin for testing."""

    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        pass

    def parse_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "mock_scanner",
            "findings": [
                {
                    "id": "MOCK-001",
                    "title": "Mock Security Issue",
                    "severity": "Medium",
                    "host": self.target,
                    "port": 80,
                    "description": "This is a mock finding from MockPlugin",
                    "raw_output": "Mock raw output data"
                },
                {
                    "id": "MOCK-002",
                    "title": "Mock SSL Issue",
                    "severity": "High",
                    "host": self.target,
                    "port": 443,
                    "description": "Mock SSL certificate issue",
                    "raw_output": "Mock SSL output"
                }
            ]
        }

    def _get_tool_name(self) -> str:
        return "mock_tool"

    def _get_mock_output(self) -> Dict[str, Any]:
        return self.parse_output()
