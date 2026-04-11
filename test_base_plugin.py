"""Test Step 1: Base Plugin System"""
import sys
sys.path.insert(0, ".")

from plugins.base_plugin import BaseScanner
from typing import Dict, Any


class TestScanner(BaseScanner):
    """Test implementation of BaseScanner."""

    def configure(self, target: str) -> None:
        self.target = target
        print(f"[TestScanner] Configured with target: {target}")

    def run(self) -> None:
        print(f"[TestScanner] Running scan on {self.target}")

    def parse_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "test_scanner",
            "findings": [
                {
                    "id": "TEST-001",
                    "title": "Test Finding",
                    "severity": "Medium",
                    "host": self.target,
                    "port": 80,
                    "description": "This is a test finding",
                    "raw_output": "Mock raw output"
                }
            ]
        }

    def _get_tool_name(self) -> str:
        return "test_tool"

    def _get_mock_output(self) -> Dict[str, Any]:
        return {
            "tool_name": "test_scanner",
            "findings": [
                {
                    "id": "MOCK-001",
                    "title": "Mock Test Finding",
                    "severity": "Low",
                    "host": self.target,
                    "port": 80,
                    "description": "Mock finding for development",
                    "raw_output": "Mock mode output"
                }
            ]
        }


def test_base_scanner():
    """Test the BaseScanner abstract class."""
    scanner = TestScanner(mock_mode=True)
    
    print("\n=== Testing BaseScanner ===\n")
    
    scanner.configure("192.168.1.1")
    print(f"Target: {scanner.target}")
    print(f"Mock mode: {scanner.mock_mode}")
    
    result = scanner.get_standardized_output()
    print(f"\nStandardized output:")
    print(f"  Tool: {result['tool_name']}")
    print(f"  Findings count: {len(result['findings'])}")
    for f in result['findings']:
        print(f"    - {f['id']}: {f['title']} ({f['severity']})")
    
    print("\n=== Test PASSED ===\n")


if __name__ == "__main__":
    test_base_scanner()
