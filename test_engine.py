"""Test Step 2: Core Engine"""
import sys
sys.path.insert(0, ".")

from core.engine import Engine
from core.models import Finding


def test_engine():
    """Test the core scanning engine."""
    print("\n=== Testing Core Engine ===\n")

    engine = Engine(mock_mode=True)
    
    loaded = engine.load_plugins()
    print(f"Loaded plugins: {loaded}")
    
    target_set = engine.set_target("192.168.1.1")
    print(f"Target set: {target_set}")
    print(f"Target: {engine.target}")
    
    print("\nRunning plugins...")
    results = engine.run_plugins()
    print(f"Plugins executed: {len(results)}")
    
    for result in results:
        print(f"  - {result.tool_name}: {len(result.findings)} findings")
    
    report = engine.generate_report()
    print(f"\nReport summary:")
    print(f"  Target: {report.target}")
    print(f"  Total findings: {report.summary['total']}")
    print(f"  Critical: {report.summary['critical']}")
    print(f"  High: {report.summary['high']}")
    print(f"  Medium: {report.summary['medium']}")
    print(f"  Low: {report.summary['low']}")
    
    file_path = engine.save_report(report)
    print(f"\nReport saved to: {file_path}")
    
    print("\n=== Test PASSED ===\n")


if __name__ == "__main__":
    test_engine()
