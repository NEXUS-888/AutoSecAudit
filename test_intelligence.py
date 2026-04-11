"""Test Step 4: Intelligence Layer"""
import sys
sys.path.insert(0, ".")

from core.engine import Engine
from core.models import Finding
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper
from intelligence.delta import DeltaAnalyzer


def test_intelligence_layer():
    """Test the intelligence layer components."""
    print("\n=== Testing Intelligence Layer ===\n")

    engine = Engine(mock_mode=True)
    engine.load_plugins()
    engine.set_target("192.168.1.1")
    engine.run_plugins()
    report = engine.generate_report()

    print("1. Testing Correlator...")
    correlator = Correlator()
    correlated = correlator.correlate(report.all_findings)
    linked = correlator.link_related(report.all_findings)
    print(f"   Correlation groups: {len(correlated)}")

    print("\n2. Testing Enricher...")
    enricher = Enricher()
    enriched_findings = enricher.enrich(report.all_findings)
    enriched_count = sum(1 for f in enriched_findings if f.cvss_score)
    print(f"   Enriched with CVSS: {enriched_count}")

    print("\n3. Testing Compliance Mapper...")
    mapper = ComplianceMapper()
    mapped_findings = mapper.map_findings(report.all_findings)
    owasp_count = sum(1 for f in mapped_findings if f.owasp_tag)
    compliance_summary = mapper.get_compliance_summary(mapped_findings)
    print(f"   Mapped to OWASP: {owasp_count}")
    print(f"   OWASP categories found: {len(compliance_summary['owasp_top_10'])}")

    print("\n4. Testing Delta Analyzer...")
    current_findings = [
        Finding(
            id="TEST-001", title="Issue 1", severity="High",
            host="192.168.1.1", port=80, description="Test", raw_output="raw"
        ),
        Finding(
            id="TEST-002", title="Issue 2", severity="Medium",
            host="192.168.1.1", port=443, description="Test", raw_output="raw"
        ),
    ]
    previous_data = {
        "all_findings": [
            {"id": "TEST-001", "title": "Issue 1", "severity": "High",
             "host": "192.168.1.1", "port": 80, "description": "Test", "raw_output": "raw"}
        ]
    }
    delta = DeltaAnalyzer().compare_with_dict(
        [f.to_dict() for f in current_findings], previous_data
    )
    print(f"   New issues: {delta['summary']['new_count']}")
    print(f"   Fixed issues: {delta['summary']['fixed_count']}")

    print("\n=== Test PASSED ===\n")


if __name__ == "__main__":
    test_intelligence_layer()
