"""Test web crawler feature."""
import sys
sys.path.insert(0, ".")

from core.crawler import WebCrawler, CrawlResult, DiscoveredEndpoint
from core.engine import Engine

print("=" * 50)
print("TESTING: Feature 3 - Web Crawler")
print("=" * 50)

# Test 1: Crawler produces results in mock mode
crawler = WebCrawler(mock_mode=True)
result = crawler.crawl("http://localhost:3000")
assert isinstance(result, CrawlResult), "Should return CrawlResult"
assert result.pages_visited > 0, "Should have visited pages"
assert len(result.endpoints) > 0, "Should have discovered endpoints"
assert len(result.forms) > 0, "Should have discovered forms"
print(f"[PASS] Mock crawl: {result.pages_visited} pages, {len(result.endpoints)} endpoints, {len(result.forms)} forms")

# Test 2: get_injectable_endpoints returns proper format
injectable = result.get_injectable_endpoints()
assert len(injectable) > 0, "Should have injectable endpoints"
for ep in injectable:
    assert "path" in ep, "Should have path"
    assert "param" in ep, "Should have param"
    assert "method" in ep, "Should have method"
print(f"[PASS] get_injectable_endpoints: {len(injectable)} endpoints with params")

# Print them
for ep in injectable[:5]:
    print(f"  {ep['method']} {ep['path']}?{ep['param']}")

# Test 3: get_login_endpoints detects login paths
logins = result.get_login_endpoints()
assert len(logins) > 0, "Should find login endpoints"
assert any("login" in path for path in logins), "Should contain /login"
print(f"[PASS] get_login_endpoints: {logins}")

# Test 4: Engine integrates crawler and passes endpoints to plugins
engine = Engine(mock_mode=True)
engine.load_plugins()
engine.set_target("http://localhost:3000")
engine.run_plugins()

assert engine.crawl_result is not None, "Engine should store crawl_result"
assert engine.crawl_result.pages_visited > 0, "Engine crawl should have visited pages"
print(f"[PASS] Engine ran crawler: {engine.crawl_result.pages_visited} pages discovered")

# Test 5: Plugins received discovered endpoints
report = engine.generate_report()
assert len(report.all_findings) > 0, "Should have findings"
print(f"[PASS] Scan produced {len(report.all_findings)} findings with crawler integration")

# Test 6: CrawlResult.to_dict works for JSON serialization
crawl_dict = result.to_dict()
assert "target" in crawl_dict
assert "endpoints" in crawl_dict
assert "forms" in crawl_dict
assert len(crawl_dict["endpoints"]) == len(result.endpoints)
print(f"[PASS] CrawlResult.to_dict() serializes correctly")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
