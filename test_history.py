"""Test scan history dashboard feature."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 6 - Scan History Dashboard")
print("=" * 50)

# Test 1: Import and route exists
from ui.app import app
rules = [rule.rule for rule in app.url_map.iter_rules()]
assert "/history" in rules, f"/history route not found in {rules}"
print("[PASS] /history route registered")

# Test 2: Unauthenticated /history redirects to login; authenticated renders with data
import core.auth as auth

with app.test_client() as client:
    unauth_resp = client.get("/history")
    assert unauth_resp.status_code == 302, f"Expected 302 redirect for unauthenticated access, got {unauth_resp.status_code}"
    assert "/login" in unauth_resp.headers.get("Location", "")
    print("[PASS] Unauthenticated /history redirected to /login")

    admin = auth.get_user_by_username("admin")
    if not admin:
        auth.init_user_db()
        admin = auth.get_user_by_username("admin")
    with client.session_transaction() as sess:
        sess["user_id"] = admin["id"]

    resp = client.get("/history")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    html = resp.data.decode("utf-8")
    
    # Check key elements
    assert "Scan History" in html, "Should contain 'Scan History' title"
    assert "Total Scans" in html, "Should contain stats"
    print(f"[PASS] /history returns 200 with dashboard HTML ({len(html)} bytes)")

    # Test 3: Check that scan data appears
    assert "localhost" in html or "No scans yet" in html, "Should show either scan data or empty state"
    if "localhost" in html:
        print("[PASS] Dashboard shows scan data for localhost")
        assert "Critical" in html, "Should show severity labels"
        assert "View Report" in html, "Should have View Report links"
        print("[PASS] Dashboard has severity bars and report links")
    else:
        print("[PASS] Dashboard shows empty state (no scans found)")

# Test 4: Home page has history link
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert "/history" in html, "Home page should link to /history"
    assert "History" in html, "Home page should mention History"
    print("[PASS] Home page contains link to /history")

# Test 5: Template file exists
from pathlib import Path
template_path = Path("ui/templates/history.html")
assert template_path.exists(), f"Template not found at {template_path}"
content = template_path.read_text(encoding="utf-8")
assert "severity-bars" in content, "Template should have severity bar chart"
assert "trend-line" in content, "Template should have trend line chart"
assert "sev-dot" in content, "Template should have severity dots"
print(f"[PASS] history.html template exists ({len(content)} bytes) with charts")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
