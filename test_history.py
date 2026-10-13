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
import os
import shutil
import tempfile
import core.auth as auth

# The history page lists the reports found in the data directory, so this test uses its own empty
# directory instead of depending on whatever other tests left behind.
_history_data_dir = tempfile.mkdtemp(prefix="history_test_")
_previous_data_dir = os.environ.get("AUTOSEC_DATA_DIR")
os.environ["AUTOSEC_DATA_DIR"] = _history_data_dir
os.makedirs(os.path.join(_history_data_dir, "reports"), exist_ok=True)
try:
    with app.test_client() as client:
        unauth_resp = client.get("/history")
        assert unauth_resp.status_code == 302, f"Expected 302 redirect for unauthenticated access, got {unauth_resp.status_code}"
        assert "/login" in unauth_resp.headers.get("Location", "")
        print("[PASS] Unauthenticated /history redirected to /login")

        admin = auth.get_user_by_username("admin")
        if not admin:
            auth.init_user_db()
            admin = auth.get_user_by_username("admin")
        auth.login_test_client(client, admin["id"])

        resp = client.get("/history")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        html = resp.data.decode("utf-8")

        # Check key elements
        assert "Scan History" in html, "Should contain 'Scan History' title"
        assert "Total Scans" in html, "Should contain stats"
        print(f"[PASS] /history returns 200 with dashboard HTML ({len(html)} bytes)")

        # Test 3a: with no reports the empty state is shown
        assert "No scans yet" in html, "An empty data directory should show the empty state"
        print("[PASS] Dashboard shows empty state (no scans found)")

        # Test 3b: after one scan the report is listed with severity labels and a link
        from core.pipeline import ScanRequest, run_scan_pipeline
        run_scan_pipeline(ScanRequest(target="http://localhost:3000", mock_mode=True, profile="full",
                                      skip_reachability=True))
        html = client.get("/history").data.decode("utf-8")
        assert "localhost" in html, "Should list the scan of localhost"
        print("[PASS] Dashboard shows scan data for localhost")
        assert "Critical" in html, "Should show severity labels"
        assert "View Report" in html, "Should have View Report links"
        print("[PASS] Dashboard has severity bars and report links")
finally:
    if _previous_data_dir is None:
        os.environ.pop("AUTOSEC_DATA_DIR", None)
    else:
        os.environ["AUTOSEC_DATA_DIR"] = _previous_data_dir
    shutil.rmtree(_history_data_dir, ignore_errors=True)

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
