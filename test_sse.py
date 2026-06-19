"""Test SSE scan progress feature."""
import sys
sys.path.insert(0, ".")

import threading
import time
import json

print("=" * 50)
print("TESTING: Feature 5 - Real-Time Scan Progress (SSE)")
print("=" * 50)

# Test 1: Import the app and routes exist
from ui.app import app, scan_jobs, _run_scan_background
assert app is not None
print("[PASS] Flask app imports correctly")

# Test 2: SSE endpoints registered
rules = [rule.rule for rule in app.url_map.iter_rules()]
assert "/scan/async" in rules, f"/scan/async not in routes: {rules}"
assert any("scan/progress" in r for r in rules), "scan/progress route missing"
assert any("scan/status" in r for r in rules), "scan/status route missing"
print("[PASS] SSE routes registered: /scan/async, /scan/progress, /scan/status")

# Test 3: Background scan worker produces progress events
import queue
scan_id = "test123"
scan_jobs[scan_id] = {
    "status": "starting",
    "target": "http://localhost:3000",
    "progress_queue": queue.Queue(),
    "report_name": None,
    "error": None,
}

# Run in background thread
t = threading.Thread(target=_run_scan_background, args=(scan_id, "http://localhost:3000"), daemon=True)
t.start()

# Collect events
events = []
q = scan_jobs[scan_id]["progress_queue"]
deadline = time.time() + 30  # 30 second timeout
while time.time() < deadline:
    try:
        event = q.get(timeout=2)
        events.append(event)
        print(f"  [{event['progress']:3d}%] {event['stage']:12s} | {event['message']}")
        if event["stage"] in ("done", "error"):
            break
    except queue.Empty:
        if scan_jobs[scan_id]["status"] in ("done", "error"):
            break

assert len(events) > 5, f"Should have many progress events, got {len(events)}"
print(f"[PASS] Background scan produced {len(events)} progress events")

# Test 4: Verify stages are correct
stages = [e["stage"] for e in events]
assert "init" in stages, "Should have init stage"
assert "scanning" in stages, "Should have scanning stage"
assert "done" in stages or "error" in stages, "Should have terminal stage"
print(f"[PASS] Progress stages: {list(dict.fromkeys(stages))}")

# Test 5: Progress goes from low to high
progresses = [e["progress"] for e in events if e["stage"] != "error"]
assert progresses[-1] == 100 or scan_jobs[scan_id]["status"] == "error"
for i in range(1, len(progresses)):
    assert progresses[i] >= progresses[i-1], \
        f"Progress should be non-decreasing: {progresses[i-1]} -> {progresses[i]}"
print(f"[PASS] Progress is non-decreasing: {progresses[0]}% -> {progresses[-1]}%")

# Test 6: Job status is done and report_name is set
job = scan_jobs[scan_id]
assert job["status"] == "done", f"Status should be done, got {job['status']}"
assert job["report_name"] is not None, "report_name should be set"
print(f"[PASS] Scan complete — report: {job['report_name']}")

# Test 7: Flask test client can hit the endpoints
with app.test_client() as client:
    # Test /scan/status endpoint
    resp = client.get(f"/scan/status/{scan_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "done"
    print(f"[PASS] /scan/status returns correct JSON")

    # Test unknown scan ID
    resp = client.get("/scan/status/nonexistent")
    assert resp.status_code == 404
    print(f"[PASS] /scan/status returns 404 for unknown scan")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
