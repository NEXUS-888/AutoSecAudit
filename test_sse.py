"""Test SSE scan progress feature."""
import json
import threading
import time
import unittest

from ui.app import app, scan_jobs, scan_jobs_lock, _run_scan_background
import core.auth as auth


class TestSSEProgress(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

        auth.init_user_db()
        admin = auth.get_user_by_username("admin")
        if not admin:
            auth.create_user("admin", "Admin123456!", "admin")
            admin = auth.get_user_by_username("admin")
        self.admin_id = admin["id"]

        with self.client.session_transaction() as sess:
            sess["user_id"] = self.admin_id

        with scan_jobs_lock:
            scan_jobs.clear()

    def tearDown(self):
        with scan_jobs_lock:
            scan_jobs.clear()

    def test_routes_registered(self):
        """Test SSE routes registered in app url_map."""
        rules = [rule.rule for rule in self.app.url_map.iter_rules()]
        self.assertIn("/scan/async", rules, f"/scan/async not in routes: {rules}")
        self.assertTrue(any("scan/progress" in r for r in rules), "scan/progress route missing")
        self.assertTrue(any("scan/status" in r for r in rules), "scan/status route missing")

    def test_background_scan_worker_produces_progress_events(self):
        """Test background scan worker produces progress events with valid stages and non-decreasing progress."""
        cond = threading.Condition()
        scan_id = "test_sse_worker"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "status": "starting",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [],
                "condition": cond,
                "report_name": None,
                "error": None,
                "created_at": time.time(),
            }

        # Run background worker in demo mode
        t = threading.Thread(
            target=_run_scan_background,
            args=(scan_id, "http://localhost:3000"),
            kwargs={"is_demo": True, "profile": "full"},
            daemon=True
        )
        t.start()

        events = []
        deadline = time.time() + 30
        while time.time() < deadline:
            with cond:
                while len(events) < len(scan_jobs[scan_id]["events"]):
                    events.append(scan_jobs[scan_id]["events"][len(events)])
                if scan_jobs[scan_id]["status"] in ("done", "error"):
                    break
                cond.wait(timeout=1)

        t.join(timeout=5)
        self.assertGreater(len(events), 5, f"Should have multiple progress events, got {len(events)}")

        stages = [e["stage"] for e in events]
        self.assertIn("init", stages, "Should have init stage")
        self.assertIn("scanning", stages, "Should have scanning stage")
        self.assertTrue("done" in stages or "error" in stages, "Should have terminal stage")

        progresses = [e["progress"] for e in events if e["stage"] != "error"]
        self.assertTrue(progresses[-1] == 100 or scan_jobs[scan_id]["status"] == "error")
        for i in range(1, len(progresses)):
            self.assertGreaterEqual(
                progresses[i],
                progresses[i - 1],
                f"Progress should be non-decreasing: {progresses[i-1]} -> {progresses[i]}"
            )

        job = scan_jobs[scan_id]
        self.assertEqual(job["status"], "done")
        self.assertIsNotNone(job["report_name"])

    def test_concurrent_subscribers_both_receive_done_event(self):
        """AUD-20: Test that two concurrent subscribers to one job both receive the done event."""
        cond = threading.Condition()
        scan_id = "test_sse_tabs"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "status": "starting",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [],
                "condition": cond,
                "report_name": None,
                "error": None,
                "created_at": time.time(),
            }

        sub1 = []
        sub2 = []

        def read_stream(dest):
            client = self.app.test_client()
            with client.session_transaction() as sess:
                sess["user_id"] = self.admin_id
            resp = client.get(f"/scan/progress/{scan_id}")
            for chunk in resp.response:
                text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
                for block in text.split("\n\n"):
                    for line in block.split("\n"):
                        if line.startswith("data:"):
                            try:
                                ev = json.loads(line[5:].strip())
                                dest.append(ev)
                                if ev.get("stage") in ("done", "error"):
                                    return
                            except Exception:
                                pass

        t1 = threading.Thread(target=read_stream, args=(sub1,))
        t2 = threading.Thread(target=read_stream, args=(sub2,))
        t1.start()
        t2.start()

        time.sleep(0.1)

        with cond:
            scan_jobs[scan_id]["events"].append({"id": 1, "stage": "init", "message": "Init", "progress": 10})
            cond.notify_all()

        time.sleep(0.05)

        with cond:
            scan_jobs[scan_id]["status"] = "done"
            scan_jobs[scan_id]["events"].append({"id": 2, "stage": "done", "message": "Done", "progress": 100})
            cond.notify_all()

        t1.join(timeout=3)
        t2.join(timeout=3)

        self.assertIn("done", [e["stage"] for e in sub1], "Subscriber 1 must receive done event")
        self.assertIn("done", [e["stage"] for e in sub2], "Subscriber 2 must receive done event")

    def test_scan_status_endpoints(self):
        """Test /scan/status/<scan_id> endpoints (401 unauth, 200 auth, 404 unknown)."""
        scan_id = "test_status_ep"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "status": "done",
                "target": "http://localhost:3000",
                "events": [],
                "report_name": "rep_test_status",
                "error": None,
                "created_at": time.time(),
            }

        unauth_client = self.app.test_client()
        unauth = unauth_client.get(f"/scan/status/{scan_id}")
        self.assertEqual(unauth.status_code, 401, f"Expected 401 for unauthenticated request, got {unauth.status_code}")

        resp = self.client.get(f"/scan/status/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "done")

        resp404 = self.client.get("/scan/status/nonexistent")
        self.assertEqual(resp404.status_code, 404)


if __name__ == "__main__":
    unittest.main()
