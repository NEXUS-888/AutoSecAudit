import json
import os
import queue
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import config
import core.auth as auth
from ui.app import (
    app,
    scan_jobs,
    scan_jobs_lock,
    _cleanup_stale_jobs,
    _run_scan_background,
)


class TestB07ScanManagement(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

        # Authenticate admin session
        auth.init_user_db()
        admin = auth.get_user_by_username("admin")
        if not admin:
            auth.create_user("admin", "Admin123456!", "admin")
            admin = auth.get_user_by_username("admin")
        self.admin_id = admin["id"]

        auth.login_test_client(self.client, self.admin_id)

        # Clear scan_jobs between tests
        with scan_jobs_lock:
            scan_jobs.clear()

    def tearDown(self):
        self.app.config.pop("AUTOSEC_MAX_CONCURRENT_SCANS", None)
        with scan_jobs_lock:
            scan_jobs.clear()

    # -----------------------------------------------------------------------
    # AUD-19: Bounded executor (AUTOSEC_MAX_CONCURRENT_SCANS) & stuck job TTL
    # -----------------------------------------------------------------------
    def test_aud19_cap_at_1_returns_429_on_second_scan(self):
        """AUD-19: with cap at 1 and one job running, a second POST /scan/async returns 429."""
        # Set cap to 1
        self.app.config["AUTOSEC_MAX_CONCURRENT_SCANS"] = 1

        # Simulate one active job already running
        with scan_jobs_lock:
            cond = threading.Condition()
            scan_jobs["job_active_1"] = {
                "status": "running",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [],
                "condition": cond,
                "report_name": None,
                "error": None,
                "created_at": time.time(),
            }

        # Attempt to launch a second scan
        resp = self.client.post("/scan/async", data={
            "target": "http://localhost:3000",
            "mode": "demo",
            "skip_reachability": "true"
        })
        self.assertEqual(resp.status_code, 429, f"Expected 429 when max concurrent scans reached, got {resp.status_code}")

    def test_aud19_ttl_cleanup_removes_jobs_older_than_ttl(self):
        """AUD-19: TTL cleanup removes any job older than TTL."""
        now = time.time()
        with scan_jobs_lock:
            cond = threading.Condition()
            # Job older than 3600s
            scan_jobs["job_old"] = {
                "status": "done",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [],
                "condition": cond,
                "created_at": now - 4000,
            }
            # Fresh job
            scan_jobs["job_fresh"] = {
                "status": "done",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [],
                "condition": cond,
                "created_at": now - 100,
            }

        _cleanup_stale_jobs()

        with scan_jobs_lock:
            self.assertNotIn("job_old", scan_jobs, "Job older than TTL must be removed")
            self.assertIn("job_fresh", scan_jobs, "Fresh job must remain")

    def test_aud19_jobs_running_longer_than_2x_scan_timeout_marked_error(self):
        """AUD-19: Jobs running longer than 2 x SCAN_TIMEOUT are marked error."""
        now = time.time()
        scan_timeout = getattr(config, "SCAN_TIMEOUT", 300)
        stuck_duration = (2 * scan_timeout) + 10  # exceeds 2x SCAN_TIMEOUT

        with scan_jobs_lock:
            cond = threading.Condition()
            scan_jobs["job_stuck"] = {
                "status": "running",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [],
                "condition": cond,
                "error": None,
                "created_at": now - stuck_duration,
            }

        _cleanup_stale_jobs()

        with scan_jobs_lock:
            self.assertIn("job_stuck", scan_jobs)
            self.assertEqual(scan_jobs["job_stuck"]["status"], "error", "Stuck job must be transitioned to 'error'")
            self.assertIsNotNone(scan_jobs["job_stuck"]["error"], "Error field must be populated")

    def test_aud19_concurrent_barrier_atomic_reservation(self):
        """AUD-19: ≥8 concurrent POST /scan/async behind a Barrier with cap=1: exactly 1 returns 200, 7 return 429."""
        self.app.config["AUTOSEC_MAX_CONCURRENT_SCANS"] = 1

        num_threads = 8
        barrier = threading.Barrier(num_threads)
        results = []
        lock = threading.Lock()

        def mock_scan_background(*args, **kwargs):
            time.sleep(1.0)

        def worker():
            client = self.app.test_client()
            auth.login_test_client(client, self.admin_id)

            barrier.wait()
            resp = client.post("/scan/async", data={
                "target": "http://localhost:3000",
                "mode": "demo",
                "skip_reachability": "true"
            })
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        with patch("ui.app._run_scan_background", side_effect=mock_scan_background):
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

        self.assertEqual(len(results), num_threads)
        status_200 = results.count(200)
        status_429 = results.count(429)
        self.assertEqual(status_200, 1, f"Expected exactly one 200 response under cap=1, got {status_200} (results: {results})")
        self.assertEqual(status_429, num_threads - 1, f"Expected {num_threads - 1} 429 responses, got {status_429} (results: {results})")

    # -----------------------------------------------------------------------
    # AUD-20: Append-only event list & concurrent SSE subscribers
    # -----------------------------------------------------------------------
    def test_aud20_two_concurrent_subscribers_both_receive_done_event(self):
        """AUD-20: Two concurrent subscribers to one job both receive the done event."""
        cond = threading.Condition()
        scan_id = "test_sse_concurrent"
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

        sub1_events = []
        sub2_events = []

        def subscriber(dest_list):
            client = self.app.test_client()
            auth.login_test_client(client, self.admin_id)
            response = client.get(f"/scan/progress/{scan_id}")
            for line in response.response:
                text = line.decode("utf-8") if isinstance(line, bytes) else line
                for part in text.split("\n\n"):
                    part = part.strip()
                    if not part or part.startswith(":"):
                        continue
                    # Parse data line
                    for subpart in part.split("\n"):
                        if subpart.startswith("data:"):
                            try:
                                ev = json.loads(subpart[5:].strip())
                                dest_list.append(ev)
                                if ev.get("stage") in ("done", "error"):
                                    return
                            except Exception:
                                pass

        # Start two concurrent subscriber threads
        t1 = threading.Thread(target=subscriber, args=(sub1_events,))
        t2 = threading.Thread(target=subscriber, args=(sub2_events,))
        t1.start()
        t2.start()

        # Small pause so both subscribers connect and wait on condition
        time.sleep(0.1)

        # Emit events into the job
        with cond:
            job = scan_jobs[scan_id]
            job["events"].append({"id": 1, "stage": "init", "message": "Init", "progress": 10})
            cond.notify_all()

        time.sleep(0.05)

        with cond:
            job = scan_jobs[scan_id]
            job["events"].append({"id": 2, "stage": "scanning", "message": "Scanning", "progress": 50})
            cond.notify_all()

        time.sleep(0.05)

        with cond:
            job = scan_jobs[scan_id]
            job["status"] = "done"
            job["events"].append({"id": 3, "stage": "done", "message": "Finished", "progress": 100})
            cond.notify_all()

        t1.join(timeout=3)
        t2.join(timeout=3)

        self.assertFalse(t1.is_alive(), "Subscriber 1 thread should have finished")
        self.assertFalse(t2.is_alive(), "Subscriber 2 thread should have finished")

        stages1 = [e["stage"] for e in sub1_events]
        stages2 = [e["stage"] for e in sub2_events]

        self.assertIn("done", stages1, "Subscriber 1 must receive the 'done' event")
        self.assertIn("done", stages2, "Subscriber 2 must receive the 'done' event")

    def test_aud20_sse_events_carry_id_and_last_event_id_resumption(self):
        """AUD-20: Events carry id: and Last-Event-ID header resumes from cursor."""
        cond = threading.Condition()
        scan_id = "test_sse_resume"
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "status": "done",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [
                    {"id": 1, "stage": "init", "message": "Init 1", "progress": 10},
                    {"id": 2, "stage": "crawling", "message": "Crawl 2", "progress": 30},
                    {"id": 3, "stage": "done", "message": "Done 3", "progress": 100},
                ],
                "condition": cond,
                "report_name": "rep123",
                "error": None,
                "created_at": time.time(),
            }

        # Request with Last-Event-ID: 2 -> should only receive event 3
        resp = self.client.get(f"/scan/progress/{scan_id}", headers={"Last-Event-ID": "2"})
        self.assertEqual(resp.status_code, 200)

        received = []
        raw_chunks = list(resp.response)
        full_text = "".join(c.decode("utf-8") if isinstance(c, bytes) else c for c in raw_chunks)

        self.assertIn("id: 3", full_text, "Event should carry id:")
        for block in full_text.split("\n\n"):
            for line in block.split("\n"):
                if line.startswith("data:"):
                    received.append(json.loads(line[5:].strip()))

        stages = [e["stage"] for e in received]
        self.assertEqual(stages, ["done"], f"Resuming from Last-Event-ID 2 should only yield done, got {stages}")

    def test_aud20_subscriber_receives_done_when_status_already_done_before_event(self):
        """AUD-20: Test that sets a job's status='done' with only a non-terminal event in events,
        starts a subscriber, then emits done via _emit_job_event. The subscriber must receive done."""
        from ui.app import _emit_job_event

        scan_id = "test_sse_race_fix"
        cond = threading.Condition()
        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "status": "done",
                "target": "http://localhost:3000",
                "profile": "full",
                "events": [
                    {"id": 1, "stage": "init", "message": "Init message", "progress": 10}
                ],
                "condition": cond,
                "report_name": None,
                "error": None,
                "created_at": time.time(),
            }

        received_events = []

        def subscriber():
            client = self.app.test_client()
            auth.login_test_client(client, self.admin_id)
            resp = client.get(f"/scan/progress/{scan_id}")
            for line in resp.response:
                text = line.decode("utf-8") if isinstance(line, bytes) else line
                for part in text.split("\n\n"):
                    part = part.strip()
                    if not part or part.startswith(":"):
                        continue
                    for subpart in part.split("\n"):
                        if subpart.startswith("data:"):
                            try:
                                ev = json.loads(subpart[5:].strip())
                                received_events.append(ev)
                                if ev.get("stage") in ("done", "error"):
                                    return
                            except Exception:
                                pass

        t = threading.Thread(target=subscriber)
        t.start()

        # Small sleep so subscriber connects, consumes event 1, and waits on condition
        time.sleep(0.1)

        # Now emit the 'done' event via _emit_job_event
        _emit_job_event(scan_jobs[scan_id], "done", "Scan completed", progress=100, detail="rep_123")

        t.join(timeout=3)
        self.assertFalse(t.is_alive(), "Subscriber thread should have terminated after receiving done")

        stages = [e["stage"] for e in received_events]
        self.assertIn("init", stages, "Subscriber should have received init event")
        self.assertIn("done", stages, "Subscriber MUST receive the done event")

    # -----------------------------------------------------------------------
    # AUD-21: Synchronous /scan removed, no full scan runs in request thread
    # -----------------------------------------------------------------------
    def test_aud21_synchronous_scan_route_removed(self):
        """AUD-21: Synchronous /scan route is removed from url_map (no full scan in request thread)."""
        rules = [rule.rule for rule in self.app.url_map.iter_rules()]
        self.assertNotIn("/scan", rules, "Synchronous /scan route should be removed from app.url_map")

    def test_aud21_scan_form_action_points_to_async_flow(self):
        """AUD-21: Embedded template form points to /scan/async rather than synchronous /scan."""
        resp = self.client.get("/dashboard")
        html = resp.data.decode("utf-8")
        self.assertNotIn('action="/scan"', html, "Dashboard form must not post to synchronous /scan")
        self.assertIn('action="/scan/async"', html, "Dashboard form should post to /scan/async")


if __name__ == "__main__":
    unittest.main()
