"""
Tests for Batch 23: Crawler coverage (AUD-54, AUD-55, AUD-56).
"""

import os
import re
import time
import unittest
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse
import requests

from core.crawler import (
    WebCrawler,
    CrawlResult,
    DiscoveredEndpoint,
    _LinkFormParser,
    _normalize_path_template,
)
import config


class TestAUD54InlineNavigation(unittest.TestCase):
    """AUD-54: Navigation in inline event handlers, data attributes, formaction, and refresh."""

    def test_inline_event_handlers_and_html_attributes_discovered(self) -> None:
        """Fixture page using each pattern discovers every target path."""
        html_content = """
        <!doctype html>
        <html>
        <head>
            <meta http-equiv="refresh" content="0; url=/nav-meta-refresh">
        </head>
        <body>
            <!-- Inline event handlers -->
            <button onclick="window.location.href='/nav-win-loc-href'">Win Loc Href</button>
            <button onclick="location.href='/nav-loc-href'">Loc Href</button>
            <button onclick="location='/nav-loc'">Loc</button>
            <button onclick="window.location='/nav-win-loc'">Win Loc</button>
            <button onclick="location.assign('/nav-loc-assign')">Loc Assign</button>
            <button onclick="location.replace('/nav-loc-replace')">Loc Replace</button>
            <button onclick="window.open('/nav-win-open')">Win Open</button>

            <!-- Data attributes -->
            <div data-href="/nav-data-href">Data Href</div>
            <div data-url="/nav-data-url">Data URL</div>

            <!-- Formaction -->
            <form action="/normal-form" method="POST">
                <input type="text" name="user" />
                <button type="submit" formaction="/nav-formaction">Submit Formaction</button>
            </form>
        </body>
        </html>
        """

        expected_paths = {
            "/nav-meta-refresh",
            "/nav-win-loc-href",
            "/nav-loc-href",
            "/nav-loc",
            "/nav-win-loc",
            "/nav-loc-assign",
            "/nav-loc-replace",
            "/nav-win-open",
            "/nav-data-href",
            "/nav-data-url",
            "/nav-formaction",
        }

        crawler = WebCrawler(mock_mode=False, max_pages=1, max_depth=1)

        def mock_get(url, *args, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.text = html_content
            resp.history = []
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000")

        discovered_paths = {ep.path for ep in result.endpoints}
        for path in expected_paths:
            self.assertIn(
                path,
                discovered_paths,
                f"AUD-54: Expected path {path} to be discovered from inline navigation",
            )

    def test_ignored_navigation_patterns(self) -> None:
        """javascript:void(0), https://other.example/x and onclick='location.href=\"/logout\"' must not be followed."""
        html_content = """
        <!doctype html>
        <html>
        <body>
            <a href="javascript:void(0)">JS Void Anchor</a>
            <button onclick="window.location.href='javascript:void(0)'">JS Void Onclick</button>
            <div data-href="javascript:void(0)">JS Void Data</div>

            <a href="https://other.example/cross-origin-a">Cross Origin A</a>
            <button onclick="location.href='https://other.example/cross-origin-btn'">Cross Origin Onclick</button>
            <div data-url="https://other.example/cross-origin-div">Cross Origin Div</div>

            <button onclick="location.href='/logout'">Logout Onclick</button>
            <button onclick="window.location.replace('/destroy-session')">Destroy Onclick</button>
            <div data-href="/delete-item">Delete Data Href</div>
        </body>
        </html>
        """

        requested_urls = []
        crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=2)

        def mock_get(url, *args, **kwargs):
            requested_urls.append(url)
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.text = html_content if url.rstrip("/") == "http://localhost:3000" else "<html><body>Child</body></html>"
            resp.history = []
            return resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000")

        for req in requested_urls:
            self.assertNotIn("other.example", req, f"Must not request cross-origin URL: {req}")
            self.assertNotIn("javascript:", req.lower(), f"Must not request javascript: URL: {req}")
            self.assertNotIn("logout", req.lower(), f"Must not request denied URL: {req}")
            self.assertNotIn("destroy", req.lower(), f"Must not request denied URL: {req}")
            self.assertNotIn("delete", req.lower(), f"Must not request denied URL: {req}")

        discovered_paths = {ep.path for ep in result.endpoints}
        self.assertNotIn("/logout", discovered_paths)
        self.assertNotIn("/destroy-session", discovered_paths)
        self.assertNotIn("/delete-item", discovered_paths)


class TestAUD55CrawlBudgetAndTemplateCap(unittest.TestCase):
    """AUD-55: Crawl budget defaults, env overrides, template capping, and time cap."""

    def test_normalize_path_template_numeric_and_hex_ids(self) -> None:
        """_normalize_path_template normalizes numeric, UUID, and hex-id segments."""
        self.assertEqual(_normalize_path_template("/post/1"), "/post/{id}")
        self.assertEqual(_normalize_path_template("/post/40"), "/post/{id}")
        self.assertEqual(_normalize_path_template("/item/0x1a"), "/item/{id}")
        self.assertEqual(_normalize_path_template("/item/deadbeef"), "/item/{id}")
        self.assertEqual(_normalize_path_template("/item/550e8400-e29b-41d4-a716-446655440000"), "/item/{id}")
        self.assertEqual(_normalize_path_template("/intro_1"), "/intro_1")
        self.assertEqual(_normalize_path_template("/lab-1"), "/lab-1")

    def test_repeated_url_templates_capped_at_five_and_all_labs_visited(self) -> None:
        """Fixture of 30 intro pages linking to 30 distinct labs + 40 /post/<n> pages visits all 30 labs and at most 5 /post/<n>."""
        # Root links to 30 intro pages and 40 post pages
        intro_links = "".join(f'<a href="/intro_{i}">Intro {i}</a>' for i in range(30))
        post_links = "".join(f'<a href="/post/{i}">Post {i}</a>' for i in range(1, 41))
        root_html = f"<html><body>{intro_links}{post_links}</body></html>"

        visited_urls = []

        def mock_get(url, *args, **kwargs):
            visited_urls.append(url)
            parsed = urlparse(url)
            path = parsed.path
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.history = []

            if path in ("", "/"):
                resp.text = root_html
            elif path.startswith("/intro_"):
                idx = path.split("_")[1]
                resp.text = f'<html><body><a href="/lab_{idx}">Go to Lab {idx}</a></body></html>'
            elif path.startswith("/lab_"):
                idx = path.split("_")[1]
                resp.text = f'<html><body><h1>Lab {idx} Active</h1></body></html>'
            elif path.startswith("/post/"):
                resp.text = "<html><body>Post Content</body></html>"
            else:
                resp.text = "<html><body>Other</body></html>"

            return resp

        crawler = WebCrawler(mock_mode=False)  # uses default max_pages=100, max_depth=4

        with patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000")

        visited_paths = [urlparse(u).path for u in visited_urls]
        post_visited = [p for p in visited_paths if p.startswith("/post/")]
        lab_visited = [p for p in visited_paths if p.startswith("/lab_")]

        self.assertLessEqual(
            len(post_visited),
            5,
            f"AUD-55: Expected at most 5 /post/<n> pages visited, got {len(post_visited)}: {post_visited}",
        )
        self.assertEqual(
            len(set(lab_visited)),
            30,
            f"AUD-55: Expected all 30 lab pages visited, got {len(set(lab_visited))}",
        )
        for i in range(30):
            self.assertIn(f"/lab_{i}", lab_visited, f"Missing lab_{i} from visited pages")

    def test_config_defaults_and_env_bounds_validation(self) -> None:
        """CRAWL_MAX_PAGES (100, range 1-500), CRAWL_MAX_DEPTH (4, range 1-8), CRAWL_MAX_SECONDS (60, range 5-600)."""
        import importlib

        try:
            # 1. Defaults when env vars are unset
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUTOSEC_CRAWL_MAX_PAGES", None)
                os.environ.pop("AUTOSEC_CRAWL_MAX_DEPTH", None)
                os.environ.pop("AUTOSEC_CRAWL_MAX_SECONDS", None)
                importlib.reload(config)
                self.assertEqual(config.CRAWL_MAX_PAGES, 100)
                self.assertEqual(config.CRAWL_MAX_DEPTH, 4)
                self.assertEqual(config.CRAWL_MAX_SECONDS, 60)
                crawler = WebCrawler(mock_mode=False)
                self.assertEqual(crawler.max_pages, 100)
                self.assertEqual(crawler.max_depth, 4)
                self.assertEqual(crawler.max_seconds, 60)

            # 2. Valid values: AUTOSEC_CRAWL_MAX_PAGES=250, AUTOSEC_CRAWL_MAX_DEPTH=6, AUTOSEC_CRAWL_MAX_SECONDS=120
            with patch.dict(
                os.environ,
                {
                    "AUTOSEC_CRAWL_MAX_PAGES": "250",
                    "AUTOSEC_CRAWL_MAX_DEPTH": "6",
                    "AUTOSEC_CRAWL_MAX_SECONDS": "120",
                },
            ):
                importlib.reload(config)
                self.assertEqual(config.CRAWL_MAX_PAGES, 250)
                self.assertEqual(config.CRAWL_MAX_DEPTH, 6)
                self.assertEqual(config.CRAWL_MAX_SECONDS, 120)
                crawler = WebCrawler(mock_mode=False)
                self.assertEqual(crawler.max_pages, 250)
                self.assertEqual(crawler.max_depth, 6)
                self.assertEqual(crawler.max_seconds, 120)

            # 3. Out-of-range values: 501, 9, 4 and non-integer 'abc'
            for bad_p, bad_d, bad_s in [
                ("501", "9", "4"),
                ("abc", "abc", "abc"),
            ]:
                with patch.dict(
                    os.environ,
                    {
                        "AUTOSEC_CRAWL_MAX_PAGES": bad_p,
                        "AUTOSEC_CRAWL_MAX_DEPTH": bad_d,
                        "AUTOSEC_CRAWL_MAX_SECONDS": bad_s,
                    },
                ):
                    with self.assertLogs("config", level="WARNING") as cm:
                        importlib.reload(config)
                    self.assertEqual(config.CRAWL_MAX_PAGES, 100)
                    self.assertEqual(config.CRAWL_MAX_DEPTH, 4)
                    self.assertEqual(config.CRAWL_MAX_SECONDS, 60)
                    crawler = WebCrawler(mock_mode=False)
                    self.assertEqual(crawler.max_pages, 100)
                    self.assertEqual(crawler.max_depth, 4)
                    self.assertEqual(crawler.max_seconds, 60)
                    self.assertGreaterEqual(len(cm.output), 3)
        finally:
            # 4. Restore defaults
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUTOSEC_CRAWL_MAX_PAGES", None)
                os.environ.pop("AUTOSEC_CRAWL_MAX_DEPTH", None)
                os.environ.pop("AUTOSEC_CRAWL_MAX_SECONDS", None)
                importlib.reload(config)

    def test_crawl_stops_at_time_cap(self) -> None:
        """A crawl stops when max_seconds is exceeded without waiting a real 60s."""
        # Simulated clock that advances 5s per fetch
        clock_state = {"now": 100.0}

        def mock_monotonic():
            clock_state["now"] += 5.0
            return clock_state["now"]

        root_html = "".join(f'<a href="/page_{i}">Page {i}</a>' for i in range(100))

        def mock_get(url, *args, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.text = root_html
            resp.history = []
            return resp

        crawler = WebCrawler(mock_mode=False, max_pages=100, max_seconds=15)

        with patch("time.monotonic", side_effect=mock_monotonic), \
             patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000")

        self.assertLess(result.pages_visited, 10, "Crawl must stop at max_seconds deadline")


class TestAUD56CrawlerResilience(unittest.TestCase):
    """AUD-56: Start URL retry with backoff, failure reporting, redirect following, never raising."""

    def test_start_url_retries_and_succeeds_on_third_attempt(self) -> None:
        """A server failing the first 2 requests then succeeding yields start_ok True and pages_visited > 0."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        good_resp = MagicMock(spec=requests.Response)
        good_resp.status_code = 200
        good_resp.url = "http://localhost:3000/"
        good_resp.headers = {"content-type": "text/html"}
        good_resp.text = '<html><body><a href="/welcome">Welcome</a></body></html>'
        good_resp.history = []

        calls = []

        def mock_get(url, *args, **kwargs):
            calls.append(url)
            if len(calls) <= 2:
                raise requests.ConnectionError(f"Connection refused attempt {len(calls)}")
            return good_resp

        sleep_durations = []

        def mock_sleep(seconds):
            sleep_durations.append(seconds)

        with patch.object(crawler._session, "get", side_effect=mock_get), \
             patch("time.sleep", side_effect=mock_sleep):
            result = crawler.crawl("http://localhost:3000")

        self.assertTrue(result.start_ok)
        self.assertGreater(result.pages_visited, 0)
        self.assertEqual(result.fetch_failures, 2)
        self.assertEqual(sleep_durations, [1.0, 2.0])

    def test_start_url_always_fails_no_exception_raised(self) -> None:
        """A server that always fails yields start_ok False, errors non-empty, and does not raise."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        def mock_get(url, *args, **kwargs):
            raise requests.ConnectionError("Server offline")

        sleep_durations = []

        with patch.object(crawler._session, "get", side_effect=mock_get), \
             patch("time.sleep", side_effect=lambda s: sleep_durations.append(s)):
            result = crawler.crawl("http://localhost:3000")

        self.assertFalse(result.start_ok)
        self.assertGreaterEqual(len(result.errors), 1)
        self.assertEqual(result.fetch_failures, 3)
        self.assertEqual(result.pages_visited, 0)
        self.assertEqual(sleep_durations, [1.0, 2.0])

    def test_start_url_redirect_target_counts_as_page_one(self) -> None:
        """A start URL / that redirects to /posts has /posts visited and its links followed."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        hist = MagicMock(spec=requests.Response)
        hist.url = "http://localhost:3000/"
        hist.status_code = 302

        redirect_resp = MagicMock(spec=requests.Response)
        redirect_resp.status_code = 200
        redirect_resp.url = "http://localhost:3000/posts"
        redirect_resp.headers = {"content-type": "text/html"}
        redirect_resp.text = '<html><body><h1>Posts</h1><a href="/posts/1">Post 1</a></body></html>'
        redirect_resp.history = [hist]

        subpage_resp = MagicMock(spec=requests.Response)
        subpage_resp.status_code = 200
        subpage_resp.url = "http://localhost:3000/posts/1"
        subpage_resp.headers = {"content-type": "text/html"}
        subpage_resp.text = '<html><body><h1>Post 1 Content</h1></body></html>'
        subpage_resp.history = []

        def mock_get(url, *args, **kwargs):
            if "/posts/1" in url:
                return subpage_resp
            return redirect_resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000/")

        self.assertTrue(result.start_ok)
        self.assertGreaterEqual(result.pages_visited, 2)
        discovered_paths = {ep.path for ep in result.endpoints}
        self.assertIn("/posts/1", discovered_paths)

    def test_crawl_result_fields_and_to_dict(self) -> None:
        """CrawlResult has errors, fetch_failures, and start_ok, and they appear in to_dict()."""
        res = CrawlResult(
            target="http://example.com",
            pages_visited=3,
            errors=["Timeout on /api"],
            fetch_failures=1,
            start_ok=True,
        )
        d = res.to_dict()
        self.assertEqual(d["errors"], ["Timeout on /api"])
        self.assertEqual(d["fetch_failures"], 1)
        self.assertTrue(d["start_ok"])

    def test_child_page_exception_does_not_raise_and_records_error(self) -> None:
        """A linked child page raising an exception (e.g. ValueError) does not abort crawl(), increments fetch_failures, and records the child URL in errors."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        root_resp = MagicMock(spec=requests.Response)
        root_resp.status_code = 200
        root_resp.url = "http://localhost:3000/"
        root_resp.headers = {"content-type": "text/html"}
        root_resp.text = '<html><body><a href="/child-error">Child Error</a><a href="/child-ok">Child OK</a></body></html>'
        root_resp.history = []

        child_ok_resp = MagicMock(spec=requests.Response)
        child_ok_resp.status_code = 200
        child_ok_resp.url = "http://localhost:3000/child-ok"
        child_ok_resp.headers = {"content-type": "text/html"}
        child_ok_resp.text = '<html><body><h1>Child OK Content</h1></body></html>'
        child_ok_resp.history = []

        def mock_get(url, *args, **kwargs):
            if "/child-error" in url:
                raise ValueError("boom")
            if "/child-ok" in url:
                return child_ok_resp
            return root_resp

        with patch.object(crawler._session, "get", side_effect=mock_get):
            result = crawler.crawl("http://localhost:3000/")

        self.assertTrue(result.start_ok)
        self.assertGreaterEqual(result.pages_visited, 1)
        self.assertGreaterEqual(result.fetch_failures, 1)
        self.assertTrue(
            any("/child-error" in err for err in result.errors),
            f"Expected error mentioning child URL '/child-error', got: {result.errors}",
        )


if __name__ == "__main__":
    unittest.main()
