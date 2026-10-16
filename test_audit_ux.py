"""Tests for audit/ux_check.py (UX rules) and audit/ux_iterations.py (self-iteration log validator)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "audit"))

import ux_check  # noqa: E402
import ux_iterations  # noqa: E402


def snap(**over):
    base = {
        "lang": "en", "title": "Page", "viewport_meta": True, "h1": 1, "main": 1,
        "scroll_width": 375, "client_width": 375,
        "controls": [], "images": [], "dup_ids": [], "text": [],
    }
    base.update(over)
    return base


def rules(issues):
    return sorted({i["rule"] for i in issues})


def analyse(s, page="login", viewport="mobile", theme="dark"):
    return ux_check.analyse_snapshot(s, page, viewport, theme)


class PureRules(unittest.TestCase):
    def test_clean_page_has_no_issues(self):
        self.assertEqual(analyse(snap()), [])

    def test_document_level_rules(self):
        got = rules(analyse(snap(lang="", title=" ", viewport_meta=False, h1=0, main=0)))
        self.assertEqual(got, ["doc-lang", "doc-title", "doc-viewport", "landmark-main", "page-h1"])

    def test_multiple_main_or_h1_flagged(self):
        self.assertEqual(rules(analyse(snap(main=2, h1=2))), ["landmark-main", "page-h1"])

    def test_horizontal_overflow(self):
        self.assertEqual(rules(analyse(snap(scroll_width=520))), ["layout-overflow"])
        self.assertEqual(analyse(snap(scroll_width=376)), [])  # 1px tolerance

    def test_unnamed_visible_control(self):
        c = {"selector": "#a", "tag": "input", "type": "text", "visible": True, "w": 200, "h": 40,
             "inline": False, "name": ""}
        self.assertEqual(rules(analyse(snap(controls=[c]))), ["control-name"])
        self.assertEqual(analyse(snap(controls=[dict(c, name="Email")])), [])
        self.assertEqual(analyse(snap(controls=[dict(c, visible=False)])), [])

    def test_tap_target_size(self):
        c = {"selector": "#b", "tag": "button", "type": "", "visible": True, "w": 18, "h": 40,
             "inline": False, "name": "Go"}
        self.assertEqual(rules(analyse(snap(controls=[c]))), ["target-size"])
        self.assertEqual(analyse(snap(controls=[dict(c, w=24, h=24)])), [])
        self.assertEqual(analyse(snap(controls=[dict(c, inline=True)])), [])  # WCAG inline-link exception

    def test_image_alt(self):
        img = {"selector": "img.logo", "alt": None, "visible": True, "decorative": False}
        self.assertEqual(rules(analyse(snap(images=[img]))), ["image-alt"])
        self.assertEqual(analyse(snap(images=[dict(img, alt="Logo")])), [])
        self.assertEqual(analyse(snap(images=[dict(img, alt="")])), [])  # explicit decorative
        self.assertEqual(analyse(snap(images=[dict(img, decorative=True)])), [])

    def test_duplicate_ids(self):
        self.assertEqual(rules(analyse(snap(dup_ids=["x"]))), ["dup-id"])

    def test_contrast(self):
        low = {"selector": "p.hint", "fg": [150, 150, 150], "bg": [255, 255, 255], "size": 14, "weight": 400,
               "sample": "hello", "opacity": 1}
        self.assertEqual(rules(analyse(snap(text=[low]))), ["text-contrast"])
        self.assertEqual(analyse(snap(text=[dict(low, fg=[20, 20, 20])])), [])
        self.assertEqual(analyse(snap(text=[dict(low, bg=None)])), [])  # unknown background is not guessed
        # large text only needs 3:1
        self.assertEqual(analyse(snap(text=[dict(low, fg=[118, 118, 118], size=28)])), [])

    def test_contrast_ratio_known_values(self):
        self.assertAlmostEqual(ux_check.contrast_ratio((0, 0, 0), (255, 255, 255)), 21.0, places=1)
        self.assertAlmostEqual(ux_check.contrast_ratio((119, 119, 119), (255, 255, 255)), 4.48, places=1)

    def test_issue_identity_ignores_viewport_and_theme(self):
        c = {"selector": "#a", "tag": "input", "type": "text", "visible": True, "w": 200, "h": 40,
             "inline": False, "name": ""}
        a = analyse(snap(controls=[c]), viewport="mobile", theme="dark")[0]
        b = analyse(snap(controls=[c]), viewport="desktop", theme="light")[0]
        self.assertEqual(a["id"], b["id"])
        merged = ux_check.merge_issues([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(sorted(merged[0]["contexts"]), ["desktop/light", "mobile/dark"])

    def test_issue_id_ignores_position_in_list(self):
        # scan results arrive in varying order, so nth-of-type must not change an issue's identity
        a = ux_check.issue_id("text-contrast", "report", "div.card:nth-of-type(10) > span.sev")
        b = ux_check.issue_id("text-contrast", "report", "div.card:nth-of-type(16) > span.sev")
        self.assertEqual(a, b)
        self.assertNotEqual(a, ux_check.issue_id("text-contrast", "report", "div.card > span.other"))

    def test_accepted_baseline_requires_reason(self):
        c = {"selector": "#a", "tag": "input", "type": "text", "visible": True, "w": 200, "h": 40,
             "inline": False, "name": ""}
        issue = ux_check.merge_issues(analyse(snap(controls=[c])))[0]
        self.assertEqual(ux_check.filter_accepted([issue], {issue["id"]: "third-party widget"}), [])
        with self.assertRaises(ValueError):
            ux_check.filter_accepted([issue], {issue["id"]: ""})


class BrowserRules(unittest.TestCase):
    """Run the real collector in headless Chrome on small fixture pages."""

    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
            cls._pw = sync_playwright().start()
            cls._browser = cls._pw.chromium.launch(channel="chrome", headless=True)
        except Exception as exc:  # pragma: no cover - environment without Chrome
            raise unittest.SkipTest(f"headless Chrome unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def _issues(self, html, width=375):
        page = self._browser.new_page(viewport={"width": width, "height": 800})
        page.set_content(html)
        s = ux_check.collect_snapshot(page)
        page.close()
        return analyse(s)

    GOOD = ('<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width">'
            '<title>Ok</title></head><body style="background:#fff;color:#111"><main><h1>Hi</h1>'
            '<label for="e">Email</label><input id="e" style="width:200px;height:40px">'
            '<button style="min-width:44px;min-height:44px">Go</button></main></body></html>')

    def test_good_page_is_clean(self):
        self.assertEqual(self._issues(self.GOOD), [])

    def test_bad_page_reports_each_problem(self):
        bad = ('<!doctype html><html><head></head><body style="background:#fff">'
               '<input id="x" style="width:200px;height:40px"><button style="width:10px;height:10px">'
               '</button><img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">'
               '<p style="color:#aaa">faint text here</p><div style="width:900px;height:5px"></div>'
               '<span id="d"></span><span id="d"></span></body></html>')
        got = set(rules(self._issues(bad)))
        self.assertGreaterEqual(
            got,
            {"doc-lang", "doc-title", "doc-viewport", "landmark-main", "page-h1", "control-name",
             "target-size", "image-alt", "text-contrast", "layout-overflow", "dup-id"},
        )

    def test_settle_waits_for_counters_and_animations(self):
        html = ('<!doctype html><html lang="en"><head><title>t</title><style>'
                '@keyframes fade{from{opacity:0}to{opacity:1}} #a{animation:fade 1.5s forwards}'
                '@keyframes pulse{from{opacity:.4}to{opacity:1}} #b{animation:pulse .3s infinite alternate}'
                '</style></head><body><main><h1 id="a">Title</h1><p id="b">x</p><p id="n">0</p></main>'
                '<script>let i=0;const t=setInterval(()=>{document.getElementById("n").textContent=++i;'
                'if(i>=9)clearInterval(t)},100)</script></body></html>')
        page = self._browser.new_page(viewport={"width": 800, "height": 600})
        page.set_content(html)
        ux_check.settle(page)
        self.assertEqual(page.inner_text("#n"), "9")
        self.assertEqual(page.evaluate("getComputedStyle(document.getElementById('a')).opacity"), "1")
        self.assertEqual(page.evaluate("document.getAnimations().filter(a => a.playState === 'running').length"), 0)
        page.close()

    def test_gradient_background_contrast_is_not_guessed(self):
        html = self.GOOD.replace("<h1>Hi</h1>", '<h1 style="color:#999;background:linear-gradient(#000,#fff)">Hi</h1>')
        self.assertNotIn("text-contrast", rules(self._issues(html)))


class IterationLog(unittest.TestCase):
    def _log(self, tmp, n, issues, body_extra="", own="Looked at login, scanner, history and report pages."):
        text = (f"# UX iteration {n}\n\nux_check issues: {issues}\n\n"
                f"## Own visual review\n{own}\n\n## Fixed\n- thing\n\n## Remaining\n- none\n{body_extra}")
        (Path(tmp) / f"B30-ITER-{n}.md").write_text(text, encoding="utf-8")

    def test_requires_minimum_consecutive_iterations_ending_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._log(tmp, 1, 9)
            self._log(tmp, 2, 3)
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertFalse(ok)
            self.assertIn("at least 3", msg)
            self._log(tmp, 3, 0)
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertTrue(ok, msg)

    def test_last_iteration_must_report_zero_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n, issues in ((1, 5), (2, 2), (3, 1)):
                self._log(tmp, n, issues)
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertFalse(ok)
            self.assertIn("last iteration", msg)

    def test_gap_in_numbering_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._log(tmp, 1, 4)
            self._log(tmp, 3, 0)
            self._log(tmp, 4, 0)
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertFalse(ok)
            self.assertIn("consecutive", msg)

    def test_each_iteration_needs_a_visual_review_and_count_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._log(tmp, 1, 4)
            self._log(tmp, 2, 2)
            self._log(tmp, 3, 0, own="")
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertFalse(ok)
            self.assertIn("visual review", msg)
            (Path(tmp) / "B30-ITER-3.md").write_text("# UX iteration 3\n\n## Own visual review\nlooked\n", encoding="utf-8")
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertFalse(ok)
            self.assertIn("ux_check issues", msg)

    def test_issue_counts_must_not_be_identical_all_the_way(self):
        # three iterations that all say 0 means the loop never found anything to improve on this UI
        with tempfile.TemporaryDirectory() as tmp:
            for n in (1, 2, 3):
                self._log(tmp, n, 0)
            ok, msg = ux_iterations.check("30", 3, Path(tmp))
            self.assertFalse(ok)
            self.assertIn("first iteration", msg)


class FeatureContract(unittest.TestCase):
    """The checker names the controls B31 must build; BACKLOG.md must describe the same ids."""

    IDS = ("finding-triage", "compare-scans", "cancel-scan", "demo-banner")

    def test_checker_and_backlog_use_same_testids(self):
        checker = (ROOT / "audit" / "ux_check.py").read_text(encoding="utf-8")
        backlog = (ROOT / "audit" / "BACKLOG.md").read_text(encoding="utf-8")
        for ident in self.IDS:
            self.assertIn(f"data-testid={ident}", checker, ident)
        for ident in self.IDS[:3]:
            self.assertIn(f'data-testid="{ident}"', backlog, ident)
        self.assertIn("/compare/<older>/<newer>", backlog)


class TransientRetry(unittest.TestCase):
    def test_retries_network_errors_then_succeeds(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("Page.goto: net::ERR_CONNECTION_TIMED_OUT at http://127.0.0.1:1/")
            return "ok"

        self.assertEqual(ux_check.retry_transient(flaky, tries=3, pause=0), "ok")
        self.assertEqual(len(calls), 3)

    def test_gives_up_after_the_limit(self):
        def always():
            raise RuntimeError("net::ERR_CONNECTION_TIMED_OUT")

        with self.assertRaises(RuntimeError):
            ux_check.retry_transient(always, tries=2, pause=0)

    def test_transient_console_noise_is_ignored_but_real_errors_are_not(self):
        self.assertFalse(ux_check.is_real_console_error("Failed to load resource: net::ERR_CONNECTION_TIMED_OUT"))
        self.assertTrue(ux_check.is_real_console_error("Uncaught TypeError: x is not a function"))
        self.assertTrue(ux_check.is_real_console_error("HTTP 404 http://127.0.0.1:1/static/missing.js"))

    def test_real_failures_are_not_retried(self):
        calls = []

        def broken():
            calls.append(1)
            raise ValueError("selector not found")

        with self.assertRaises(ValueError):
            ux_check.retry_transient(broken, tries=3, pause=0)
        self.assertEqual(len(calls), 1)


class Protection(unittest.TestCase):
    def test_fixer_cannot_edit_the_measuring_tools(self):
        import run_loop
        for path in ("audit/ux_check.py", "audit/ux_iterations.py", "audit/baselines/ux_accepted.json",
                     "test_audit_ux.py"):
            self.assertTrue(path.startswith(run_loop.PROTECTED), path)


class CliContract(unittest.TestCase):
    def test_help_lists_documented_flags(self):
        import subprocess
        out = subprocess.run([sys.executable, str(ROOT / "audit" / "ux_check.py"), "--help"],
                             capture_output=True, text=True, cwd=ROOT).stdout
        for flag in ("--fail-on-issues", "--quick", "--no-screenshots", "--json"):
            self.assertIn(flag, out)


if __name__ == "__main__":
    unittest.main()
