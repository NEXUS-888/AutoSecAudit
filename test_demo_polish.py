"""Demo-readiness polish: scan mode is recorded and shown, form fields are labelled,
and unresolvable targets get a readable error."""

import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from jinja2 import Environment, select_autoescape

from core.models import Report
from core.utils import is_target_allowed

ROOT = Path(__file__).resolve().parent


def _render_report(**overrides) -> str:
    data = Report(
        target="http://127.0.0.1:8080",
        timestamp="2026-01-01 00:00:00",
        summary={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    ).to_dict()
    data.update(overrides)
    from ui.app import _enrich_report_data
    data = _enrich_report_data(data)
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = env.from_string((ROOT / "reports" / "templates" / "report.html").read_text(encoding="utf-8"))
    return template.render(report=data, report_id="x")


class ScanModeRecorded(unittest.TestCase):
    def test_report_round_trips_scan_mode(self):
        rep = Report(target="t", timestamp="now", scan_mode="demo")
        self.assertEqual(rep.to_dict()["scan_mode"], "demo")
        self.assertEqual(Report.from_dict(rep.to_dict()).scan_mode, "demo")

    def test_engine_records_mode(self):
        src = (ROOT / "core" / "engine.py").read_text(encoding="utf-8")
        self.assertRegex(src, r'scan_mode\s*=\s*"demo" if self\.mock_mode else "real"')


class ReportBanner(unittest.TestCase):
    def test_demo_report_has_visible_banner(self):
        html = _render_report(scan_mode="demo")
        self.assertIn('data-testid="demo-banner"', html)
        self.assertRegex(html, r"(?i)simulated")

    def test_real_and_legacy_reports_have_no_banner(self):
        self.assertNotIn('data-testid="demo-banner"', _render_report(scan_mode="real"))
        self.assertNotIn('data-testid="demo-banner"', _render_report())

    def test_search_box_is_labelled(self):
        html = _render_report()
        tag = re.search(r'<input[^>]*id="findingSearch"[^>]*>', html).group(0)
        self.assertIn("aria-label=", tag)


class PdfNotice(unittest.TestCase):
    def _pdf_paragraph_texts(self, scan_mode):
        import tempfile
        import reportlab.platypus as platypus
        from reports.generator import ReportGenerator
        seen = []
        real_paragraph = platypus.Paragraph

        def spy(text, *a, **kw):
            seen.append(str(text))
            return real_paragraph(text, *a, **kw)

        data = {"target": "http://127.0.0.1:8080", "timestamp": "now", "all_findings": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "scan_mode": scan_mode}
        with tempfile.TemporaryDirectory() as tmp, patch.object(platypus, "Paragraph", spy):
            ReportGenerator().generate_pdf(data, str(Path(tmp) / "r.pdf"))
        return " ".join(seen)

    def test_demo_pdf_is_marked(self):
        self.assertIn("DEMO MODE", self._pdf_paragraph_texts("demo"))

    def test_real_pdf_is_not_marked(self):
        self.assertNotIn("DEMO MODE", self._pdf_paragraph_texts("real"))


class AuthFormsLabelled(unittest.TestCase):
    def _page(self, path):
        from ui.app import app
        with patch.dict(os.environ, {"AUTOSEC_ALLOW_REGISTRATION": "true"}):
            return app.test_client().get(path).get_data(as_text=True)

    def _assert_all_labelled(self, html):
        inputs = [m for m in re.findall(r"<input[^>]*>", html) if 'type="hidden"' not in m]
        self.assertGreaterEqual(len(inputs), 2)
        for tag in inputs:
            ident = re.search(r'\bid="([^"]+)"', tag)
            ok = "aria-label=" in tag or (ident and re.search(r'<label[^>]*\bfor="%s"' % re.escape(ident.group(1)), html))
            self.assertTrue(ok, f"unlabelled input: {tag}")

    def test_login_inputs_labelled(self):
        self._assert_all_labelled(self._page("/login"))

    def test_register_inputs_labelled(self):
        self._assert_all_labelled(self._page("/register"))


class TargetErrorMessage(unittest.TestCase):
    def test_unresolvable_host_message_is_readable(self):
        ok, reason = is_target_allowed("not a url")
        self.assertFalse(ok)
        self.assertNotIn("Errno", reason)
        self.assertNotIn("getaddrinfo", reason)
        self.assertIn("http://127.0.0.1", reason)  # shows a valid example


if __name__ == "__main__":
    unittest.main()
