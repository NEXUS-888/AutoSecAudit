"""Form coverage: a vulnerable promising form past the old 8-form cap is still probed.

Found in the 2026-10-13 pygoat retest: the app exposed ~36 forms that all had promising fields,
so a real reflected-XSS form (/xssL1, field 'q') ranked below the 8-form cap and was never probed.
The cap default is now 20 (env AUTOSEC_MAX_FORMS_PER_PLUGIN), enough for realistic apps.
"""
import html
import sys
import threading
import unittest

sys.path.insert(0, ".")

from flask import Flask, Response, request
from werkzeug.serving import make_server

import config
from core.crawler import WebCrawler
from plugins.xss_plugin import XSSScanner


class TestFormCoverage(unittest.TestCase):
    def test_vulnerable_promising_form_past_the_old_cap_is_probed(self):
        # 15 POST forms, each with a promising field 'q'. All tie on priority, so only the cap decides
        # how many are probed. Only the 12th form reflects input unescaped (a real XSS); it sits past
        # the old 8-form cap and must now be reached.
        self.assertGreater(config.MAX_FORMS_PER_PLUGIN, 11,
                           "default form cap must cover a realistic number of forms")
        n_forms, vuln_idx = 15, 12
        app = Flask(__name__)

        @app.route("/")
        def index():
            forms = "".join(
                f'<form method="POST" action="/f{i}"><input type="text" name="q"></form>'
                for i in range(1, n_forms + 1)
            )
            return f"<html><body>{forms}</body></html>"

        @app.route("/f<int:i>", methods=["POST"])
        def handle(i):
            q = request.form.get("q", "")
            if i == vuln_idx:
                return Response(f"<html><body>Results for: {q}</body></html>", mimetype="text/html")
            return Response(f"<html><body>Results for: {html.escape(q)}</body></html>", mimetype="text/html")

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            injectables = WebCrawler(mock_mode=False, max_pages=5, max_depth=2).crawl(
                f"http://127.0.0.1:{srv.server_port}").get_injectable_endpoints()
            scanner = XSSScanner(mock_mode=False)
            scanner.configure(f"http://127.0.0.1:{srv.server_port}")
            scanner.set_discovered_endpoints(injectables)
            scanner.run()
            findings = scanner.parse_output()["findings"]
        finally:
            srv.shutdown()

        xss = [f for f in findings if f.get("vuln_type") == "xss" and f.get("endpoint") == f"/f{vuln_idx}"]
        self.assertEqual(len(xss), 1, f"vulnerable form /f{vuln_idx} not probed/reported: {[f['endpoint'] for f in findings]}")


if __name__ == "__main__":
    unittest.main()
