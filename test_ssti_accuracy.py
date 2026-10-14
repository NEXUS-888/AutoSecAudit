"""SSTI detection must rely on a distinctive evaluated value, not the two digits '49'.

Found in the 2026-10-13 retest: the plugin flagged an unrelated static page as high-confidence
SSTI because the number 49 appeared inside markup (an element id, a timestamp), while the real
template-injection lab returned HTTP 500 on {{...}} and was never confirmed.
"""
import sys
import threading
import unittest

sys.path.insert(0, ".")

from flask import Flask, request
from werkzeug.serving import make_server

from plugins.ssti_plugin import SSTIScanner


def _server(app):
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestSSTIAccuracy(unittest.TestCase):
    def _scan(self, app):
        srv = _server(app)
        try:
            plugin = SSTIScanner(mock_mode=False)
            plugin.configure(f"http://127.0.0.1:{srv.server_port}")
            plugin.set_discovered_endpoints([{"path": "/p", "param": "name", "method": "GET"}])
            plugin.run()
            return plugin.parse_output()["findings"]
        finally:
            srv.shutdown()

    def test_dynamic_noise_containing_49_is_not_flagged(self):
        # The page ignores the template payload entirely but stamps a changing counter into the markup.
        # The control response has no '49'; a later response happens to render an id containing '49'.
        # Matching on the two digits '49' would raise a false positive here; a distinctive value won't.
        # Calls arrive as: control (146), then payloads (147, 148, 149, ...). The control has no '49';
        # the third probe renders id "c149". Matching on '49' flags it; a distinctive value does not.
        app = Flask(__name__)
        state = {"n": 145}

        @app.route("/p")
        def p():
            state["n"] += 1
            return f'<html><body id="c{state["n"]}"><p>static page, input ignored</p></body></html>'

        self.assertEqual(self._scan(app), [])

    def test_real_template_evaluation_is_flagged(self):
        app = Flask(__name__)

        @app.route("/p")
        def p():
            import re
            val = request.args.get("name", "")
            m = re.search(r"(\d{2,7})\s*\*\s*(\d{2,7})", val)   # a toy template engine that evaluates N*M
            if m:
                val = str(int(m.group(1)) * int(m.group(2)))
            return f"<html><body><p>Hello {val}</p></body></html>"

        findings = self._scan(app)
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["vuln_type"], "ssti")

    def test_reflected_payload_without_evaluation_is_not_flagged(self):
        app = Flask(__name__)

        @app.route("/p")
        def p():
            import html
            return f"<p>Hello {html.escape(request.args.get('name', ''))}</p>"   # echoes payload, never evaluates

        self.assertEqual(self._scan(app), [])


if __name__ == "__main__":
    unittest.main()
