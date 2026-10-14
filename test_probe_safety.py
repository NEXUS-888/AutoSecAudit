"""Active GET probes must obey the same state-changing-path deny rules as form probes.

Found in the 2026-10-13 authenticated retest: the open-redirect plugin probed a hard-coded
/logout and every discovered path, so an authenticated scan would log its own session out.
"""
import sys
import threading
import unittest

sys.path.insert(0, ".")

from flask import Flask, redirect, request
from werkzeug.serving import make_server

from plugins.open_redirect_plugin import OpenRedirectScanner


def _server(app):
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestOpenRedirectProbeSafety(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        self.hits = []

        @app.before_request
        def _record():
            self.hits.append(request.path)

        # Every path (including the dangerous ones) is a working open redirect, so the ONLY reason
        # a dangerous path would not be reported is that the scanner refused to probe it.
        @app.route("/<path:p>")
        def any_path(p):
            target = request.args.get("next") or request.args.get("redirect") or request.args.get("url")
            if target:
                return redirect(target)
            return "ok"

        @app.route("/")
        def index():
            return "ok"

        self.srv = _server(app)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"

    def tearDown(self):
        self.srv.shutdown()

    def _scan(self, discovered=None):
        plugin = OpenRedirectScanner(mock_mode=False)
        plugin.configure(self.base)
        if discovered:
            plugin.set_discovered_endpoints(discovered)
        plugin.run()
        return plugin.parse_output()["findings"]

    def test_logout_and_other_state_changing_paths_are_never_probed(self):
        discovered = [
            {"path": "/password/change", "param": "next", "method": "GET"},
            {"path": "/account/delete", "param": "next", "method": "GET"},
            {"path": "/settings/reset", "param": "next", "method": "GET"},
            {"path": "/app/goto", "param": "next", "method": "GET"},
        ]
        findings = self._scan(discovered)
        dangerous = [h for h in self.hits if any(w in h for w in
                     ("logout", "delete", "password", "reset", "destroy", "signout"))]
        self.assertEqual(dangerous, [], f"probed state-changing path(s): {dangerous}")
        reported = {f["endpoint"] for f in findings}
        self.assertNotIn("/password/change", reported)
        self.assertNotIn("/account/delete", reported)
        self.assertNotIn("/settings/reset", reported)

    def test_safe_redirect_endpoints_are_still_probed_and_reported(self):
        findings = self._scan([{"path": "/app/goto", "param": "next", "method": "GET"}])
        reported = {f["endpoint"] for f in findings}
        # /login and /redirect are built-in safe candidates; /app/goto is discovered and safe.
        self.assertTrue({"/login", "/redirect"} & reported, reported)
        self.assertIn("/app/goto", reported)


if __name__ == "__main__":
    unittest.main()
