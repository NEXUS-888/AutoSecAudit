"""Shared local fixture server helpers for unit and regression tests.

Starts Flask fixture apps on 127.0.0.1 with an ephemeral port using
werkzeug.serving.make_server("127.0.0.1", 0, app) in a background daemon thread.
Never contacts any external host.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Generator
from werkzeug.serving import make_server


class LocalFixtureServer:
    """Wrapper around werkzeug's BaseWSGIServer bound to 127.0.0.1:0."""

    def __init__(self, app: Any, host: str = "127.0.0.1", port: int = 0) -> None:
        self.app = app
        self.server = make_server(host, port, app, threaded=True)
        self.host = host
        self.port = int(self.server.server_port)
        self.base_url = f"http://{self.host}:{self.port}"
        self._thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )

    def start(self) -> "LocalFixtureServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def __enter__(self) -> "LocalFixtureServer":
        return self.start()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


@contextmanager
def run_fixture_server(app: Any) -> Generator[LocalFixtureServer, None, None]:
    """Context manager that runs a Flask app on 127.0.0.1:0 in a thread."""
    srv = LocalFixtureServer(app)
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()
