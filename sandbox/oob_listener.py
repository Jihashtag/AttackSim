"""Built-in out-of-band (OOB) canary listener for blind-vulnerability confirmation.

Some confirmations (SSRF in ``active-confirm``, blind injection) need an operator-controlled
callback so the target can prove it reached "out of band". Rather than require external
infrastructure, this starts a tiny localhost HTTP listener that records every hit and mints
per-probe tokens. A module confirms a blind bug by checking whether its token was hit.

Safety model:

* Binds an **operator-controlled** interface (default loopback). It only *records* requests;
  it never initiates traffic and serves a fixed inert response.
* It is the toolkit's *own* canary — consistent with the "only fetch your own canary" rule
  enforced by ``active-confirm``. Exposing it on a routable interface is an explicit
  operator choice (``--oob-listen host:port``).
"""
from __future__ import annotations

import http.server
import threading
import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


class _Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        listener: "OOBListener" = self.server._listener  # type: ignore[attr-defined]
        qs = parse_qs(urlparse(self.path).query)
        # Correlation/confirmation endpoint (compatible with active-confirm): report
        # whether a marker was previously seen. The check itself is NOT recorded as a hit.
        if "check" in qs:
            marker = qs["check"][0]
            body = (f"HIT {marker}" if listener.was_hit(marker) else "none").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return
        listener.record(self.path, dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"sectest-oob-ok")

    def do_GET(self):  # noqa: N802
        self._handle()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            try:
                self.rfile.read(length)
            except Exception:
                pass
        self._handle()

    def log_message(self, *_a):
        pass


class OOBListener:
    """A localhost HTTP listener that records callbacks keyed by an embedded token."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._hits: List[Tuple[str, dict]] = []
        self._lock = threading.Lock()
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> "OOBListener":
        srv = http.server.HTTPServer((self.host, self.port), _Handler)
        srv._listener = self  # type: ignore[attr-defined]
        self.host, self.port = srv.server_address
        self._server = srv
        self._thread = threading.Thread(target=srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        # Idempotent: safe to call twice. Also join the serve_forever thread and reset it
        # so a second stop() (or a stop() after a failed start) does not crash (BUG-20).
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
        if self._thread is not None:
            try:
                self._thread.join(timeout=5)
            except RuntimeError:
                pass
            self._thread = None

    # -- recording / querying ------------------------------------------------
    def record(self, path: str, headers: dict):
        with self._lock:
            self._hits.append((path, headers))

    @property
    def hits(self) -> List[Tuple[str, dict]]:
        with self._lock:
            return list(self._hits)

    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def new_token(self) -> str:
        return "oob-" + uuid.uuid4().hex[:16]

    def token_url(self, token: str) -> str:
        return f"{self.base_url()}/{token}"

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return any(token in path or token in str(headers)
                       for path, headers in self._hits)


def parse_listen_spec(spec: Optional[str]) -> Tuple[str, int]:
    """Parse ``host:port`` / ``:port`` / ``port`` into ``(host, port)`` (defaults loopback)."""
    if not spec:
        return ("127.0.0.1", 0)
    spec = spec.strip()
    if "://" in spec:
        u = urlparse(spec)
        return (u.hostname or "127.0.0.1", u.port or 0)
    if ":" in spec:
        host, _, port = spec.rpartition(":")
        port = port.strip()
        # A non-numeric port (e.g. --oob-listen host:abc) must not raise ValueError (BUG-25).
        if port and not port.isdigit():
            raise ValueError(f"invalid --oob-listen port {port!r} in spec {spec!r}")
        return (host or "127.0.0.1", int(port or 0))
    if spec.isdigit():
        return ("127.0.0.1", int(spec))
    return (spec, 0)
