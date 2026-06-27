"""Offline tests for the web confirmation modules: sqli / path-traversal / xxe.

A single deliberately-vulnerable local app exposes endpoints that emit a SQL error, a
boolean-divergent response, a traversal file signature, and XML entity expansion (plus an
endpoint that simulates a vulnerable XML parser fetching an external entity, to exercise
the out-of-band XXE path against the real OOB listener).
"""
from __future__ import annotations

import http.server
import re
import threading
import types
from urllib.parse import parse_qs, urlparse

from exploits import netutil, path_traversal_confirm, sqli_confirm, xxe_confirm
from sandbox import oob_listener


class _VulnApp(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path
        if path == "/sqli-error":
            val = (qs.get("id") or [""])[0]
            if "'" in val:
                return self._send(200, b"Error: You have an error in your SQL syntax near '1''")
            return self._send(200, b"<html>product page</html>")
        if path == "/sqli-bool":
            val = (qs.get("id") or [""])[0]
            if val.endswith("'='2"):
                return self._send(200, b"none")  # FALSE -> short, divergent
            return self._send(200, b"<html>" + b"PRODUCT " * 40 + b"</html>")  # baseline/TRUE
        if path == "/download":
            val = (qs.get("file") or [""])[0]
            if "etc/passwd" in val:
                return self._send(200, b"root:x:0:0:root:/root:/bin/bash\n")
            return self._send(200, b"<html>download</html>")
        return self._send(404, b"nope")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("latin-1", "replace") if length else ""
        u = urlparse(self.path)
        if u.path == "/xml-inband":
            # Simulate a parser that resolves internal entities into the response.
            m = re.search(r'<!ENTITY x "([^"]+)"', body)
            echoed = m.group(1) if m else ""
            return self._send(200, ("<r>" + echoed + "</r>").encode())
        if u.path == "/xml-oob":
            # Simulate a vulnerable parser fetching an external entity URL out-of-band.
            m = re.search(r'SYSTEM\s+"([^"]+)"', body)
            if m:
                try:
                    netutil.http_get(m.group(1), timeout=3, max_bytes=256)
                except Exception:
                    pass
            return self._send(200, b"<r></r>")
        return self._send(404, b"nope")

    def log_message(self, *_a):
        pass


def _app():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _VulnApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    return srv, f"http://{host}:{port}"


def _target(url, canary_url=None):
    return types.SimpleNamespace(url=url, scope_guard=None, budget=None,
                                 canary_url=canary_url, request_headers=lambda: {})


def test_sqli_error_based_confirmed():
    srv, base = _app()
    try:
        res = sqli_confirm.run(_target(base + "/sqli-error"))
        assert res.exploited is True
        assert any("error-based" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_sqli_boolean_based_confirmed():
    srv, base = _app()
    try:
        res = sqli_confirm.run(_target(base + "/sqli-bool"))
        assert res.exploited is True
        assert any("boolean-based" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_path_traversal_confirmed():
    srv, base = _app()
    try:
        res = path_traversal_confirm.run(_target(base + "/download"))
        assert res.exploited is True
        assert any(f.cwe == "CWE-22" for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_xxe_inband_entity_expansion():
    srv, base = _app()
    try:
        res = xxe_confirm.run(_target(base + "/xml-inband"))
        assert any("entity expansion" in f.title.lower() and f.severity == "MEDIUM"
                   for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_xxe_out_of_band_via_oob_listener():
    oob = oob_listener.OOBListener("127.0.0.1", 0).start()
    srv, base = _app()
    try:
        res = xxe_confirm.run(_target(base + "/xml-oob", canary_url=oob.base_url()))
        assert res.exploited is True
        assert any("out-of-band xxe" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()
        oob.stop()
