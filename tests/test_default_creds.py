"""Tests for default-credential spraying (exploits/default_creds.py)."""
from __future__ import annotations

import base64
import http.server
import threading

import pytest

from exploits import default_creds
from sandbox import scope_guard


class _Target:
    """Minimal duck-typed hostport target with a spray flag + scope guard."""

    def __init__(self, host, port, spray=True, scope=("127.0.0.1",)):
        self.kind = "hostport"
        self.raw = f"{host}:{port}"
        self.host = host
        self.port = port
        self.ports = [port]
        self.spray = spray
        self.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity="intrusive")


def _basic_server(valid_user, valid_pw, *, server_header="Grafana", lockout=False,
                  login_path="/login"):
    """A fake HTTP service: 200 only with correct basic creds; 401 otherwise.

    The root path advertises ``server_header`` for fingerprinting.
    """
    attempts = {"n": 0}

    class _H(http.server.BaseHTTPRequestHandler):
        def _auth_ok(self):
            hdr = self.headers.get("Authorization", "")
            if not hdr.startswith("Basic "):
                return False
            try:
                user, pw = base64.b64decode(hdr[6:]).decode().split(":", 1)
            except Exception:
                return False
            return user == valid_user and pw == valid_pw

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/":
                self.send_response(200)
                self.send_header("Server", server_header)
                self.end_headers()
                self.wfile.write(f"<title>{server_header}</title>".encode())
                return
            if path == login_path:
                has_auth = self.headers.get("Authorization") is not None
                if has_auth:
                    attempts["n"] += 1  # count only real credential attempts
                if lockout:
                    self.send_response(429)
                    self.end_headers()
                    return
                if self._auth_ok():
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                else:
                    self.send_response(401)
                    self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):  # noqa: N802
            self.do_GET()

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    return srv, host, port, attempts


def test_spray_disabled_is_informational(monkeypatch):
    t = _Target("127.0.0.1", 12345, spray=False)
    res = default_creds.run(t)
    assert res.exploited is False
    assert any("not enabled" in f.title for f in res.findings)


def test_spray_finds_default_basic_creds(monkeypatch):
    # Force the loaded set to a basic-auth service on the test's login path.
    services = [{
        "service": "tomcat", "fingerprints": ["tomcat"], "default_ports": [],
        "auth": "http-basic", "login_path": "/login",
        "credentials": [["tomcat", "tomcat"], ["admin", "admin"]],
    }]
    monkeypatch.setattr(default_creds, "_load_services", lambda path=None: services)
    srv, host, port, _ = _basic_server("admin", "admin", server_header="Apache-Tomcat")
    try:
        t = _Target(host, port)
        res = default_creds.run(t)
        assert res.exploited is True
        assert any("Default credentials accepted: admin/admin" in f.title for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_spray_respects_max_attempts(monkeypatch):
    # Three passwords for one user, but cap is 3 and none match -> exactly 3 attempts.
    services = [{
        "service": "tomcat", "fingerprints": ["tomcat"], "default_ports": [],
        "auth": "http-basic", "login_path": "/login",
        "credentials": [["admin", "x1"], ["admin", "x2"], ["admin", "x3"], ["admin", "x4"]],
    }]
    monkeypatch.setattr(default_creds, "_load_services", lambda path=None: services)
    monkeypatch.setattr(default_creds, "_MAX_ATTEMPTS", 3)
    srv, host, port, attempts = _basic_server("admin", "correct", server_header="Tomcat")
    try:
        res = default_creds.run(_Target(host, port))
        assert res.exploited is False
        assert attempts["n"] == 3  # capped; the 4th password is never tried
    finally:
        srv.shutdown(); srv.server_close()


def test_spray_aborts_on_lockout(monkeypatch):
    services = [{
        "service": "tomcat", "fingerprints": ["tomcat"], "default_ports": [],
        "auth": "http-basic", "login_path": "/login",
        "credentials": [["admin", "x1"], ["admin", "x2"], ["admin", "x3"]],
    }]
    monkeypatch.setattr(default_creds, "_load_services", lambda path=None: services)
    srv, host, port, attempts = _basic_server("admin", "admin", server_header="Tomcat",
                                              lockout=True)
    try:
        res = default_creds.run(_Target(host, port))
        assert res.exploited is False
        assert attempts["n"] == 1  # aborted immediately on the first 429
        assert any("lockout" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_spray_skips_out_of_scope(monkeypatch):
    services = [{
        "service": "tomcat", "fingerprints": ["tomcat"], "default_ports": [],
        "auth": "http-basic", "login_path": "/login",
        "credentials": [["admin", "admin"]],
    }]
    monkeypatch.setattr(default_creds, "_load_services", lambda path=None: services)
    srv, host, port, attempts = _basic_server("admin", "admin")
    try:
        # scope only allows a different host -> the real loopback target is out of scope
        t = _Target(host, port, scope=("10.255.255.255",))
        res = default_creds.run(t)
        assert attempts["n"] == 0
        assert any("out-of-scope" in f.title for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_module_metadata():
    assert default_creds.SUPPORTS == {"url", "hostport"}
    assert default_creds.INTENSITY == "intrusive"
