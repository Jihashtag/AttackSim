"""Tests for the intrusive/active web modules: content_discovery, active_confirm, web_misconfig."""
from __future__ import annotations

import http.server
import threading

import pytest

from exploits import active_confirm, content_discovery, web_misconfig
from sandbox import scope_guard


def _target(base, *, scope=("127.0.0.1",), canary_url=None):
    t = type("T", (), {})()
    t.kind = "url"
    t.raw = base
    t.url = base
    t.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity="intrusive")
    t.canary_url = canary_url
    return t


# ---------------------------------------------------------------------------
# content_discovery
# ---------------------------------------------------------------------------
def test_content_discovery_finds_paths_against_soft404(routed_http_server):
    # Server: most paths 404; /admin -> 200 sensitive; /api/v1 -> 401; random -> 404.
    routes = {
        "GET /admin": (200, b"<h1>admin panel</h1>"),
        "GET /api/v1": (401, b"unauthorized"),
    }
    _h, _p, base = routed_http_server(routes)
    res = content_discovery.run(_target(base))
    titles = " ".join(f.title for f in res.findings)
    assert "/admin" in titles
    assert any(f.severity == "HIGH" and "admin" in f.title for f in res.findings)
    assert "/api/v1" in titles  # 401 still reported as existing surface
    assert res.exploited is True


def test_content_discovery_suppresses_soft404_catchall(routed_http_server):
    # A catch-all that returns 200 with the SAME body for everything (SPA soft-404):
    class _All(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>same page everywhere</html>")

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _All)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    try:
        res = content_discovery.run(_target(f"http://{host}:{port}"))
        # Every path matches the calibrated baseline -> no false-positive findings.
        assert [f for f in res.findings if f.severity in ("HIGH", "MEDIUM", "LOW")] == []
    finally:
        srv.shutdown(); srv.server_close()


def test_content_discovery_out_of_scope_skips(routed_http_server):
    _h, _p, base = routed_http_server({"GET /admin": (200, b"x")})
    res = content_discovery.run(_target(base, scope=("10.255.255.255",)))
    assert res.exploited is False
    assert any("out of scope" in f.title for f in res.findings)


def test_content_discovery_metadata():
    assert content_discovery.SUPPORTS == {"url"}
    assert content_discovery.INTENSITY == "intrusive"
    assert content_discovery._load_words()  # wordlist parses


# ---------------------------------------------------------------------------
# active_confirm
# ---------------------------------------------------------------------------
def test_active_confirm_reflection(routed_http_server):
    # Reflect any query string back into the body verbatim.
    class _Echo(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(("echo:" + self.path).encode())

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    try:
        res = active_confirm.run(_target(f"http://{host}:{port}/?q=1"))
        assert any("Reflected parameter confirmed" in f.title for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_active_confirm_ssrf_skipped_without_canary(routed_http_server):
    _h, _p, base = routed_http_server({"GET /": (200, b"ok")})
    res = active_confirm.run(_target(base))
    assert any("SSRF confirmation skipped" in f.title for f in res.findings)


def test_active_confirm_ssrf_confirmed_with_canary():
    # A single fake server doubles as target (fetches the canary) and canary (logs hits).
    hits = set()

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            # canary 'check' endpoint: report whether the marker was previously hit
            if "check" in qs:
                marker = qs["check"][0]
                self.send_response(200); self.end_headers()
                self.wfile.write(b"HIT " + marker.encode() if marker in hits else b"none")
                return
            # canary 'm' endpoint: record the marker (simulates the target's server-side fetch)
            if "m" in qs:
                hits.add(qs["m"][0])
                self.send_response(200); self.end_headers(); self.wfile.write(b"logged")
                return
            # target endpoint: when given a url= param, fetch it (the SSRF behaviour)
            if "url" in qs:
                import urllib.request
                try:
                    urllib.request.urlopen(qs["url"][0], timeout=3).read(64)
                except Exception:
                    pass
                self.send_response(200); self.end_headers(); self.wfile.write(b"fetched")
                return
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    base = f"http://{host}:{port}"
    try:
        t = _target(base, canary_url=base + "/canary")
        res = active_confirm.run(t)
        assert res.exploited is True
        assert any("SSRF confirmed" in f.title for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_active_confirm_metadata():
    assert active_confirm.INTENSITY == "intrusive"


# ---------------------------------------------------------------------------
# web_misconfig
# ---------------------------------------------------------------------------
def test_web_misconfig_cors_with_credentials(routed_http_server):
    routes = {"GET /": (200, b"ok", [
        ("Access-Control-Allow-Origin", "https://sectest-evil.example"),
        ("Access-Control-Allow-Credentials", "true"),
    ])}
    _h, _p, base = routed_http_server(routes)
    res = web_misconfig.run(_target(base))
    assert res.exploited is True
    assert any("CORS reflects arbitrary Origin WITH credentials" in f.title for f in res.findings)


def test_web_misconfig_open_redirect(routed_http_server):
    routes = {"GET /": (302, b"", [("Location", "https://sectest-evil.example/owned")])}
    _h, _p, base = routed_http_server(routes)
    res = web_misconfig.run(_target(base))
    assert any("Open redirect" in f.title for f in res.findings)


def test_web_misconfig_clean_site(routed_http_server):
    routes = {"GET /": (200, b"ok")}
    _h, _p, base = routed_http_server(routes)
    res = web_misconfig.run(_target(base))
    # http (not https) clean root -> no HIGH findings
    assert res.exploited is False


def test_web_misconfig_metadata():
    assert web_misconfig.SUPPORTS == {"url"}
    assert web_misconfig.INTENSITY == "active"
