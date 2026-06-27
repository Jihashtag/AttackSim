"""Tests for Phase-3 modules: ssti_confirm, oidc_oauth_misconfig, cache_poisoning, OOB."""
from __future__ import annotations

import http.server
import json
import threading

from exploits import cache_poisoning, oidc_oauth_misconfig, ssti_confirm
from sandbox import oob_listener, scope_guard


def _target(url, *, scope=("127.0.0.1",), intensity="intrusive"):
    t = type("T", (), {})()
    t.kind = "url"
    t.url = url
    t.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity=intensity)
    t.canary_url = None
    t.request_headers = lambda: {}
    return t


# ---------------------------------------------------------------------------
# ssti_confirm
# ---------------------------------------------------------------------------
def test_ssti_confirmed_when_arithmetic_evaluated():
    product = str(ssti_confirm._A * ssti_confirm._B)

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            val = qs.get("q", [""])[0]
            self.send_response(200)
            self.end_headers()
            # Emulate a Jinja2-style engine: evaluate {{A*B}} to the product.
            if val.startswith("{{") and val.endswith("}}"):
                self.wfile.write(("result=" + product).encode())
            else:
                self.wfile.write(b"result=" + val.encode())

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    try:
        res = ssti_confirm.run(_target(f"http://{host}:{port}/?q=1"))
        assert res.exploited is True
        assert any("SSTI confirmed" in f.title for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_ssti_no_eval_no_finding(routed_http_server):
    # Echoes the raw payload back (no evaluation) -> must NOT confirm.
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
        res = ssti_confirm.run(_target(f"http://{host}:{port}/?q=1"))
        assert res.exploited is False
    finally:
        srv.shutdown(); srv.server_close()


# ---------------------------------------------------------------------------
# oidc_oauth_misconfig
# ---------------------------------------------------------------------------
def test_oidc_alg_none_and_no_pkce(routed_http_server):
    doc = json.dumps({
        "issuer": "http://idp.example",
        "authorization_endpoint": "https://idp.example/auth",
        "token_endpoint": "http://idp.example/token",   # plaintext -> HIGH
        "id_token_signing_alg_values_supported": ["RS256", "none"],  # none -> HIGH
    }).encode()
    routes = {"GET /.well-known/openid-configuration":
              (200, doc, [("Content-Type", "application/json")])}
    _h, _p, base = routed_http_server(routes)
    res = oidc_oauth_misconfig.run(_target(base, intensity="active"))
    titles = " ".join(f.title for f in res.findings).lower()
    assert "none" in titles and "plaintext" in titles and "pkce" in titles
    assert res.exploited is True


def test_oidc_no_doc(routed_http_server):
    _h, _p, base = routed_http_server({"GET /": (200, b"hi")})
    res = oidc_oauth_misconfig.run(_target(base, intensity="active"))
    assert res.exploited is False
    assert res.findings == []


# ---------------------------------------------------------------------------
# cache_poisoning
# ---------------------------------------------------------------------------
def test_cache_poisoning_reflected_and_cacheable():
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            xfh = self.headers.get("X-Forwarded-Host", "")
            self.send_response(200)
            self.send_header("Age", "120")           # cache indicator
            self.end_headers()
            self.wfile.write(f"<link href=https://{xfh}/a.css>".encode())

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    try:
        res = cache_poisoning.run(_target(f"http://{host}:{port}/", intensity="active"))
        assert res.exploited is True
        assert any("cacheable reflection" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_cache_poisoning_no_reflection(routed_http_server):
    _h, _p, base = routed_http_server({"GET /": (200, b"static", [("Age", "5")])})
    res = cache_poisoning.run(_target(base, intensity="active"))
    assert res.exploited is False


# ---------------------------------------------------------------------------
# OOB listener
# ---------------------------------------------------------------------------
def test_oob_listener_records_and_confirms():
    import urllib.request
    listener = oob_listener.OOBListener().start()
    try:
        token = listener.new_token()
        urllib.request.urlopen(f"{listener.base_url()}/?m={token}", timeout=3).read()
        assert listener.was_hit(token) is True
        # The check endpoint echoes back a seen marker (active-confirm compatible).
        body = urllib.request.urlopen(f"{listener.base_url()}/?check={token}",
                                      timeout=3).read().decode()
        assert token in body
        assert listener.was_hit("never-seen") is False
    finally:
        listener.stop()


def test_oob_parse_listen_spec():
    assert oob_listener.parse_listen_spec(None) == ("127.0.0.1", 0)
    assert oob_listener.parse_listen_spec("9000") == ("127.0.0.1", 9000)
    assert oob_listener.parse_listen_spec("0.0.0.0:8888") == ("0.0.0.0", 8888)
