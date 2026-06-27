"""Tests for Phase-2 cross-cutting infra: global request budget + auth passthrough."""
from __future__ import annotations

import http.server
import threading
import time

from exploits import web_misconfig
from sandbox import budget as budgetmod
from sandbox import scope_guard


# ---------------------------------------------------------------------------
# RequestBudget
# ---------------------------------------------------------------------------
def test_budget_request_ceiling():
    b = budgetmod.RequestBudget(max_requests=3, rate_limit=0, wall_budget=60)
    assert b.acquire() is True
    assert b.acquire() is True
    assert b.acquire() is True
    assert b.acquire() is False        # ceiling hit
    assert b.exhausted is True
    assert b.count == 3


def test_budget_rate_limit_delays():
    b = budgetmod.RequestBudget(max_requests=100, rate_limit=50, wall_budget=60)
    start = time.monotonic()
    for _ in range(4):
        assert b.acquire() is True
    elapsed = time.monotonic() - start
    # 4 acquisitions at 50/s => at least ~3 inter-request gaps of 20ms.
    assert elapsed >= 0.04


def test_budget_wall_deadline():
    b = budgetmod.RequestBudget(max_requests=100, rate_limit=0, wall_budget=0.0)
    time.sleep(0.01)
    assert b.acquire() is False
    assert b.exhausted is True


def test_budget_remaining():
    b = budgetmod.RequestBudget(max_requests=5, rate_limit=0, wall_budget=60)
    b.acquire(2)
    assert b.remaining == 3


# ---------------------------------------------------------------------------
# Auth passthrough end-to-end through web_misconfig
# ---------------------------------------------------------------------------
def test_auth_passthrough_sends_cookie_and_headers():
    seen = {}

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["cookie"] = self.headers.get("Cookie")
            seen["xcsrf"] = self.headers.get("X-CSRF-Token")
            seen["auth"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    base = f"http://{host}:{port}/"
    try:
        t = type("T", (), {})()
        t.kind = "url"
        t.url = base
        t.scope_guard = scope_guard.ScopeGuard.from_specs(["127.0.0.1"], intensity="active")
        t.jwt = "tok123"
        t.api_key = None
        t.auth_header = None
        t.auth_scheme = "Bearer"
        t.cookies = "session=abc"
        t.session_headers = {"X-CSRF-Token": "xyz"}

        def auth_headers():
            return {"Authorization": "Bearer tok123"}

        def request_headers():
            out = dict(auth_headers())
            out["Cookie"] = t.cookies
            out.update(t.session_headers)
            return out

        t.auth_headers = auth_headers
        t.request_headers = request_headers
        web_misconfig.run(t)
        assert seen.get("cookie") == "session=abc"
        assert seen.get("xcsrf") == "xyz"
        assert seen.get("auth") == "Bearer tok123"
    finally:
        srv.shutdown(); srv.server_close()
