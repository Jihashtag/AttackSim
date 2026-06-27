"""Tests for the FUZZ-tier robustness module (fuzz_probe). Hard-gated, bounded, anti-DoS."""
from __future__ import annotations

import http.server
import threading

import pytest

from exploits import fuzz_probe
from sandbox import scope_guard


@pytest.fixture(autouse=True)
def _no_rate_sleep(monkeypatch):
    # Disable the real inter-request delay so tests are fast (the production default is 0.1s).
    monkeypatch.setattr(fuzz_probe, "_MIN_DELAY", 0.0)


def _target(base, *, scope=("127.0.0.1",)):
    t = type("T", (), {})()
    t.kind = "url"
    t.raw = base
    t.url = base
    t.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity="fuzz")
    return t


def _server(handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    return srv, f"http://{host}:{port}/?q=1"


def test_fuzz_detects_server_error():
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            # Return 500 whenever the q param contains a quote (a 'fault').
            if "'" in self.path or "%27" in self.path:
                self.send_response(500); self.end_headers(); self.wfile.write(b"boom")
                return
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *_a):
            pass

    srv, base = _server(_H)
    try:
        res = fuzz_probe.run(_target(base))
        assert res.exploited is False  # fuzz tier never claims exploitation
        assert any("server error 500" in f.title for f in res.findings)
        assert all(f.category == "fuzz" for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_fuzz_detects_stack_trace_signature():
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200); self.end_headers()
            self.wfile.write(b"Traceback (most recent call last):\n  File ...")

        def log_message(self, *_a):
            pass

    srv, base = _server(_H)
    try:
        res = fuzz_probe.run(_target(base))
        assert any("error signature" in f.title for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_fuzz_respects_request_cap(monkeypatch):
    monkeypatch.setattr(fuzz_probe, "_MAX_REQUESTS", 5)
    count = {"n": 0}

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            count["n"] += 1
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *_a):
            pass

    srv, base = _server(_H)
    try:
        fuzz_probe.run(_target(base))
        assert count["n"] <= 5  # hard cap enforced
    finally:
        srv.shutdown(); srv.server_close()


def test_fuzz_out_of_scope_skips():
    # No server needed; out-of-scope returns immediately.
    t = _target("http://127.0.0.1:1/?q=1", scope=("10.0.0.1",))
    res = fuzz_probe.run(t)
    assert res.exploited is False
    assert any("out of scope" in f.title for f in res.findings)


def test_fuzz_corpus_loads_and_is_benign():
    corpus = fuzz_probe._load_corpus()
    assert corpus
    blob = "\n".join(corpus).lower()
    # The corpus must NOT contain working destructive payloads.
    for forbidden in ("drop table", "rm -rf", "; shutdown", "delete from"):
        assert forbidden not in blob


def test_fuzz_metadata():
    assert fuzz_probe.SUPPORTS == {"url"}
    assert fuzz_probe.INTENSITY == "fuzz"
