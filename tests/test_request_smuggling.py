"""Offline timing test for request-smuggling detection.

A raw TCP HTTP server stalls on any request carrying a Transfer-Encoding header (the
ambiguous probe) and answers a normal baseline request immediately. The module's delay
threshold/read-timeout are lowered so the test runs quickly.
"""
from __future__ import annotations

import socket
import threading
import time
import types

from exploits import request_smuggling


def _raw_http_server(stall_seconds=2.0):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def handle(conn):
        try:
            conn.settimeout(5)
            data = b""
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if b"transfer-encoding" in data.lower():
                time.sleep(stall_seconds)  # simulate the back-end waiting for more body
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port, (lambda: (stop.set(), srv.close()))


def test_request_smuggling_timing_detected(monkeypatch):
    monkeypatch.setattr(request_smuggling, "_DELAY_THRESHOLD", 1)
    monkeypatch.setattr(request_smuggling, "_READ_TIMEOUT", 4)
    port, stop = _raw_http_server(stall_seconds=2.0)
    target = types.SimpleNamespace(url=f"http://127.0.0.1:{port}/", scope_guard=None, budget=None)
    try:
        res = request_smuggling.run(target)
    finally:
        stop()
    assert res.exploited is True
    assert any("smuggling" in f.title.lower() and f.cwe == "CWE-444" for f in res.findings)


def test_request_smuggling_clean_server_no_finding(monkeypatch):
    monkeypatch.setattr(request_smuggling, "_DELAY_THRESHOLD", 1)
    monkeypatch.setattr(request_smuggling, "_READ_TIMEOUT", 3)
    # stall_seconds=0 => even the TE probe answers promptly, so no desync is inferred.
    port, stop = _raw_http_server(stall_seconds=0.0)
    target = types.SimpleNamespace(url=f"http://127.0.0.1:{port}/", scope_guard=None, budget=None)
    try:
        res = request_smuggling.run(target)
    finally:
        stop()
    assert res.exploited is False
