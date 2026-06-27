"""Pytest configuration: make the toolkit importable and provide fixtures.

Adds the toolkit root to ``sys.path`` (so ``import config`` / ``import exploits``
work the same way they do under ``python main.py``) and exposes a lightweight
local HTTP server fixture for the active network modules.
"""
from __future__ import annotations

import http.server
import os
import sys
import threading
from dataclasses import dataclass
from typing import Iterator, Optional

import pytest

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOL_DIR not in sys.path:
    sys.path.insert(0, TOOL_DIR)


@dataclass
class _FakeTarget:
    """A minimal duck-typed stand-in for targets.model.Target."""

    kind: str = "url"
    raw: str = ""
    root: Optional[str] = None
    url: Optional[str] = None
    jwt: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    auth_header: Optional[str] = None
    auth_scheme: Optional[str] = None

    def __post_init__(self):
        self.ports = [self.port] if self.port else []

    # Mirror the real Target auth helpers so modules behave identically.
    def jwt_header(self):
        if not self.jwt:
            return None
        name = self.auth_header or "Authorization"
        scheme = "Bearer" if self.auth_scheme is None else self.auth_scheme
        prefix = f"{scheme} " if scheme else ""
        return (name, f"{prefix}{self.jwt}")

    def api_key_header(self):
        if not self.api_key:
            return None
        name = self.auth_header or "X-API-Key"
        scheme = "" if self.auth_scheme is None else self.auth_scheme
        prefix = f"{scheme} " if scheme else ""
        return (name, f"{prefix}{self.api_key}")

    def auth_headers(self):
        out = {}
        for pair in (self.jwt_header(), self.api_key_header()):
            if pair:
                out[pair[0]] = pair[1]
        return out

    def request_headers(self):
        out = dict(self.auth_headers())
        cookies = getattr(self, "cookies", None)
        if cookies:
            out["Cookie"] = cookies
        session_headers = getattr(self, "session_headers", None)
        if session_headers:
            out.update(session_headers)
        return out


@pytest.fixture
def fake_target():
    return _FakeTarget


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Server", "pytest-fixture/1.0")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):  # silence the test server
        pass


@pytest.fixture
def http_server() -> Iterator[str]:
    """A throwaway local HTTP server. Yields its base URL."""
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = srv.server_address
        yield f"http://{host}:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


class _AppHandler(http.server.BaseHTTPRequestHandler):
    """A deliberately vulnerable app: exposes sensitive paths and honours alg:none JWTs."""

    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/actuator/env":
            return self._send(200, b'{"propertySources":[{"name":"systemEnvironment"}]}',
                              "application/json")
        if path == "/actuator/heapdump":
            return self._send(200, b"\x00JAVA PROFILE 1.0.1\x00" * 8, "application/octet-stream")
        if path == "/.git/config":
            return self._send(200, b"[core]\n\trepositoryformatversion = 0\n")
        if path in ("/", ""):
            auth = self.headers.get("Authorization", "")
            tok = auth.split(" ", 1)[1] if " " in auth else auth
            # Vulnerable verifier: accepts unsigned (alg:none) tokens.
            if tok and tok.count(".") == 2 and tok.endswith("."):
                return self._send(200, b"welcome admin")
            return self._send(401, b"unauthorized")
        return self._send(404, b"not found")

    def log_message(self, *_args):
        pass


@pytest.fixture
def app_server() -> Iterator[str]:
    """A vulnerable HTTP app (sensitive paths + alg:none JWT acceptance). Yields base URL."""
    srv = http.server.HTTPServer(("127.0.0.1", 0), _AppHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = srv.server_address
        yield f"http://{host}:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# Generic routed HTTP + raw TCP fixtures for the cloud-native active modules.
# ---------------------------------------------------------------------------
def _make_routed_handler(routes: dict):
    """routes: {path: (status, body_bytes, [extra_header_tuples])}.

    Keys may be a bare path (matches any method) or "METHOD path" (e.g. "POST /x").
    Method-qualified keys win over bare keys.
    """

    def _lookup(method, path):
        spec = routes.get(f"{method} {path}")
        if spec is None:
            spec = routes.get(path)
        return spec

    class _Routed(http.server.BaseHTTPRequestHandler):
        def _serve(self, method):
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                try:
                    self.rfile.read(length)
                except Exception:
                    pass
            spec = _lookup(method, path)
            if spec is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            status, body, *rest = spec
            extra = rest[0] if rest else []
            self.send_response(status)
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            self._serve("GET")

        def do_POST(self):  # noqa: N802
            self._serve("POST")

        def do_PUT(self):  # noqa: N802
            self._serve("PUT")

        def do_DELETE(self):  # noqa: N802
            self._serve("DELETE")

        def log_message(self, *_a):
            pass

    return _Routed


@pytest.fixture
def routed_http_server():
    """Factory: given a routes dict, yields (host, port, base_url) of a live server."""
    servers = []

    def _start(routes: dict):
        srv = http.server.HTTPServer(("127.0.0.1", 0), _make_routed_handler(routes))
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        servers.append(srv)
        host, port = srv.server_address
        return host, port, f"http://{host}:{port}"

    try:
        yield _start
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


@pytest.fixture
def tcp_server():
    """Factory: given a responder(bytes)->bytes, yields (host, port) of a raw TCP server."""
    import socket

    socks = []
    stop = threading.Event()

    def _start(responder):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(8)
        socks.append(s)
        host, port = s.getsockname()

        def _serve():
            while not stop.is_set():
                try:
                    conn, _ = s.accept()
                except OSError:
                    return
                try:
                    data = conn.recv(4096)
                    reply = responder(data)
                    if reply:
                        conn.sendall(reply)
                except OSError:
                    pass
                finally:
                    conn.close()

        threading.Thread(target=_serve, daemon=True).start()
        return host, port

    try:
        yield _start
    finally:
        stop.set()
        for s in socks:
            s.close()


@pytest.fixture
def redis_server():
    """A minimal stateful fake Redis (PING/SET/GET/DEL) over RESP. Yields (host, port).

    State persists across connections (real Redis behaviour) so the prover's
    SET (conn 1) -> GET (conn 2) -> DEL (conn 3) canary round-trip works.
    """
    import socket

    store: dict = {}
    socks = []
    stop = threading.Event()

    def _parse(data: bytes):
        # Parse a RESP array of bulk strings into a list of byte tokens.
        try:
            lines = data.split(b"\r\n")
            if not lines or not lines[0].startswith(b"*"):
                return [p for p in data.strip().split() if p]
            out, i = [], 1
            while i < len(lines):
                if lines[i].startswith(b"$"):
                    i += 1
                    if i < len(lines):
                        out.append(lines[i])
                i += 1
            return out
        except Exception:
            return []

    def _handle(tokens):
        if not tokens:
            return b"-ERR\r\n"
        cmd = tokens[0].upper()
        if cmd == b"PING":
            return b"+PONG\r\n"
        if cmd == b"SET" and len(tokens) >= 3:
            store[tokens[1]] = tokens[2]
            return b"+OK\r\n"
        if cmd == b"GET" and len(tokens) >= 2:
            v = store.get(tokens[1])
            if v is None:
                return b"$-1\r\n"
            return b"$%d\r\n%s\r\n" % (len(v), v)
        if cmd == b"DEL" and len(tokens) >= 2:
            existed = 1 if store.pop(tokens[1], None) is not None else 0
            return b":%d\r\n" % existed
        return b"-ERR unknown\r\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    socks.append(s)
    host, port = s.getsockname()

    def _serve():
        while not stop.is_set():
            try:
                conn, _ = s.accept()
            except OSError:
                return
            try:
                data = conn.recv(4096)
                conn.sendall(_handle(_parse(data)))
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    try:
        yield host, port
    finally:
        stop.set()
        for sk in socks:
            sk.close()
