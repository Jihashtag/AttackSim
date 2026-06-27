"""Phase-5 tests: MQTT/AMQP broker auth (B5), port-level scope (D4), targets-file (D5),
and egress-proxy routing (D6). Offline only."""
from __future__ import annotations

import socket
import struct
import threading

import main
from exploits import mqtt_amqp_probe, netutil
from sandbox.scope_guard import ScopeGuard


class _T:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ports = [port]
        self.scope_guard = None


# ---------------------------------------------------------------------------
# B5: MQTT anonymous CONNECT accepted.
# ---------------------------------------------------------------------------
def test_mqtt_anonymous_accept(tcp_server, monkeypatch):
    def responder(data: bytes) -> bytes:
        # Expect a CONNECT (0x10); reply CONNACK accepted (rc=0x00).
        if data and data[0] == 0x10:
            return bytes([0x20, 0x02, 0x00, 0x00])
        return b""

    host, port = tcp_server(responder)
    monkeypatch.setattr(mqtt_amqp_probe, "_PORTS", {"mqtt": (port,)})
    res = mqtt_amqp_probe.run(_T(host, port))
    assert res.exploited is True
    assert any("ANONYMOUS" in f.title for f in res.findings)


def test_mqtt_auth_required(tcp_server, monkeypatch):
    def responder(data: bytes) -> bytes:
        if data and data[0] == 0x10:
            return bytes([0x20, 0x02, 0x00, 0x05])  # rc=5 not authorized
        return b""

    host, port = tcp_server(responder)
    monkeypatch.setattr(mqtt_amqp_probe, "_PORTS", {"mqtt": (port,)})
    res = mqtt_amqp_probe.run(_T(host, port))
    assert res.exploited is False
    assert any(f.severity == "INFO" and "requires authentication" in f.title
               for f in res.findings)


# ---------------------------------------------------------------------------
# B5: AMQP default-credential (guest:guest) accepted — multi-step handshake.
# ---------------------------------------------------------------------------
def _amqp_server(accept: bool):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    host, port = srv.getsockname()

    def _frame(class_id, method_id):
        payload = struct.pack(">HH", class_id, method_id) + b"\x00\x00\x00\x00"
        return struct.pack(">BHI", 1, 0, len(payload)) + payload + b"\xce"

    def _serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.recv(64)                      # protocol header
            conn.sendall(_frame(10, 10))       # Connection.Start
            conn.recv(4096)                    # StartOk
            conn.sendall(_frame(10, 30) if accept else _frame(10, 50))
            conn.recv(4096)                    # client Close
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, host, port


def test_amqp_default_creds_accept(monkeypatch):
    srv, host, port = _amqp_server(accept=True)
    try:
        monkeypatch.setattr(mqtt_amqp_probe, "_PORTS", {"amqp": (port,)})
        res = mqtt_amqp_probe.run(_T(host, port))
        assert res.exploited is True
        assert any("default credentials" in f.title for f in res.findings)
    finally:
        srv.close()


def test_amqp_default_creds_rejected(monkeypatch):
    srv, host, port = _amqp_server(accept=False)
    try:
        monkeypatch.setattr(mqtt_amqp_probe, "_PORTS", {"amqp": (port,)})
        res = mqtt_amqp_probe.run(_T(host, port))
        assert res.exploited is False
        assert any(f.severity == "INFO" and "rejects default" in f.title
                   for f in res.findings)
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# D4: port-level scope.
# ---------------------------------------------------------------------------
def test_scope_port_restriction_host():
    g = ScopeGuard.from_specs(["host.example.com:8080"], intensity="intrusive")
    assert g.in_scope("host.example.com:8080") is True
    assert g.in_scope("https://host.example.com:8080/x") is True
    assert g.in_scope("host.example.com:9090") is False
    # Port unknown => not blocked on port grounds (host still in scope).
    assert g.in_scope("host.example.com") is True


def test_scope_no_port_means_all_ports():
    g = ScopeGuard.from_specs(["host.example.com"], intensity="intrusive")
    assert g.in_scope("host.example.com:9090") is True
    assert g.in_scope("host.example.com:1") is True


def test_scope_cidr_port_restriction():
    g = ScopeGuard.from_specs(["10.0.0.0/24:443"], intensity="intrusive")
    assert g.in_scope("10.0.0.5:443") is True
    assert g.in_scope("10.0.0.5:80") is False
    assert g.in_scope("10.0.1.5:443") is False  # outside CIDR


def test_scope_authorize_blocks_wrong_port():
    g = ScopeGuard.from_specs(["10.0.0.5:22"], intensity="intrusive")
    ok, _ = g.authorize("10.0.0.5:22")
    assert ok is True
    ok, _ = g.authorize("10.0.0.5:23")
    assert ok is False


# ---------------------------------------------------------------------------
# D5: targets-file resolution.
# ---------------------------------------------------------------------------
def test_load_targets_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# comment\n10.0.0.5:8080\nexample.com:443\n\n")

    class _Args:
        targets_file = str(f)
        jwt = None
        api_key = None
        ports = None
        auth_header = None
        auth_scheme = None
        max_hosts = None

    targets = main._load_targets_file(_Args(), None)
    assert len(targets) == 2
    hosts = {t.host for t in targets}
    assert "10.0.0.5" in hosts and "example.com" in hosts


def test_load_targets_file_capped(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "TARGETS_FILE_MAX", 2, raising=False)
    f = tmp_path / "t.txt"
    f.write_text("a.com:1\nb.com:2\nc.com:3\n")

    class _Args:
        targets_file = str(f)
        jwt = api_key = ports = auth_header = auth_scheme = max_hosts = None

    targets = main._load_targets_file(_Args(), None)
    assert len(targets) == 2


# ---------------------------------------------------------------------------
# D6: egress proxy routing.
# ---------------------------------------------------------------------------
def test_proxy_handler_wiring():
    try:
        netutil.set_default_proxy("http://127.0.0.1:9")
        h = netutil._proxy_handler(None)
        assert h.proxies.get("http") == "http://127.0.0.1:9"
        assert h.proxies.get("https") == "http://127.0.0.1:9"
        # Explicit per-call proxy overrides the default.
        h2 = netutil._proxy_handler("http://127.0.0.1:10")
        assert h2.proxies.get("http") == "http://127.0.0.1:10"
    finally:
        netutil.set_default_proxy(None)
    assert netutil._proxy_handler(None).proxies == {}


def test_proxy_routes_requests():
    import http.server

    seen = []

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.append(self.path)         # absolute-form URI when proxied
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"VIA-PROXY")

        def log_message(self, *_a):
            pass

    proxy = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    p_host, p_port = proxy.server_address
    try:
        status, body, _ = netutil.http_get(
            "http://example.invalid/secret", proxy=f"http://{p_host}:{p_port}")
        assert status == 200 and body == "VIA-PROXY"
        assert any("example.invalid" in s for s in seen)
    finally:
        proxy.shutdown(); proxy.server_close()
