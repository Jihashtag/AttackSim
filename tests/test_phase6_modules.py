"""Phase-6 tests: gRPC server-reflection probe (B3). Offline only.

Covers the grpcurl-preferred path (mocked via toolrunner), the native HTTP/2
fallback, and the clean INFO skip when nothing is detected.
"""
from __future__ import annotations

import socket
import threading

from exploits import grpc_reflection, toolrunner


class _T:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ports = [port]
        self.scope_guard = None


def _ToolResult(ok, available, stdout="", returncode=0):
    return toolrunner.ToolResult(ok=ok, available=available, returncode=returncode,
                                 stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# grpcurl path: reflection enabled => HIGH.
# ---------------------------------------------------------------------------
def test_grpcurl_reflection_enabled(monkeypatch):
    monkeypatch.setattr(grpc_reflection.toolrunner, "available", lambda b: True)
    monkeypatch.setattr(grpc_reflection.toolrunner, "run_tool",
                        lambda *a, **k: _ToolResult(
                            True, True,
                            stdout="myapp.OrderService\nmyapp.UserService\n"
                                   "grpc.reflection.v1alpha.ServerReflection\n"))
    res = grpc_reflection.run(_T("10.0.0.5", 50051))
    assert res.exploited is True
    f = next(f for f in res.findings if f.severity == "HIGH")
    assert "reflection" in f.title.lower() and "ENABLED" in f.title
    assert "OrderService" in f.evidence


def test_grpcurl_only_reflection_service_is_medium(monkeypatch):
    monkeypatch.setattr(grpc_reflection.toolrunner, "available", lambda b: True)
    monkeypatch.setattr(grpc_reflection.toolrunner, "run_tool",
                        lambda *a, **k: _ToolResult(
                            True, True,
                            stdout="grpc.reflection.v1alpha.ServerReflection\n"
                                   "grpc.health.v1.Health\n"))
    res = grpc_reflection.run(_T("10.0.0.5", 50051))
    assert any(f.severity == "MEDIUM" for f in res.findings)
    assert res.exploited is False


def test_grpcurl_reflection_disabled(monkeypatch):
    # grpcurl present but the call fails (reflection off / TLS) => no finding.
    monkeypatch.setattr(grpc_reflection.toolrunner, "available", lambda b: True)
    monkeypatch.setattr(grpc_reflection.toolrunner, "run_tool",
                        lambda *a, **k: _ToolResult(False, True, stdout=""))
    res = grpc_reflection.run(_T("10.0.0.5", 50051))
    assert res.findings == []
    assert res.exploited is False


# ---------------------------------------------------------------------------
# Native HTTP/2 fallback when grpcurl is absent.
# ---------------------------------------------------------------------------
def _http2_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    host, port = srv.getsockname()

    def _serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.recv(128)  # client preface + SETTINGS
            # Reply with an empty SETTINGS frame (type 0x04).
            conn.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, host, port


def test_native_http2_fallback_info(monkeypatch):
    monkeypatch.setattr(grpc_reflection.toolrunner, "available", lambda b: False)
    monkeypatch.setattr(grpc_reflection.toolrunner, "run_tool",
                        lambda *a, **k: _ToolResult(False, False))
    srv, host, port = _http2_server()
    try:
        res = grpc_reflection.run(_T(host, port))
        assert any(f.severity == "INFO" and "HTTP/2" in f.title for f in res.findings)
        assert res.exploited is False
    finally:
        srv.close()


def test_clean_skip_when_nothing_detected(monkeypatch):
    monkeypatch.setattr(grpc_reflection.toolrunner, "available", lambda b: False)
    monkeypatch.setattr(grpc_reflection.toolrunner, "run_tool",
                        lambda *a, **k: _ToolResult(False, False))
    # Point at a closed port (native HTTP/2 probe fails) => clean tool-unavailable skip.
    res = grpc_reflection.run(_T("127.0.0.1", 1))
    assert res.tool_available is False
    assert res.exploited is False
    assert res.findings == []
