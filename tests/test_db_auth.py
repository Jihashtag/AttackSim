"""Offline tests for the raw database-protocol auth module (db-auth).

Tiny scripted TCP servers stand in for PostgreSQL and MySQL so the wire-protocol logic
(trust-auth detection, blank-password handshake) is exercised deterministically. The
module's ``_PORTS`` map is monkeypatched so it probes the throwaway test port.
"""
from __future__ import annotations

import socket
import struct
import threading
import types

from exploits import db_auth


def _tcp_server(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_wrap, args=(conn,), daemon=True).start()

    def _wrap(conn):
        try:
            handler(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return port, (lambda: (stop.set(), srv.close()))


def _target(host, port):
    return types.SimpleNamespace(host=host, port=port, ports=[port],
                                 scope_guard=None, budget=None)


def _read_pg_startup(conn):
    head = conn.recv(4)
    if len(head) < 4:
        return
    length = struct.unpack("!I", head)[0]
    conn.recv(max(0, length - 4))


# ---------------------------------------------------------------------------
# PostgreSQL trust auth (AuthenticationOk, type 0) => CRITICAL.
# ---------------------------------------------------------------------------
def test_postgres_trust_auth_is_critical(monkeypatch):
    def handler(conn):
        _read_pg_startup(conn)
        conn.sendall(b"R" + struct.pack("!I", 8) + struct.pack("!I", 0))  # AuthenticationOk

    port, stop = _tcp_server(handler)
    monkeypatch.setattr(db_auth, "_PORTS", {"postgres": (port,)})
    try:
        res = db_auth.run(_target("127.0.0.1", port))
    finally:
        stop()
    assert res.exploited is True
    assert any(f.severity == "CRITICAL" and "trust" in f.title.lower() for f in res.findings)


def test_postgres_auth_required_is_low(monkeypatch):
    def handler(conn):
        _read_pg_startup(conn)
        # AuthenticationMD5Password (type 5) + 4-byte salt.
        conn.sendall(b"R" + struct.pack("!I", 12) + struct.pack("!I", 5) + b"salt")

    port, stop = _tcp_server(handler)
    monkeypatch.setattr(db_auth, "_PORTS", {"postgres": (port,)})
    try:
        res = db_auth.run(_target("127.0.0.1", port))
    finally:
        stop()
    assert res.exploited is False
    assert any("postgresql" in f.title.lower() and f.severity == "LOW" for f in res.findings)


# ---------------------------------------------------------------------------
# MySQL blank-password root (OK packet) => CRITICAL.
# ---------------------------------------------------------------------------
def _mysql_greeting() -> bytes:
    payload = bytes([10]) + b"8.0.30\x00" + b"\x00" * 30
    n = len(payload)
    return bytes([n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, 0]) + payload


def test_mysql_blank_password_root_is_critical(monkeypatch):
    def handler(conn):
        conn.sendall(_mysql_greeting())
        head = conn.recv(4)  # client handshake response header
        if len(head) == 4:
            length = head[0] | (head[1] << 8) | (head[2] << 16)
            conn.recv(length)
        ok = b"\x00\x00\x00\x02\x00"  # minimal OK packet (payload first byte 0x00)
        n = len(b"\x00\x00\x00")
        conn.sendall(bytes([3, 0, 0, 2]) + b"\x00\x00\x00")  # OK payload starts with 0x00

    port, stop = _tcp_server(handler)
    monkeypatch.setattr(db_auth, "_PORTS", {"mysql": (port,)})
    try:
        res = db_auth.run(_target("127.0.0.1", port))
    finally:
        stop()
    assert res.exploited is True
    assert any(f.severity == "CRITICAL" and "blank password" in f.title.lower()
               for f in res.findings)


def test_mysql_password_required_is_low(monkeypatch):
    def handler(conn):
        conn.sendall(_mysql_greeting())
        head = conn.recv(4)
        if len(head) == 4:
            length = head[0] | (head[1] << 8) | (head[2] << 16)
            conn.recv(length)
        # ERR packet: payload first byte 0xFF.
        conn.sendall(bytes([3, 0, 0, 2]) + b"\xff\x15\x04")

    port, stop = _tcp_server(handler)
    monkeypatch.setattr(db_auth, "_PORTS", {"mysql": (port,)})
    try:
        res = db_auth.run(_target("127.0.0.1", port))
    finally:
        stop()
    assert res.exploited is False
    assert any("mysql" in f.title.lower() and f.severity == "LOW" for f in res.findings)
