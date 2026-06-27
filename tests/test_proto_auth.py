"""Tests for the protocol auth-surface module (proto_auth): FTP/LDAP/SMB/SNMP/NFS."""
from __future__ import annotations

import socket
import struct
import threading

from exploits import proto_auth
from sandbox import scope_guard


def _target(host, port, *, scope=("127.0.0.1",)):
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    t.raw = f"{host}:{port}"
    t.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity="intrusive")
    return t


# ---------------------------------------------------------------------------
# FTP anonymous (uses the raw tcp_server with a stateful responder).
# ---------------------------------------------------------------------------
def test_ftp_anonymous_login_detected():
    # A minimal FTP server: greet 220, accept USER, return 230 on PASS.
    socks = []

    def _serve(s):
        conn, _ = s.accept()
        conn.sendall(b"220 test ftp\r\n")
        conn.recv(128)  # USER anonymous
        conn.sendall(b"331 send password\r\n")
        conn.recv(128)  # PASS ...
        conn.sendall(b"230 login ok\r\n")
        conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    socks.append(s)
    host, port = s.getsockname()
    threading.Thread(target=_serve, args=(s,), daemon=True).start()
    try:
        res = proto_auth._ftp(_target(host, port), host, port)
        assert any("ANONYMOUS login" in f.title for f in res)
    finally:
        s.close()


def test_ftp_no_anonymous():
    def _serve(s):
        conn, _ = s.accept()
        conn.sendall(b"220 test ftp\r\n")
        conn.recv(128)
        conn.sendall(b"331 send password\r\n")
        conn.recv(128)
        conn.sendall(b"530 login incorrect\r\n")
        conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    host, port = s.getsockname()
    threading.Thread(target=_serve, args=(s,), daemon=True).start()
    try:
        res = proto_auth._ftp(_target(host, port), host, port)
        assert res == []
    finally:
        s.close()


# ---------------------------------------------------------------------------
# LDAP anonymous bind.
# ---------------------------------------------------------------------------
def test_ldap_anonymous_bind_detected():
    # Respond with a BindResponse: 0x61 ... resultCode 0x0a 0x01 0x00 (success).
    bind_response = bytes([0x30, 0x0c, 0x02, 0x01, 0x01,
                           0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])

    def _serve(s):
        conn, _ = s.accept()
        conn.recv(128)
        conn.sendall(bind_response)
        conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    host, port = s.getsockname()
    threading.Thread(target=_serve, args=(s,), daemon=True).start()
    try:
        res = proto_auth._ldap(_target(host, port), host, port)
        assert any("ANONYMOUS bind" in f.title for f in res)
    finally:
        s.close()


def test_ldap_bind_rejected():
    # resultCode 0x31 (invalidCredentials) -> no finding.
    bind_response = bytes([0x30, 0x0c, 0x02, 0x01, 0x01,
                           0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00])

    def _serve(s):
        conn, _ = s.accept()
        conn.recv(128)
        conn.sendall(bind_response)
        conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    host, port = s.getsockname()
    threading.Thread(target=_serve, args=(s,), daemon=True).start()
    try:
        res = proto_auth._ldap(_target(host, port), host, port)
        assert res == []
    finally:
        s.close()


# ---------------------------------------------------------------------------
# SNMP default community (UDP).
# ---------------------------------------------------------------------------
def test_snmp_default_community_detected():
    # UDP server: reply to any GET with a GetResponse PDU (0xa2) + sysDescr string.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    host, port = sock.getsockname()
    stop = threading.Event()

    def _serve():
        sock.settimeout(1.0)
        while not stop.is_set():
            try:
                _data, addr = sock.recvfrom(2048)
            except OSError:
                continue
            # GetResponse PDU tag 0xa2 + a printable OCTET STRING 'TestRouter'
            descr = b"TestRouter v1.0"
            reply = bytes([0x30, 0x20, 0xa2, 0x1e, 0x04, len(descr)]) + descr
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass

    threading.Thread(target=_serve, daemon=True).start()
    try:
        res = proto_auth._snmp(_target(host, port), host, port)
        assert any("default community" in f.title for f in res)
        assert any("TestRouter" in f.evidence for f in res)
    finally:
        stop.set()
        sock.close()


# ---------------------------------------------------------------------------
# SMB2 signing-not-required.
# ---------------------------------------------------------------------------
def test_smb_signing_not_required_detected():
    def _serve(s):
        conn, _ = s.accept()
        conn.recv(512)
        # NBT header + SMB2 header (64B) with SecurityMode=0x0001 (enabled, NOT required).
        smb2 = b"\xfeSMB" + b"\x00" * 60  # header padded to 64
        # NEGOTIATE response: StructureSize(2)=65, SecurityMode(2)=0x0001
        nego = struct.pack("<HH", 65, 0x0001) + b"\x00" * 60
        body = smb2 + nego
        nbt = b"\x00" + struct.pack(">I", len(body))[1:]
        conn.sendall(nbt + body)
        conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    host, port = s.getsockname()
    threading.Thread(target=_serve, args=(s,), daemon=True).start()
    try:
        res = proto_auth._smb(_target(host, port), host, port)
        assert any("signing NOT required" in f.title for f in res)
    finally:
        s.close()


# ---------------------------------------------------------------------------
# scope gating + metadata + packet builders
# ---------------------------------------------------------------------------
def test_proto_auth_out_of_scope_skips():
    # No server needed: out-of-scope host returns [] immediately.
    assert proto_auth._ftp(_target("127.0.0.1", 21, scope=("10.0.0.1",)), "127.0.0.1", 21) == []
    assert proto_auth._snmp(_target("127.0.0.1", 161, scope=("10.0.0.1",)), "127.0.0.1", 161) == []


def test_snmp_packet_is_well_formed():
    pkt = proto_auth._snmp_get_packet("public")
    assert pkt[0] == 0x30           # SEQUENCE
    assert b"public" in pkt         # community embedded
    assert bytes([0xa0]) in pkt     # GetRequest PDU tag


def test_proto_auth_metadata():
    assert proto_auth.SUPPORTS == {"hostport"}
    assert proto_auth.INTENSITY == "intrusive"
