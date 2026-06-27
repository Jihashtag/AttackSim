"""Offline tests for ssh-probe and smtp-probe using scripted TCP servers."""
from __future__ import annotations

import socket
import struct
import threading
import types

from exploits import smtp_probe, ssh_probe


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


def _hp_target(port):
    return types.SimpleNamespace(host="127.0.0.1", port=port, ports=[port],
                                 scope_guard=None, budget=None)


# ---------------------------------------------------------------------------
# SSH: weak algorithms in KEXINIT + old banner.
# ---------------------------------------------------------------------------
def _namelist(items):
    raw = ",".join(items).encode()
    return struct.pack("!I", len(raw)) + raw


def _kexinit_packet():
    cookie = b"\x00" * 16
    payload = bytes([20]) + cookie
    payload += _namelist(["curve25519-sha256", "diffie-hellman-group14-sha1"])  # kex (weak)
    payload += _namelist(["ssh-ed25519", "ssh-rsa"])                            # hostkey (weak)
    payload += _namelist(["aes256-ctr", "aes128-cbc"])                          # enc c2s (weak)
    payload += _namelist(["aes256-ctr", "aes128-cbc"])                          # enc s2c
    payload += _namelist(["hmac-sha2-256", "hmac-md5"])                         # mac c2s (weak)
    payload += _namelist(["hmac-sha2-256", "hmac-md5"])                         # mac s2c
    payload += _namelist(["none"])                                              # comp c2s
    payload += _namelist(["none"])                                              # comp s2c
    payload += _namelist([""])                                                  # lang c2s
    payload += _namelist([""])                                                  # lang s2c
    payload += b"\x00" + b"\x00\x00\x00\x00"  # first_kex_follows + reserved
    pad_len = 8
    rest = bytes([pad_len]) + payload + b"\x00" * pad_len
    return struct.pack("!I", len(rest)) + rest


def test_ssh_probe_flags_weak_algorithms(monkeypatch):
    def handler(conn):
        conn.sendall(b"SSH-2.0-OpenSSH_6.6p1 Ubuntu\r\n")
        conn.recv(256)  # client identification
        conn.sendall(_kexinit_packet())

    port, stop = _tcp_server(handler)
    monkeypatch.setattr(ssh_probe, "_PORTS", (port,))
    try:
        res = ssh_probe.run(_hp_target(port))
    finally:
        stop()
    tags = {t for f in res.findings for t in f.tags}
    assert "weak-kex" in tags
    assert "weak-hostkey" in tags
    assert "weak-cipher" in tags
    assert "weak-mac" in tags
    # Old OpenSSH (pre-7.4) banner flagged LOW.
    assert any("exposed" in f.title.lower() and f.severity == "LOW" for f in res.findings)


# ---------------------------------------------------------------------------
# SMTP: open relay (MAIL/RCPT accepted, no STARTTLS).
# ---------------------------------------------------------------------------
def _smtp_relay_handler(conn):
    conn.sendall(b"220 mail.test ESMTP\r\n")
    buf = b""
    while True:
        try:
            data = conn.recv(1024)
        except OSError:
            return
        if not data:
            return
        buf += data
        # Respond per command line received.
        while b"\r\n" in buf:
            line, buf = buf.split(b"\r\n", 1)
            up = line.upper()
            if up.startswith(b"EHLO"):
                conn.sendall(b"250-mail.test\r\n250 SIZE 10240000\r\n")  # no STARTTLS
            elif up.startswith(b"MAIL FROM"):
                conn.sendall(b"250 OK\r\n")
            elif up.startswith(b"RCPT TO"):
                conn.sendall(b"250 OK\r\n")  # accepts external recipient -> open relay
            elif up.startswith(b"RSET"):
                conn.sendall(b"250 OK\r\n")
            elif up.startswith(b"QUIT"):
                conn.sendall(b"221 Bye\r\n")
                return
            else:
                conn.sendall(b"250 OK\r\n")


def test_smtp_open_relay_detected(monkeypatch):
    port, stop = _tcp_server(_smtp_relay_handler)
    monkeypatch.setattr(smtp_probe, "_PLAIN_PORTS", (port,))
    monkeypatch.setattr(smtp_probe, "_TLS_PORTS", ())
    try:
        res = smtp_probe.run(_hp_target(port))
    finally:
        stop()
    assert res.exploited is True
    assert any("open relay" in f.title.lower() and f.severity == "HIGH" for f in res.findings)
    # Also flags the lack of STARTTLS.
    assert any("starttls" in f.title.lower() for f in res.findings)
