"""Phase 1 tests: NETRANGE target parsing + the host-sweep discovery module."""
from __future__ import annotations

import socket

import pytest

from targets import model
from exploits import host_sweep


# --------------------------------------------------------------------------- parsing
def test_parse_hosts_cidr_drops_network_and_broadcast():
    hosts = model.parse_hosts("10.0.0.0/30")
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_parse_hosts_slash31_keeps_both():
    hosts = model.parse_hosts("10.0.0.0/31")
    assert hosts == ["10.0.0.0", "10.0.0.1"]


def test_parse_hosts_last_octet_range():
    assert model.parse_hosts("10.0.0.5-8") == [
        "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]


def test_parse_hosts_full_ip_range_crossing_octet():
    hosts = model.parse_hosts("10.0.0.254-10.0.1.1")
    assert hosts == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]


def test_parse_hosts_reversed_range_is_normalised():
    assert model.parse_hosts("10.0.0.8-5") == [
        "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]


def test_parse_hosts_respects_host_cap():
    with pytest.raises(model.TargetError) as exc:
        model.parse_hosts("10.0.0.0/8")
    assert "cap" in str(exc.value).lower()


def test_parse_hosts_custom_cap():
    with pytest.raises(model.TargetError):
        model.parse_hosts("10.0.0.0/24", max_hosts=10)


def test_looks_like_netrange():
    assert model.looks_like_netrange("10.0.0.0/24")
    assert model.looks_like_netrange("10.0.0.5-20")
    assert model.looks_like_netrange("10.0.0.1-10.0.0.9")
    assert not model.looks_like_netrange("example.com")
    assert not model.looks_like_netrange("10.0.0.1")  # single host, not a range


# --------------------------------------------------------------------------- resolve
def test_resolve_cidr_flag_with_ports():
    t = model.resolve(cidr="192.168.1.0/29", ports="80,443")
    assert t.kind == model.NETRANGE
    assert t.ports == [80, 443]
    assert t.host == t.hosts[0]
    assert t.port == 80
    assert "netrange:" in t.describe()


def test_resolve_positional_netrange_autodetect_inline_ports():
    t = model.resolve(positional="10.0.0.0/28:6379")
    assert t.kind == model.NETRANGE
    assert t.ports == [6379]
    assert len(t.hosts) == 14  # /28 minus network+broadcast


def test_resolve_netrange_default_ports_when_none_given():
    t = model.resolve(cidr="10.0.0.0/30")
    assert t.ports == list(model._NETRANGE_DEFAULT_PORTS)


def test_resolve_product_cap_rejects_wide_scan():
    with pytest.raises(model.TargetError) as exc:
        model.resolve(cidr="10.0.0.0/16")
    assert "probe" in str(exc.value).lower() or "cap" in str(exc.value).lower()


# --------------------------------------------------------------------------- host_sweep
def test_host_sweep_finds_live_and_skips_dead(tcp_server, monkeypatch):
    host, port = tcp_server(lambda data: b"")
    # Restrict the probe set to the live port so the test is deterministic & fast.
    monkeypatch.setattr(host_sweep, "_PROBE_PORTS", (port,))
    # A guaranteed-closed port on loopback for the "dead" host.
    closed = _free_port()

    target = model.resolve(cidr=f"127.0.0.1-127.0.0.1", ports=str(port))
    # Hand-build a two-host target: one live (real server), one dead.
    target.hosts = ["127.0.0.1"]
    res = host_sweep.run(target)
    assert res.exploited is True
    assert any("Live host" in f.title for f in res.findings)
    assert target.live_hosts == ["127.0.0.1"]


def test_host_sweep_no_live_hosts_is_not_exploited(monkeypatch):
    closed = _free_port()
    monkeypatch.setattr(host_sweep, "_PROBE_PORTS", (closed,))
    target = model.resolve(cidr="127.0.0.1-127.0.0.1", ports=str(closed))
    res = host_sweep.run(target)
    assert res.exploited is False
    assert res.findings  # still emits an INFO summary
    assert target.live_hosts == []


def test_host_sweep_empty_hosts_returns_error():
    target = model.Target(kind=model.NETRANGE, raw="x", hosts=[], ports=[80])
    res = host_sweep.run(target)
    assert res.exploited is False
    assert res.error


def test_host_sweep_supports_only_netrange():
    assert host_sweep.SUPPORTS == {"netrange"}


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
