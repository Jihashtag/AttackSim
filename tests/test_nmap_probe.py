"""Phase 2 tests: nmap_probe XML parsing, NSE allow-list, and absent-binary skip."""
from __future__ import annotations

import pytest

from exploits import nmap_probe
from targets import model


_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis key-value store" version="6.0.5"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_returns_only_open_ports():
    services = nmap_probe.parse_nmap_xml(_SAMPLE_XML)
    ports = sorted(s["port"] for s in services)
    assert ports == [22, 6379]
    ssh = next(s for s in services if s["port"] == 22)
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.2p1"


def test_parse_nmap_xml_bad_input_is_safe():
    assert nmap_probe.parse_nmap_xml("not xml at all") == []


# --------------------------------------------------------------------- NSE allow-list
def test_validate_nse_allows_safe_categories():
    assert nmap_probe.validate_nse_scripts("safe,version") == ["safe", "version"]


@pytest.mark.parametrize("spec", [
    "intrusive",
    "exploit",
    "dos",
    "brute",
    "vuln",
    "http-vuln-cve2017-5638",   # concrete script matching a forbidden family
    "ssh-brute",
    "smb-os-discovery,exploit",  # one bad token poisons the set
])
def test_validate_nse_rejects_forbidden(spec):
    with pytest.raises(nmap_probe.NseRejected):
        nmap_probe.validate_nse_scripts(spec)


def test_validate_nse_rejects_wildcard():
    with pytest.raises(nmap_probe.NseRejected):
        nmap_probe.validate_nse_scripts("http-*")


# --------------------------------------------------------------------- argv builder
def test_build_argv_is_connect_scan_no_syn():
    argv = nmap_probe.build_argv(["10.0.0.5"], [22, 80])
    assert "-sT" in argv          # connect scan (rootless)
    assert "-sS" not in argv      # never a raw SYN scan
    assert "-sV" in argv
    assert "10.0.0.5" in argv
    # ports joined
    i = argv.index("-p")
    assert argv[i + 1] == "22,80"


def test_build_argv_rejects_unsafe_nse_before_exec():
    with pytest.raises(nmap_probe.NseRejected):
        nmap_probe.build_argv(["10.0.0.5"], [22], nse_scripts="intrusive")


def test_build_argv_includes_safe_nse():
    argv = nmap_probe.build_argv(["10.0.0.5"], [22], nse_scripts="safe,discovery")
    i = argv.index("--script")
    assert argv[i + 1] == "safe,discovery"


# --------------------------------------------------------------------- run() behaviour
def test_run_skips_cleanly_when_nmap_absent(monkeypatch):
    monkeypatch.setattr(nmap_probe.toolrunner, "available", lambda b: False)
    t = model.resolve(cidr="10.0.0.0/30", ports="22")
    res = nmap_probe.run(t)
    assert res.exploited is False
    assert res.tool_available is False
    assert any("not installed" in f.title for f in res.findings)


def test_run_parses_services_with_fake_nmap(monkeypatch):
    monkeypatch.setattr(nmap_probe.toolrunner, "available", lambda b: True)

    class _TR:
        available = True
        timed_out = False
        error = ""
        output = _SAMPLE_XML

    monkeypatch.setattr(nmap_probe.toolrunner, "run_tool",
                        lambda *a, **k: _TR())
    t = model.resolve(positional="10.0.0.5:22,80,6379")
    res = nmap_probe.run(t)
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "OpenSSH" in titles
    assert "Redis" in titles


def test_run_rejected_nse_does_not_invoke_nmap(monkeypatch):
    monkeypatch.setattr(nmap_probe.toolrunner, "available", lambda b: True)
    called = {"ran": False}

    def _boom(*a, **k):
        called["ran"] = True
        raise AssertionError("nmap must not run with rejected NSE")

    monkeypatch.setattr(nmap_probe.toolrunner, "run_tool", _boom)
    t = model.resolve(positional="10.0.0.5:22")
    t.nse_scripts = "exploit"
    res = nmap_probe.run(t)
    assert called["ran"] is False
    assert res.exploited is False
    assert any("rejected" in f.title.lower() for f in res.findings)


def test_supports():
    assert nmap_probe.SUPPORTS == {"hostport", "netrange", "url"}
