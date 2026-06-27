"""Tests for the live network modules against a local fixture server."""
from urllib.parse import urlsplit

from exploits import cred_tester, http_probe, port_probe


def test_http_probe_reaches_local_server(http_server, fake_target):
    t = fake_target(kind="url", url=http_server, raw=http_server)
    res = http_probe.run(t)
    # Plaintext + unauthenticated 200 => the attacker "wins".
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "plaintext HTTP" in titles


def test_http_probe_unreachable_is_skip(fake_target):
    t = fake_target(kind="url", url="http://127.0.0.1:1", raw="x")
    res = http_probe.run(t)
    assert res.exploited is False
    assert res.error


def test_port_probe_finds_open_port(http_server, fake_target):
    parts = urlsplit(http_server)
    t = fake_target(kind="hostport", host=parts.hostname, port=parts.port)
    res = port_probe.run(t)
    assert res.exploited is True
    assert any(str(parts.port) in f.evidence for f in res.findings)


def test_port_probe_closed_port_mitigated(fake_target):
    t = fake_target(kind="hostport", host="127.0.0.1", port=1)
    res = port_probe.run(t)
    assert res.exploited is False


def test_cred_tester_offline_classifies(fake_target):
    t = fake_target(kind="creds", jwt="abc", url=None)
    res = cred_tester.run(t)
    assert res.exploited is False
    assert any("no URL" in f.title for f in res.findings)


def test_cred_tester_custom_header_label(fake_target):
    t = fake_target(kind="creds", jwt="abc", auth_header="X-Auth-Token", url=None)
    res = cred_tester.run(t)
    assert any("X-Auth-Token" in f.evidence for f in res.findings)
