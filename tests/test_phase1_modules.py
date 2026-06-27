"""Tests for the Phase-1 detective recon modules.

Covers: dnsutil (encode/parse), dns_recon, subdomain_takeover, graphql_probe,
api_spec_discovery, public_storage_enum, etcd_probe.
"""
from __future__ import annotations

import json

import pytest

from exploits import (api_spec_discovery, dns_recon, dnsutil, etcd_probe,
                      graphql_probe, public_storage_enum, subdomain_takeover)
from sandbox import scope_guard


def _target(*, url=None, host=None, port=None, raw="", scope=("127.0.0.1",),
            intensity="active"):
    t = type("T", (), {})()
    t.kind = "url" if url else "hostport"
    t.url = url
    t.host = host
    t.port = port
    t.ports = [port] if port else []
    t.raw = raw or (url or "") or (f"{host}:{port}" if host else "")
    t.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity=intensity)
    t.canary_url = None
    t.auth_headers = lambda: {}
    return t


# ---------------------------------------------------------------------------
# dnsutil
# ---------------------------------------------------------------------------
def test_dnsutil_encode_name():
    assert dnsutil._encode_name("a.bc") == b"\x01a\x02bc\x00"
    assert dnsutil._encode_name("") == b"\x00"


def test_dnsutil_build_and_parse_roundtrip():
    q = dnsutil.build_query("example.com", "A", txid=0x1234)
    assert q[:2] == b"\x12\x34"
    # Hand-build a response: header (ANCOUNT=1) + question + one A answer (compressed name).
    import struct
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = dnsutil._encode_name("example.com") + struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    parsed = dnsutil.parse_message(header + question + answer)
    assert parsed["rcode"] == 0
    assert parsed["answers"][0]["data"] == "93.184.216.34"


# ---------------------------------------------------------------------------
# dns_recon
# ---------------------------------------------------------------------------
def test_dns_recon_axfr(monkeypatch):
    monkeypatch.setattr(dnsutil, "system_resolvers", lambda: ["127.0.0.1"])

    def fake_resolve(name, qtype, resolver, timeout=None):
        if qtype == "NS":
            return ["ns1.example.com"]
        if qtype == "A" and name.startswith("ns1"):
            return ["10.0.0.53"]
        return []

    monkeypatch.setattr(dnsutil, "resolve", fake_resolve)
    monkeypatch.setattr(dnsutil, "axfr", lambda zone, ns, timeout=None: [
        {"name": "www.example.com", "type": "A", "data": "1.2.3.4"},
        {"name": "db.example.com", "type": "A", "data": "1.2.3.5"},
    ])
    monkeypatch.setattr(dnsutil, "query_udp",
                        lambda *a, **k: {"rcode": 3, "answers": []})

    res = dns_recon.run(_target(url="http://example.com"))
    assert res.exploited is True
    assert any("zone transfer" in f.title.lower() for f in res.findings)


def test_dns_recon_missing_spf_dmarc(monkeypatch):
    monkeypatch.setattr(dnsutil, "system_resolvers", lambda: ["127.0.0.1"])
    monkeypatch.setattr(dnsutil, "resolve", lambda *a, **k: [])
    monkeypatch.setattr(dnsutil, "axfr", lambda *a, **k: None)
    monkeypatch.setattr(dnsutil, "query_udp", lambda *a, **k: {"rcode": 3, "answers": []})
    res = dns_recon.run(_target(url="http://example.com"))
    titles = " ".join(f.title for f in res.findings).lower()
    assert "no spf" in titles and "no dmarc" in titles
    assert res.exploited is False


def test_dns_recon_out_of_scope():
    res = dns_recon.run(_target(url="http://example.com", scope=("10.10.10.10",),
                                intensity="intrusive"))
    assert any("out of scope" in f.title for f in res.findings)


# ---------------------------------------------------------------------------
# subdomain_takeover
# ---------------------------------------------------------------------------
def test_subdomain_takeover_confirmed(monkeypatch):
    monkeypatch.setattr(subdomain_takeover, "_cname_chain",
                        lambda host: ["myapp.s3.amazonaws.com"])
    monkeypatch.setattr(subdomain_takeover, "_fetch_body",
                        lambda host: "<html>NoSuchBucket: the specified bucket</html>")
    res = subdomain_takeover.run(_target(url="http://assets.example.com"))
    assert res.exploited is True
    assert any("takeover possible" in f.title.lower() for f in res.findings)


def test_subdomain_takeover_no_cname(monkeypatch):
    monkeypatch.setattr(subdomain_takeover, "_cname_chain", lambda host: [])
    res = subdomain_takeover.run(_target(url="http://www.example.com"))
    assert res.exploited is False


# ---------------------------------------------------------------------------
# graphql_probe
# ---------------------------------------------------------------------------
def test_graphql_introspection_enabled(routed_http_server):
    schema = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                        "types": [{"name": "Query", "kind": "OBJECT"},
                                  {"name": "User", "kind": "OBJECT"}]}}}).encode()
    _h, _p, base = routed_http_server({"POST /graphql": (200, schema,
                                       [("Content-Type", "application/json")])})
    res = graphql_probe.run(_target(url=base))
    assert res.exploited is True
    assert any("introspection is enabled" in f.title.lower() for f in res.findings)


def test_graphql_not_present(routed_http_server):
    _h, _p, base = routed_http_server({"GET /": (200, b"hello")})
    res = graphql_probe.run(_target(url=base))
    assert res.exploited is False
    assert res.findings == []


# ---------------------------------------------------------------------------
# api_spec_discovery
# ---------------------------------------------------------------------------
def test_api_spec_discovery_unauth_endpoint(routed_http_server):
    spec = json.dumps({
        "openapi": "3.0.0",
        "paths": {"/admin/users": {"get": {}}, "/public/info": {"get": {}}},
    }).encode()
    routes = {
        "GET /openapi.json": (200, spec, [("Content-Type", "application/json")]),
        "GET /admin/users": (200, b"[{\"user\":\"root\"}]"),
        "GET /public/info": (200, b"ok"),
    }
    _h, _p, base = routed_http_server(routes)
    res = api_spec_discovery.run(_target(url=base))
    assert res.exploited is True
    assert any("without auth" in f.title.lower() and "admin" in f.title.lower()
               for f in res.findings)


def test_api_spec_discovery_spec_only(routed_http_server):
    spec = json.dumps({"openapi": "3.0.0", "paths": {"/health": {"get": {}}}}).encode()
    routes = {
        "GET /openapi.json": (200, spec, [("Content-Type", "application/json")]),
        "GET /health": (200, b"ok"),
    }
    _h, _p, base = routed_http_server(routes)
    res = api_spec_discovery.run(_target(url=base))
    assert any("specification exposed" in f.title.lower() for f in res.findings)
    assert res.exploited is False  # /health is not sensitive


# ---------------------------------------------------------------------------
# public_storage_enum
# ---------------------------------------------------------------------------
def test_public_storage_enum_open_bucket(routed_http_server, monkeypatch):
    body = (b"<?xml version=\"1.0\"?><ListBucketResult><Contents><Key>secret.txt</Key>"
            b"</Contents></ListBucketResult>")
    _h, _p, base = routed_http_server({"GET /s3-mybucket": (200, body)})
    monkeypatch.setattr(public_storage_enum, "_S3", base + "/s3-{bucket}")
    monkeypatch.setattr(public_storage_enum, "_GCS", base + "/gcs-{bucket}")
    monkeypatch.setattr(public_storage_enum, "_AZURE", base + "/az-{bucket}")
    res = public_storage_enum.run(_target(url="http://mybucket.example.com",
                                          host="mybucket.example.com"))
    assert res.exploited is True
    assert any("public s3 bucket" in f.title.lower() for f in res.findings)


def test_public_storage_enum_read_only_guard():
    with pytest.raises(ValueError):
        public_storage_enum._assert_read_only("PUT")


# ---------------------------------------------------------------------------
# etcd_probe
# ---------------------------------------------------------------------------
def test_etcd_probe_unauth_v2(routed_http_server, monkeypatch):
    routes = {
        "GET /version": (200, b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}'),
        "GET /v2/keys/": (200, b'{"node":{"nodes":[{"key":"/a"},{"key":"/b"}]}}'),
    }
    host, port, base = routed_http_server(routes)
    monkeypatch.setattr(etcd_probe, "_PORTS", (port,))
    res = etcd_probe.run(_target(host=host, port=port, intensity="detective"))
    assert res.exploited is True
    assert any(f.severity == "CRITICAL" and "etcd" in f.title.lower() for f in res.findings)


def test_etcd_probe_metadata():
    assert etcd_probe.SUPPORTS == {"hostport"}
    assert etcd_probe.INTENSITY == "detective"
