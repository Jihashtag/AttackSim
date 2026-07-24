"""Tests for the infrastructure-coverage gap-closure items (service discovery audit):

2. Credential-to-pivot chaining (covered in test_v11_features.py)
3. Schema-to-execution (covered in test_v11_features.py)
4. Database cluster topology discovery (db-topology)
5. Service mesh peer topology (service-mesh-probe extension)
6. Multi-vendor detection fallbacks
7. Out-of-band management interface discovery (IPMI/iLO/DRAC)
8. IoT/embedded protocol scanning (CoAP, Modbus, OPC-UA)
9. Extended propagation depth
10. Container registry enumeration (ECR/GCR/Artifactory)
"""
from __future__ import annotations

import json

import types

from exploits import (db_topology, netutil, post_exploit, service_mesh_probe,
                      mqtt_amqp_probe, oob_management_probe, iot_protocol_probe)
import main as cli
import targets as targetmod
from sandbox import scope_guard
from exploits import cloudutil, container_registry_enum


# ---------------------------------------------------------------------------
# Item 4: database cluster topology
# ---------------------------------------------------------------------------
def test_mongo_topology_discovers_replica_set_members(fake_target, monkeypatch):
    resp = (b"\x00" * 16 +
            b"ismaster\x00setName\x00rs0\x00hosts\x0010.0.0.2:27017\x0010.0.0.3:27017\x00")
    monkeypatch.setattr(netutil, "tcp_send_recv", lambda *a, **k: resp)
    t = fake_target(kind="hostport", host="10.0.0.1", port=27017)
    t.intensity = "active"
    t.pivot_targets = []
    res = db_topology.run(t)
    assert res.exploited is True
    assert any("replica set" in f.title.lower() for f in res.findings)
    hosts = {e["host"] for e in t.pivot_targets}
    assert "10.0.0.2" in hosts and "10.0.0.3" in hosts
    assert "10.0.0.1" not in hosts  # self excluded


def test_redis_cluster_nodes_discovers_peers(fake_target, monkeypatch):
    cluster_nodes = (
        b"07c37dfd node1 10.0.0.10:6379@16379 myself,master - 0 0 0 connected\n"
        b"e7d1eecc node2 10.0.0.11:6379@16379 master - 0 1234 1 connected\n"
    )

    def fake_send_recv(host, port, payload, recv=1024, timeout=None):
        if b"CLUSTER" in payload:
            return cluster_nodes
        return b"$-1\r\n"
    monkeypatch.setattr(netutil, "tcp_send_recv", fake_send_recv)
    t = fake_target(kind="hostport", host="10.0.0.10", port=6379)
    t.intensity = "active"
    t.pivot_targets = []
    res = db_topology.run(t)
    assert res.exploited is True
    hosts = {e["host"] for e in t.pivot_targets}
    assert "10.0.0.11" in hosts
    assert "10.0.0.10" not in hosts


def test_elasticsearch_cluster_nodes_discovers_peers(fake_target, monkeypatch):
    nodes_json = json.dumps([
        {"ip": "10.0.0.20"}, {"ip": "10.0.0.21"}, {"ip": "10.0.0.22"},
    ])

    def fake_http_get(url, **kw):
        if "_cat/nodes" in url:
            return 200, nodes_json, {}
        return None, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_http_get)
    t = fake_target(kind="hostport", host="10.0.0.20", port=9200)
    t.intensity = "active"
    t.pivot_targets = []
    res = db_topology.run(t)
    assert res.exploited is True
    hosts = {e["host"] for e in t.pivot_targets}
    assert "10.0.0.21" in hosts and "10.0.0.22" in hosts


def test_db_topology_no_findings_when_single_node(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "tcp_send_recv", lambda *a, **k: b"")
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (None, "", {}))
    t = fake_target(kind="hostport", host="10.0.0.1", port=27017)
    t.intensity = "active"
    t.pivot_targets = []
    res = db_topology.run(t)
    assert res.exploited is False
    assert res.findings == []


# ---------------------------------------------------------------------------
# Item 5: service mesh topology (Consul catalog)
# ---------------------------------------------------------------------------
def test_consul_catalog_discovers_nodes(fake_target, monkeypatch):
    services_json = json.dumps({"web": [], "redis": [], "consul": []})
    nodes_json = json.dumps([
        {"Node": "node-a", "Address": "10.0.0.30"},
        {"Node": "node-b", "Address": "10.0.0.31"},
    ])

    def fake_http_get(url, **kw):
        if "/v1/catalog/services" in url:
            return 200, services_json, {}
        if "/v1/catalog/nodes" in url:
            return 200, nodes_json, {}
        return None, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_http_get)
    t = fake_target(kind="hostport", host="10.0.0.30", port=8500)
    t.intensity = "active"
    t.pivot_targets = []
    res = service_mesh_probe.run(t)
    assert res.exploited is True
    assert any("consul" in f.title.lower() and "catalog" in f.title.lower()
               for f in res.findings)
    hosts = {e["host"] for e in t.pivot_targets}
    assert "10.0.0.31" in hosts
    assert "10.0.0.30" not in hosts


# ---------------------------------------------------------------------------
# Item 6: multi-vendor detection fallback (RabbitMQ Management HTTP API)
# ---------------------------------------------------------------------------
def test_rabbitmq_management_api_default_creds(fake_target, monkeypatch):
    def fake_http_get(url, headers=None, **kw):
        if "/api/overview" in url:
            return 200, '{"rabbitmq_version": "3.11.0"}', {}
        return None, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_http_get)
    monkeypatch.setattr(mqtt_amqp_probe, "_PORTS", {})  # skip raw MQTT/AMQP socket probes
    t = fake_target(kind="hostport", host="10.0.0.40", port=15672)
    t.intensity = "intrusive"
    res = mqtt_amqp_probe.run(t)
    assert res.exploited is True
    assert any("rabbitmq" in f.title.lower() and "guest:guest" in f.title.lower()
               for f in res.findings)


# ---------------------------------------------------------------------------
# Item 7: out-of-band management interface discovery (IPMI/Redfish/iLO/iDRAC)
# ---------------------------------------------------------------------------
def test_ipmi_presence_pong_detected(fake_target, monkeypatch):
    class _FakeSocket:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def settimeout(self, t):
            pass
        def sendto(self, data, addr):
            pass
        def recvfrom(self, n):
            return (b"\x06\x00\xff\x06\x00\x00\x11\xbe\x40\x00\x00\x08\x00\x00\x11\xbe\x81\x00", ("h", 623))

    import socket as _socket
    monkeypatch.setattr(_socket, "socket", lambda *a, **k: _FakeSocket())
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (None, "", {}))
    t = fake_target(kind="hostport", host="10.0.0.50", port=623)
    t.intensity = "active"
    res = oob_management_probe.run(t)
    assert res.exploited is True
    assert any("ipmi" in f.title.lower() for f in res.findings)


def test_redfish_detected_and_intrusive_confirms_unauth_systems(fake_target, monkeypatch):
    def fake_http_get(url, **kw):
        if url.rstrip("/").endswith("/redfish/v1"):
            return 200, json.dumps({"RedfishVersion": "1.6.0", "Vendor": "Dell"}), {}
        if url.endswith("/redfish/v1/Systems"):
            return 200, '{"Members": [{"@odata.id": "/redfish/v1/Systems/1"}]}', {}
        return None, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_http_get)
    t = fake_target(kind="hostport", host="10.0.0.51", port=443)
    t.intensity = "intrusive"
    res = oob_management_probe.run(t)
    assert res.exploited is True
    assert any("redfish bmc api exposed" in f.title.lower() for f in res.findings)
    assert any("without authentication" in f.title.lower() for f in res.findings)


def test_vendor_web_banner_ilo_detected(fake_target, monkeypatch):
    def fake_http_get(url, **kw):
        if url.rstrip("/").endswith("/redfish/v1"):
            return None, "", {}
        if url.rstrip("/").endswith(":443") or url.endswith("/"):
            return 200, "<title>HPE Integrated Lights-Out</title>", {}
        return None, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_http_get)
    t = fake_target(kind="hostport", host="10.0.0.52", port=443)
    t.intensity = "active"
    res = oob_management_probe.run(t)
    assert res.exploited is True
    assert any("ilo" in f.title.lower() for f in res.findings)


# ---------------------------------------------------------------------------
# Item 8: IoT/embedded protocol discovery (CoAP, Modbus, OPC-UA)
# ---------------------------------------------------------------------------
def test_coap_probe_detects_endpoint(fake_target, monkeypatch):
    class _FakeUdpSocket:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def settimeout(self, t):
            pass
        def sendto(self, data, addr):
            pass
        def recvfrom(self, n):
            return (b"\x60\x45\x12\x34", ("h", 5683))

    import socket as _socket

    def _no_tcp(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(_socket, "socket", lambda *a, **k: _FakeUdpSocket())
    monkeypatch.setattr(_socket, "create_connection", _no_tcp)
    t = fake_target(kind="hostport", host="10.0.0.60", port=5683)
    t.intensity = "active"
    res = iot_protocol_probe.run(t)
    assert res.exploited is False  # CoAP discovery alone is MEDIUM, not exploited
    assert any("coap" in f.title.lower() for f in res.findings)


def test_modbus_probe_detects_device(fake_target, monkeypatch):
    response = bytes.fromhex("000100000005010302002a")

    class _FakeTcpSocket:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def sendall(self, data):
            pass
        def recv(self, n):
            return response

    import socket as _socket

    def _no_udp(*a, **k):
        raise OSError("no CoAP response")

    monkeypatch.setattr(_socket, "create_connection", lambda *a, **k: _FakeTcpSocket())
    monkeypatch.setattr(_socket, "socket", _no_udp)
    t = fake_target(kind="hostport", host="10.0.0.61", port=502)
    t.intensity = "active"
    res = iot_protocol_probe.run(t)
    assert res.exploited is True
    assert any("modbus" in f.title.lower() for f in res.findings)


def test_opcua_probe_detects_server(fake_target, monkeypatch):
    class _FakeTcpSocket:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def sendall(self, data):
            pass
        def recv(self, n):
            return b"ACKF\x00\x00\x00\x08"

    import socket as _socket

    def _no_udp(*a, **k):
        raise OSError("no CoAP response")

    monkeypatch.setattr(_socket, "create_connection", lambda *a, **k: _FakeTcpSocket())
    monkeypatch.setattr(_socket, "socket", _no_udp)
    t = fake_target(kind="hostport", host="10.0.0.62", port=4840)
    t.intensity = "active"
    res = iot_protocol_probe.run(t)
    assert res.exploited is True
    assert any("opc-ua" in f.title.lower() for f in res.findings)


# ---------------------------------------------------------------------------
# Item 9: propagation depth beyond the previous fixed 2-hop limit
# ---------------------------------------------------------------------------
def _stub_target(**kw):
    t = types.SimpleNamespace(pivot_targets=[])
    for k, v in kw.items():
        setattr(t, k, v)
    return t


def _args(**kw):
    base = {"assume_yes": False, "only": None}
    base.update(kw)
    return types.SimpleNamespace(**base)


def _chain_fanout(monkeypatch, *, pivot_max_depth):
    probed = []

    def fake_run_modules(mods, sub, jobs=1, resume=None):
        probed.append((sub.host, sub.pivot_depth))
        # Each hop discovers exactly one further hop, chaining indefinitely.
        next_octet = 2 + sub.pivot_depth
        sub.pivot_targets = [{"kind": "hostport", "host": f"10.0.0.{next_octet}",
                              "port": 80, "via": "chain"}]
        return []

    monkeypatch.setattr(cli, "_run_modules", fake_run_modules)
    guard = scope_guard.ScopeGuard.from_specs(["10.0.0.0/24"], intensity="intrusive")
    target = _stub_target(
        kind=targetmod.HOSTPORT, host="10.0.0.1", port=80, ports=[80],
        scope_guard=guard, intensity="proof", pivot_depth=0,
        pivot_max_depth=pivot_max_depth,
        pivot_targets=[{"kind": "hostport", "host": "10.0.0.2", "port": 80, "via": "root"}])
    cli._fanout_pivots(target, _args(), jobs=1)
    return probed


def test_fanout_pivots_respects_default_two_hop_depth(monkeypatch):
    probed = _chain_fanout(monkeypatch, pivot_max_depth=None)
    depths_reached = {d for _h, d in probed}
    assert depths_reached == {1, 2}, "default depth must stop at 2 hops"


def test_fanout_pivots_honours_extended_pivot_depth(monkeypatch):
    probed = _chain_fanout(monkeypatch, pivot_max_depth=4)
    depths_reached = {d for _h, d in probed}
    assert depths_reached == {1, 2, 3, 4}, "--pivot-depth must extend past the old 2-hop cap"


def test_pivot_depth_cli_flag_parses():
    args = cli.parse_args(["--pivot-depth", "5", "--local"])
    assert args.pivot_depth_limit == 5


# ---------------------------------------------------------------------------
# Item 10: container registry enumeration (ECR/Artifact Registry/Artifactory)
# ---------------------------------------------------------------------------
class _Cred(types.SimpleNamespace):
    pass


def test_ecr_enum_lists_repos_and_flags_public_policy(monkeypatch):
    def fake_aws_json(creds, *, service, target, payload, endpoint, region, **kw):
        if target.endswith("DescribeRepositories"):
            return 200, json.dumps({"repositories": [
                {"repositoryName": "app1"}, {"repositoryName": "app2"}]})
        if target.endswith("GetRepositoryPolicy"):
            if payload.get("repositoryName") == "app1":
                policy = {"Statement": [{"Effect": "Allow", "Principal": "*"}]}
                return 200, json.dumps({"policyText": json.dumps(policy)})
            return 400, ""
        return None, ""
    monkeypatch.setattr(cloudutil, "aws_json", fake_aws_json)

    cred = _Cred(provider="aws", region="us-east-1",
                 secret={"access_key": "AKIA...", "secret_key": "x"})
    inv = types.SimpleNamespace(credentials=[cred])
    t = types.SimpleNamespace(kind="cloud", cloud_inventory=inv, intensity="active")
    res = container_registry_enum.run(t)
    assert res.exploited is True
    assert any("ecr" in f.title.lower() and "enumerated" in f.title.lower()
               for f in res.findings)
    assert any("publicly pullable" in f.title.lower() for f in res.findings)


def test_ecr_enum_no_credentials():
    t = types.SimpleNamespace(kind="cloud", cloud_inventory=None, intensity="active")
    res = container_registry_enum.run(t)
    assert res.exploited is False
    assert res.error


def test_artifactory_unauth_repository_listing(fake_target, monkeypatch):
    repos = [{"key": "docker-local"}, {"key": "maven-local"}]

    def fake_http_get(url, **kw):
        if "/artifactory/api/repositories" in url:
            return 200, json.dumps(repos), {}
        return None, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_http_get)
    t = fake_target(kind="hostport", host="10.0.0.70", port=8081)
    t.intensity = "active"
    res = container_registry_enum.run(t)
    assert res.exploited is True
    assert any("artifactory" in f.title.lower() for f in res.findings)
