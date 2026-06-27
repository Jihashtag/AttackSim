"""Tests for foothold-relayed scanning + the proof-of-access ledger (offline).

These cover the three improvements that make multi-hop lateral movement detectable AND
provable across container / VM / server / cloud resources:

* ``sandbox/relay.py``   — run the next hop's reachability probe FROM a proven foothold
  (Docker exec relay, HTTP-CONNECT / SOCKS5 proxy relay) with a strict injection guard.
* ``sandbox/ledger.py``  — record an auditable identification path for every reached
  resource (resource, reached-from, relay, proof) and reconstruct the end-to-end chain.
* ``main`` orchestration — relay-backed subnet expansion, named cross-cloud (url) next
  hops, foothold provenance, and ledger wiring.
* ``attack_chain``       — the "proven foothold -> lateral movement" chain rule.

No network is used: Docker/HTTP are monkeypatched and the proxy relays talk to a tiny
loopback server spun up per test.
"""
from __future__ import annotations

import socket
import threading
import time
import types

import main as cli
import targets as targetmod
from exploits import access_prover, attack_chain, cloud_pivot
from exploits.base import ExploitResult, Finding
from sandbox import ledger as ledger_mod
from sandbox import relay as relay_mod
from sandbox import scope_guard


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _stub_target(**kw):
    t = types.SimpleNamespace(pivot_targets=[], proof_ledger=None, pivot_proxy=None,
                              scope_guard=None, intensity="active", reached_via="scanner",
                              via_relay=None)
    for k, v in kw.items():
        setattr(t, k, v)
    return t


def _args(**kw):
    base = {"assume_yes": False, "only": None}
    base.update(kw)
    return types.SimpleNamespace(**base)


def _serve_once(handler):
    """Bind a loopback TCP server that serves a single connection with ``handler(conn)``."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def loop():
        try:
            conn, _ = srv.accept()
            with conn:
                handler(conn)
        except OSError:
            pass
        finally:
            srv.close()

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return port, srv


# ---------------------------------------------------------------------------
# relay: classification + injection guard
# ---------------------------------------------------------------------------
def test_classify_resource_kind():
    assert relay_mod.classify_resource_kind("cloud") == "cloud"
    assert relay_mod.classify_resource_kind("hostport", port=2375) == "container"
    assert relay_mod.classify_resource_kind("hostport", port=10250) == "container"
    assert relay_mod.classify_resource_kind("hostport", port=22) == "host"
    assert relay_mod.classify_resource_kind("hostport", port=6443) == "service"
    assert relay_mod.classify_resource_kind("hostport", evidence="Docker Engine API") == "container"


def test_safe_targets_drops_injection_and_bad_ports():
    raw = [("10.0.0.10; rm -rf /", 80),   # shell metacharacters -> dropped
           ("10.0.0.11", 70000),           # port out of range -> dropped
           ("$(touch x)", 80),             # command substitution -> dropped
           ("eks.internal", 6443),         # legitimate hostname -> kept
           ("10.0.0.12", 443)]             # legitimate IP -> kept
    out = relay_mod._safe_targets(raw)
    assert ("eks.internal", 6443) in out
    assert ("10.0.0.12", 443) in out
    assert all(";" not in h and "$" not in h and " " not in h for h, _ in out)
    assert len(out) == 2


# ---------------------------------------------------------------------------
# relay: DirectRelay delegates to the shared host sweep
# ---------------------------------------------------------------------------
def test_direct_relay_delegates_to_host_sweep(monkeypatch):
    from exploits import host_sweep
    monkeypatch.setattr(host_sweep, "discover_live_hosts",
                        lambda hosts, ports=None, *, timeout=None, deadline=None: [("1.2.3.4", 80)])
    out = relay_mod.DirectRelay().sweep(["1.2.3.4"], [80])
    assert out == [("1.2.3.4", 80)]
    assert relay_mod.DirectRelay().proxy_url() is None


# ---------------------------------------------------------------------------
# relay: DockerRelay runs a connect-only container and parses OPEN markers
# ---------------------------------------------------------------------------
def test_docker_relay_sweep_parses_open_markers(monkeypatch):
    from exploits import netutil

    def fake_get(url, headers=None, *, verify=False, timeout=None, max_bytes=8192, proxy=None):
        if url.endswith("/version"):
            return 200, '{"ApiVersion":"1.45"}', {}
        if "/logs" in url:
            # The connect-only container reports the private EKS API as reachable.
            return 200, "OPEN 10.0.0.10:6443\n", {}
        return 200, "", {}

    def fake_request(url, method, **kw):
        if url.endswith("/containers/create"):
            return 201, '{"Id":"deadbeef"}', {}
        return 204, "", {}

    monkeypatch.setattr(netutil, "http_get", fake_get)
    monkeypatch.setattr(netutil, "http_request", fake_request)

    relay = relay_mod.DockerRelay("10.0.0.5", 2375)
    assert relay.available() is True
    out = relay.sweep(["10.0.0.10"], [6443, 443])
    assert out == [("10.0.0.10", 6443)], "the reachable private peer must be discovered FROM the foothold"


def test_docker_relay_sweep_empty_when_image_absent(monkeypatch):
    from exploits import netutil
    monkeypatch.setattr(netutil, "http_get",
                        lambda url, headers=None, **kw: (200, "{}", {}))
    # create returns no Id (image missing / refused) -> sweep yields nothing, no crash.
    monkeypatch.setattr(netutil, "http_request",
                        lambda url, method, **kw: (404, '{"message":"no such image"}', {}))
    out = relay_mod.DockerRelay("10.0.0.5", 2375).sweep(["10.0.0.10"], [6443])
    assert out == []


# ---------------------------------------------------------------------------
# relay: ProxyRelay reachability via HTTP CONNECT and SOCKS5 (loopback servers)
# ---------------------------------------------------------------------------
def test_proxy_relay_http_connect_reachable():
    def handler(conn):
        conn.recv(256)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    port, srv = _serve_once(handler)
    try:
        r = relay_mod.ProxyRelay(f"http://127.0.0.1:{port}")
        assert r.proxy_url() == f"http://127.0.0.1:{port}"
        out = r.sweep(["10.0.0.10"], [6443], timeout=2)
        assert out == [("10.0.0.10", 6443)]
    finally:
        srv.close()


def test_proxy_relay_http_connect_refused():
    def handler(conn):
        conn.recv(256)
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")

    port, srv = _serve_once(handler)
    try:
        out = relay_mod.ProxyRelay(f"http://127.0.0.1:{port}").sweep(["10.0.0.10"], [6443], timeout=2)
        assert out == []
    finally:
        srv.close()


def test_proxy_relay_socks5_reachable():
    def handler(conn):
        assert conn.recv(3) == b"\x05\x01\x00"          # greeting
        conn.sendall(b"\x05\x00")                        # no-auth accepted
        conn.recv(32)                                     # connect request
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # REP 0x00 = succeeded

    port, srv = _serve_once(handler)
    try:
        out = relay_mod.ProxyRelay(f"socks5://127.0.0.1:{port}").sweep(["10.0.0.10"], [6443], timeout=2)
        assert out == [("10.0.0.10", 6443)]
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# relay: build_relay factory precedence
# ---------------------------------------------------------------------------
def test_build_relay_precedence():
    docker = relay_mod.build_relay({"type": "docker", "host": "h", "port": 2375})
    assert isinstance(docker, relay_mod.DockerRelay)
    proxy = relay_mod.build_relay({"type": "proxy", "url": "socks5://127.0.0.1:1080"})
    assert isinstance(proxy, relay_mod.ProxyRelay)
    fallback = relay_mod.build_relay(None, fallback_proxy="http://127.0.0.1:8080")
    assert isinstance(fallback, relay_mod.ProxyRelay)
    assert isinstance(relay_mod.build_relay(None), relay_mod.DirectRelay)


# ---------------------------------------------------------------------------
# ledger: record / upgrade / paths / render
# ---------------------------------------------------------------------------
def test_ledger_records_and_reconstructs_path():
    led = ledger_mod.ProofLedger()
    led.record("container", "10.0.0.5:2375", reached_from="scanner",
               via="direct", proof="artifact", proof_kind=ledger_mod.PROVEN, severity="CRITICAL")
    led.record("service", "10.0.0.10:6443", reached_from="10.0.0.5:2375",
               via="docker", proof_kind=ledger_mod.REACHABILITY, severity="MEDIUM")
    led.record("service", "https://cr.run.app", reached_from="10.0.0.10:6443",
               via="proxy", proof_kind=ledger_mod.REACHABILITY, severity="MEDIUM")
    paths = led.paths()
    assert len(paths) == 1
    chain = [h.identity for h in paths[0]]
    assert chain == ["10.0.0.5:2375", "10.0.0.10:6443", "https://cr.run.app"]
    s = led._path_str(paths[0])
    assert s.startswith("scanner -> 10.0.0.5:2375 (proven)")
    assert "https://cr.run.app (reachable)" in s


def test_ledger_upgrades_reachability_to_proven():
    led = ledger_mod.ProofLedger()
    led.record("service", "10.0.0.10:6443", reached_from="x", proof_kind=ledger_mod.REACHABILITY,
               severity="MEDIUM")
    led.record("service", "10.0.0.10:6443", reached_from="x", proof_kind=ledger_mod.PROVEN,
               proof="marker", severity="CRITICAL")
    hops = led.hops
    assert len(hops) == 1, "the same resource must collapse to one identification"
    assert hops[0].proof_kind == ledger_mod.PROVEN
    assert hops[0].severity == "CRITICAL"


def test_ledger_to_result_emits_path_and_per_hop_findings():
    led = ledger_mod.ProofLedger()
    led.record("container", "ecs:1", reached_from="scanner", proof_kind=ledger_mod.PROVEN,
               severity="CRITICAL")
    led.record("service", "eks:1", reached_from="ecs:1", proof_kind=ledger_mod.REACHABILITY,
               severity="MEDIUM")
    res = led.to_result()
    assert res.name == "proof-ledger"
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "Lateral-movement path" in titles
    assert "Proof-of-access hop" in titles


def test_ledger_get_or_create_attaches_once():
    t = _stub_target()
    led1 = ledger_mod.get_or_create(t)
    led2 = ledger_mod.get_or_create(t)
    assert led1 is led2 is t.proof_ledger


# ---------------------------------------------------------------------------
# access_prover: relay descriptor + foothold hop
# ---------------------------------------------------------------------------
def test_publish_subnet_pivot_attaches_relay_and_provenance():
    t = _stub_target()
    relay_spec = {"type": "docker", "host": "10.0.0.5", "port": 2375}
    cidr = access_prover._publish_subnet_pivot(t, "10.0.0.5", 2375, relay=relay_spec)
    assert cidr == "10.0.0.0/24"
    spec = t.pivot_targets[0]
    assert spec["relay"] == relay_spec
    assert spec["reached_from"] == "10.0.0.5:2375"


def test_record_foothold_hop_writes_proven_entry():
    t = _stub_target(kind=targetmod.HOSTPORT, host="10.0.0.5", port=2375,
                     scope_guard=object(), proof_ledger=ledger_mod.ProofLedger())
    findings = [Finding(title="Code execution proven via exposed Docker Engine API",
                        severity="CRITICAL", location="10.0.0.5:2375", detail="x")]
    access_prover._record_foothold_hop(t, "10.0.0.5", 2375, findings,
                                       {"type": "docker", "host": "10.0.0.5", "port": 2375})
    hops = t.proof_ledger.hops
    assert len(hops) == 1
    assert hops[0].identity == "10.0.0.5:2375"
    assert hops[0].proof_kind == ledger_mod.PROVEN
    assert hops[0].via == "docker"
    assert hops[0].resource_kind == "container"


# ---------------------------------------------------------------------------
# cloud_pivot: SSM instance hop is recorded as SIMULATED (never executed)
# ---------------------------------------------------------------------------
def test_cloud_pivot_records_simulated_instance_hop():
    t = _stub_target(proof_ledger=ledger_mod.ProofLedger())
    cloud_pivot._record_instance_hop(t, "i-0abc", "subnet-1", True)
    hops = t.proof_ledger.hops
    assert hops[0].identity == "aws:ec2:i-0abc"
    assert hops[0].proof_kind == ledger_mod.SIMULATED
    assert hops[0].severity == "HIGH"


# ---------------------------------------------------------------------------
# main._expand_subnet_spec: relay-backed sweep + ledger reachability + via_proxy
# ---------------------------------------------------------------------------
def test_expand_subnet_uses_docker_relay_and_records_reachability(monkeypatch):
    # The foothold's Docker relay reports a private peer reachable FROM the foothold.
    monkeypatch.setattr(relay_mod.DockerRelay, "sweep",
                        lambda self, hosts, ports, *, timeout=None, deadline=None: [("10.0.0.10", 6443)])
    guard = scope_guard.ScopeGuard.from_specs(["10.0.0.0/24"], intensity="intrusive")
    target = _stub_target(proof_ledger=ledger_mod.ProofLedger())
    spec = {"kind": "netrange", "cidr": "10.0.0.0/24", "ports": [6443, 443],
            "via": "proof:10.0.0.5:2375", "reached_from": "10.0.0.5:2375",
            "relay": {"type": "docker", "host": "10.0.0.5", "port": 2375}}
    out = cli._expand_subnet_spec(spec, guard, time.monotonic() + 60, target)
    assert len(out) == 1
    assert out[0]["host"] == "10.0.0.10"
    assert out[0]["reached_from"] == "10.0.0.5:2375"
    # The reachable peer is now identified in the ledger, attributed to the foothold.
    hops = target.proof_ledger.hops
    assert any(h.identity == "10.0.0.10:6443" and h.reached_from == "10.0.0.5:2375"
               and h.proof_kind == ledger_mod.REACHABILITY for h in hops)


def test_expand_subnet_uses_pivot_proxy_when_no_relay(monkeypatch):
    monkeypatch.setattr(relay_mod.ProxyRelay, "sweep",
                        lambda self, hosts, ports, *, timeout=None, deadline=None: [("10.0.0.10", 80)])
    guard = scope_guard.ScopeGuard.from_specs(["10.0.0.0/24"], intensity="intrusive")
    target = _stub_target(pivot_proxy="socks5://127.0.0.1:1080",
                          proof_ledger=ledger_mod.ProofLedger())
    spec = {"kind": "netrange", "cidr": "10.0.0.0/24", "ports": [80],
            "via": "proof:10.0.0.5", "reached_from": "10.0.0.5"}
    out = cli._expand_subnet_spec(spec, guard, time.monotonic() + 60, target)
    assert out and out[0]["via_proxy"] == "socks5://127.0.0.1:1080"


# ---------------------------------------------------------------------------
# main._fanout_pivots: named cross-cloud (url) next hop is probed via the relay
# ---------------------------------------------------------------------------
def test_fanout_pivots_probes_named_url_next_hop(monkeypatch):
    # Collect all _run_modules calls — a URL pivot now also spawns a hostport
    # companion so the fake is called more than once.
    calls = []

    def fake_run_modules(mods, target, jobs=1, resume=None):
        calls.append({
            "url": getattr(target, "url", None),
            "proxy": getattr(target, "proxy", None),
            "reached_via": getattr(target, "reached_via", None),
            "kind": getattr(target, "kind", None),
        })
        return []

    monkeypatch.setattr(cli, "_run_modules", fake_run_modules)
    target = _stub_target(
        kind=targetmod.HOSTPORT, host="10.0.0.10", intensity="active",
        proof_ledger=ledger_mod.ProofLedger(), pivot_depth=0,
        pivot_targets=[{"kind": "url", "url": "https://cr.run.app",
                        "reached_from": "10.0.0.10:6443", "via_proxy": "socks5://127.0.0.1:1080"}])
    cli._fanout_pivots(target, _args(), jobs=1)
    # The URL pivot must have been probed.
    url_call = next((c for c in calls if c["url"] == "https://cr.run.app"), None)
    assert url_call is not None, f"URL https://cr.run.app not found in calls: {calls}"
    assert url_call["proxy"] == "socks5://127.0.0.1:1080"
    assert url_call["reached_via"] == "10.0.0.10:6443"
    # The URL companion hostport for cr.run.app must also have been probed.
    hostport_call = next((c for c in calls if c["kind"] == "hostport" and c["url"] is None), None)
    assert hostport_call is not None, "hostport companion for cr.run.app was not probed"
    # The named next hop is identified in the ledger.
    assert any(h.identity == "https://cr.run.app" for h in target.proof_ledger.hops)


# ---------------------------------------------------------------------------
# attack_chain: the proven-foothold -> lateral-movement rule fires
# ---------------------------------------------------------------------------
def test_attack_chain_lateral_movement_rule_fires():
    led = ledger_mod.ProofLedger()
    led.record("container", "10.0.0.5:2375", reached_from="scanner", proof_kind=ledger_mod.PROVEN,
               severity="CRITICAL")
    led.record("service", "10.0.0.10:6443", reached_from="10.0.0.5:2375",
               proof_kind=ledger_mod.REACHABILITY, severity="MEDIUM")
    results = [
        ExploitResult(name="access-prover", description="d", exploited=True, findings=[
            Finding(title="Code execution proven via exposed Docker Engine API",
                    severity="CRITICAL", location="10.0.0.5:2375", detail="x")]),
        led.to_result(),
    ]
    chain = attack_chain.correlate(results)
    titles = [f.title for f in chain.findings]
    assert any("Proven foothold -> lateral movement" in t for t in titles)


def test_attack_chain_no_lateral_rule_without_foothold():
    # Reachability alone (no proven foothold) must NOT fire the lateral-movement chain.
    led = ledger_mod.ProofLedger()
    led.record("service", "10.0.0.10:6443", reached_from="10.0.0.5:2375",
               proof_kind=ledger_mod.REACHABILITY, severity="MEDIUM")
    chain = attack_chain.correlate([led.to_result()])
    assert not any("Proven foothold -> lateral movement" in f.title for f in chain.findings)
