"""Tests for the opt-in access-prover module.

Verifies:
* OFF by default (no flag => SKIP, no requests).
* Redis canary proof: SET/GET round-trip leaves a persistent proof key behind.
* Docker proof: spawns a throwaway container that writes a persistent host marker, then
  cleans the container up.
* Elasticsearch write-proof is gated behind --prove-access-writes.
* Proof artifacts are durable for blue-team verification.
"""
import json

import pytest

from exploits import access_prover


def _target(host, port, prove=False, writes=False, shell=False):
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    t.prove_access = prove
    t.prove_access_writes = writes
    t.prove_access_shell = shell
    return t


# --- opt-in gate -----------------------------------------------------------
def test_prover_off_by_default(redis_server):
    host, port = redis_server
    res = access_prover.run(_target(host, port, prove=False))
    assert res.exploited is False
    assert "OFF" in (res.error or "")


# --- redis canary proof ----------------------------------------------------
def test_redis_canary_proof_persists(redis_server):
    host, port = redis_server
    res = access_prover.run(_target(host, port, prove=True))
    assert res.exploited is True
    assert any("Redis" in f.title and f.severity == "CRITICAL" for f in res.findings)
    # The canary must still be present afterwards for durable verification.
    from exploits import netutil
    findings = [f for f in res.findings if "Redis" in f.title]
    key = findings[0].evidence.split("key=")[-1]
    got = netutil.redis_command(host, port, ["GET", key])
    assert got and b"authorized-assessment-" in got


def test_redis_proof_skips_when_not_redis(routed_http_server):
    # An HTTP server on the "redis" port does not speak RESP -> no proof, no crash.
    host, port, _ = routed_http_server({"/": (200, b"not redis")})
    res = access_prover.run(_target(host, port, prove=True))
    assert res.exploited is False


# --- docker proof ----------------------------------------------------------
def test_docker_proof_writes_host_marker_and_removes_container(routed_http_server):
    cid = "deadbeefcafe"
    marker_holder = {}

    routes = {
        "/version": (200, b'{"Version":"24.0.0"}'),
        "/info": (200, b'{"CgroupDriver":"cgroupfs","Name":"kubepods-node"}'),
        "POST /containers/create": (201, json.dumps({"Id": cid}).encode()),
        f"POST /containers/{cid}/start": (204, b""),
        f"POST /containers/{cid}/wait": (200, b'{"StatusCode":0}'),
        # logs echo back whatever marker the container "wrote"; we can't know it in
        # advance, so return a generic body — the proof still records execution.
        f"/containers/{cid}/logs": (200, b"proof-marker-present"),
        f"POST /containers/{cid}/stop": (204, b""),
        f"DELETE /containers/{cid}": (204, b""),
    }
    host, port, _ = routed_http_server(routes)
    res = access_prover.run(_target(host, port, prove=True))
    assert res.exploited is True
    assert any("Docker" in f.title or "Code execution" in f.title for f in res.findings)
    assert any("/tmp/" in f.evidence for f in res.findings)


def test_docker_create_reachable_even_without_image(routed_http_server):
    # create returns 404 (no image) -> still proves control of the create endpoint.
    routes = {
        "/version": (200, b'{"Version":"24.0.0"}'),
        "/info": (200, b'{"Name":"plain-host"}'),
        "POST /containers/create": (404, b'{"message":"No such image"}'),
    }
    host, port, _ = routed_http_server(routes)
    res = access_prover.run(_target(host, port, prove=True))
    assert res.exploited is True
    assert any("create" in f.title.lower() for f in res.findings)


# --- elasticsearch write gating -------------------------------------------
def test_es_write_proof_gated_off(routed_http_server):
    host, port, _ = routed_http_server(
        {"/": (200, b'{"cluster_name":"x","version":{"lucene_version":"9.0"}}')}
    )
    res = access_prover.run(_target(host, port, prove=True, writes=False))
    # HIGH (not CRITICAL) finding noting the proof was skipped.
    assert any("skipped" in f.title.lower() for f in res.findings)
    assert all(f.severity != "CRITICAL" for f in res.findings)


def test_es_write_proof_when_enabled(routed_http_server):
    host, port, _ = routed_http_server({
        "/": (200, b'{"cluster_name":"x","version":{"lucene_version":"9.0"}}'),
        "PUT /sectest-canary/_doc/1": (201, b'{"result":"created"}'),
    })
    res = access_prover.run(_target(host, port, prove=True, writes=True))
    assert res.exploited is True
    assert any("Elasticsearch" in f.title and f.severity == "CRITICAL" for f in res.findings)


# --- pinpointed port with nothing listening --------------------------------
def test_prover_pinpoint_dead_port_is_safe(fake_target):
    # Operator pinpoints one non-standard port; nothing is listening there.
    t = _target("127.0.0.1", 1, prove=True)
    t.ports = [1]
    res = access_prover.run(t)
    assert res.exploited is False
    # No CRITICAL/HIGH proof, and no crash.
    assert all(f.severity not in ("CRITICAL", "HIGH") for f in res.findings)


# --- sandboxed shell-handle (opt-in --prove-access-shell) ------------------
def test_docker_shell_handle_spawns_persistent_container(routed_http_server):
    cid = "feedfacecafe"
    routes = {
        "/version": (200, b'{"Version":"24.0.0"}'),
        "POST /containers/create": (201, json.dumps({"Id": cid}).encode()),
        f"POST /containers/{cid}/start": (204, b""),
    }
    host, port, _ = routed_http_server(routes)
    res = access_prover.run(_target(host, port, prove=True, shell=True))
    assert res.exploited is True
    handle = [f for f in res.findings if "shell-handle" in f.title.lower()]
    assert handle and handle[0].severity == "CRITICAL"
    # The operator is handed an attach command and the evidence references the host marker.
    assert "attach" in handle[0].evidence.lower()
    assert "/tmp/" in handle[0].evidence


def test_docker_shell_handle_create_refused_is_safe(routed_http_server):
    routes = {
        "/version": (200, b'{"Version":"24.0.0"}'),
        "POST /containers/create": (404, b'{"message":"No such image"}'),
    }
    host, port, _ = routed_http_server(routes)
    res = access_prover.run(_target(host, port, prove=True, shell=True))
    # No Id returned -> a HIGH "reachable but not created" finding, no crash.
    assert any("not created" in f.title.lower() for f in res.findings)
