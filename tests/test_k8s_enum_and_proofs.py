"""Tests for credentialed k8s enumeration (F8) and the new access-prover canaries (F9)."""
from __future__ import annotations

from exploits import access_prover, k8s_enum
from sandbox import scope_guard


# ---------------------------------------------------------------------------
# k8s_enum (credentialed, intrusive)
# ---------------------------------------------------------------------------
def _k8s_target(base, *, token="tok", scope=("127.0.0.1",)):
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = "127.0.0.1"
    t.port = 6443
    t.ports = [6443]
    t.raw = "127.0.0.1:6443"
    t.k8s_token = token
    t.k8s_api_base = base  # override -> plain-HTTP fake API server for offline tests
    t.scope_guard = scope_guard.ScopeGuard.from_specs(list(scope), intensity="intrusive")
    return t


def test_k8s_enum_detects_dangerous_permissions(routed_http_server):
    import json
    rules = json.dumps({
        "status": {"resourceRules": [
            {"verbs": ["get", "list"], "apiGroups": [""], "resources": ["secrets"]},
            {"verbs": ["create"], "apiGroups": [""], "resources": ["pods/exec"]},
        ]}
    }).encode()
    routes = {
        "GET /api": (200, b'{"kind":"APIVersions","versions":["v1"]}'),
        "POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews": (201, rules),
        "GET /api/v1/namespaces": (200, b'{"items":[{"a":1},{"b":2}]}'),
        "GET /api/v1/secrets": (200, b'{"items":[{"metadata":{"name":"s1"}}]}'),
    }
    _h, _p, base = routed_http_server(routes)
    res = k8s_enum.run(_k8s_target(base))
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "dangerous Kubernetes permissions" in titles
    assert "LIST cluster Secrets" in titles
    assert any("k8s-privesc" in f.tags for f in res.findings)


def test_k8s_enum_token_rejected(routed_http_server):
    routes = {"GET /api": (401, b'{"message":"Unauthorized"}')}
    _h, _p, base = routed_http_server(routes)
    res = k8s_enum.run(_k8s_target(base))
    assert res.exploited is False
    assert any("token rejected" in f.title for f in res.findings)


def test_k8s_enum_no_token_skips(routed_http_server):
    routes = {"GET /api": (200, b"{}")}
    _h, _p, base = routed_http_server(routes)
    res = k8s_enum.run(_k8s_target(base, token=None))
    assert res.exploited is False
    assert any("no Kubernetes token" in f.title for f in res.findings)


def test_k8s_enum_out_of_scope(routed_http_server):
    routes = {"GET /api": (200, b"{}")}
    _h, _p, base = routed_http_server(routes)
    res = k8s_enum.run(_k8s_target(base, scope=("10.0.0.1",)))
    assert any("out of scope" in f.title for f in res.findings)


def test_k8s_enum_metadata():
    assert k8s_enum.SUPPORTS == {"hostport"}
    assert k8s_enum.INTENSITY == "intrusive"


# ---------------------------------------------------------------------------
# access_prover: memcached canary (F9)
# ---------------------------------------------------------------------------
def _prove_target(host, port, *, writes=False):
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    t.raw = f"{host}:{port}"
    t.prove_access = True
    t.prove_access_writes = writes
    t.prove_access_shell = False
    return t


def test_memcached_proof_sets_and_reads_canary(tcp_server):
    store = {}

    def responder(data: bytes) -> bytes:
        text = data.decode("latin-1", "replace")
        if text.startswith("version"):
            return b"VERSION 1.6.0\r\n"
        if text.startswith("set "):
            # set <key> <flags> <exptime> <bytes>\r\n<data>\r\n
            header, _, rest = text.partition("\r\n")
            parts = header.split()
            key = parts[1]
            value = rest.split("\r\n", 1)[0]
            store[key] = value
            return b"STORED\r\n"
        if text.startswith("get "):
            key = text.split()[1].strip()
            if key in store:
                v = store[key]
                return (f"VALUE {key} 0 {len(v)}\r\n{v}\r\nEND\r\n").encode()
            return b"END\r\n"
        return b"ERROR\r\n"

    host, port = tcp_server(responder)
    res = access_prover.run(_prove_target(host, port))
    assert res.exploited is True
    assert any("Memcached" in f.title and "Write access proven" in f.title
               for f in res.findings)
    # the canary key was stored and NOT deleted (persists)
    assert store  # at least one key remains


def test_memcached_proof_ignores_non_memcached(tcp_server):
    # A server that does not speak memcached must not yield a false proof.
    host, port = tcp_server(lambda data: b"not-memcached\r\n")
    res = access_prover.run(_prove_target(host, port))
    # No memcached finding; (other proofs against this port self-validate and bail too)
    assert not any("Memcached" in f.title for f in res.findings)


# ---------------------------------------------------------------------------
# access_prover: container-registry canary (F9, writes-gated)
# ---------------------------------------------------------------------------
def test_registry_proof_gated_off(routed_http_server):
    routes = {"GET /v2/": (200, b"{}", [("Docker-Distribution-Api-Version", "registry/2.0")])}
    host, port, _base = routed_http_server(routes)
    res = access_prover.run(_prove_target(host, port, writes=False))
    assert any("registry write-proof skipped" in f.title for f in res.findings)
    # the gated finding is HIGH, not a CRITICAL write proof
    assert not any("Write access proven on unauthenticated container registry" in f.title
                   for f in res.findings)


def test_registry_proof_writes_canary_upload(routed_http_server):
    routes = {
        "GET /v2/": (200, b"{}", [("Docker-Distribution-Api-Version", "registry/2.0")]),
        "POST /v2/sectest-canary/blobs/uploads/": (
            202, b"", [("Location", "/v2/sectest-canary/blobs/uploads/abc123")]),
    }
    host, port, _base = routed_http_server(routes)
    res = access_prover.run(_prove_target(host, port, writes=True))
    assert res.exploited is True
    assert any("Write access proven on unauthenticated container registry" in f.title
               for f in res.findings)


def test_registry_proof_authenticated_is_info(routed_http_server):
    routes = {"GET /v2/": (401, b"", [("Docker-Distribution-Api-Version", "registry/2.0")])}
    host, port, _base = routed_http_server(routes)
    res = access_prover.run(_prove_target(host, port, writes=True))
    assert any("requires authentication" in f.title for f in res.findings)
    assert res.exploited is False
