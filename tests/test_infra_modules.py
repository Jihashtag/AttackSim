"""Tests for the cloud-native active modules.

These exercise each module against local fixture servers (routed HTTP + raw TCP)
and verify both the positive (exposed) and negative (skip) paths.
"""
import struct

from exploits import (
    k8s_probe, ingress_nightmare, unauth_service_probe,
    kafka_probe, metadata_ssrf, argocd_probe, kyverno_probe, netutil,
)


# --- k8s-probe -------------------------------------------------------------
def test_k8s_readonly_kubelet_pods_exposed(routed_http_server):
    host, port, _ = routed_http_server({"/pods": (200, b'{"kind":"PodList","items":[]}')})
    findings = k8s_probe._kubelet(host, port, read_only=True)
    assert findings and findings[0].severity == "HIGH"
    assert "PodList" not in findings[0].title  # title is descriptive, not raw


def test_k8s_etcd_unauthenticated(routed_http_server):
    host, port, _ = routed_http_server({"/version": (200, b'{"etcdserver":"3.5.9"}')})
    findings = k8s_probe._etcd(host, port)
    assert findings and findings[0].severity == "CRITICAL"
    assert findings[0].cwe == "CWE-306"


def test_k8s_probe_skip_when_unreachable(fake_target):
    t = fake_target(kind="hostport", host="127.0.0.1", port=1, raw="x")
    t.ports = [1]
    res = k8s_probe.run(t)
    assert res.exploited is False
    assert res.error


# --- ingress-nightmare -----------------------------------------------------
def test_ingress_vulnerable_version(routed_http_server):
    host, port, base = routed_http_server({"/": (200, b"ok", [("Server", "nginx/1.9.3")])})
    t = type("T", (), {})()
    t.kind = "url"
    t.url = base
    res = ingress_nightmare.run(t)
    assert res.exploited is True
    assert any("vulnerable" in f.title.lower() for f in res.findings)
    assert any("CVE-2025-1974" in (f.references or []) for f in res.findings)


def test_ingress_version_compare():
    assert ingress_nightmare._is_vulnerable_version((1, 11, 4)) is True
    assert ingress_nightmare._is_vulnerable_version((1, 11, 5)) is False
    assert ingress_nightmare._is_vulnerable_version((1, 12, 1)) is False
    assert ingress_nightmare._is_vulnerable_version((1, 10, 0)) is True


# --- unauth-service-probe --------------------------------------------------
def test_unauth_redis_open(tcp_server):
    def responder(data):
        if data.startswith(b"PING"):
            return b"+PONG\r\n"
        if data.startswith(b"INFO"):
            return b"$20\r\nredis_version:7.2.0\r\n"
        return b""

    host, port = tcp_server(responder)
    findings = unauth_service_probe._redis(host, port)
    assert findings and findings[0].severity == "CRITICAL"


def test_unauth_docker_api_exposed(routed_http_server):
    host, port, _ = routed_http_server({"/version": (200, b'{"Version":"24.0.0"}')})
    findings = unauth_service_probe._docker(host, port)
    assert findings and findings[0].severity == "CRITICAL"
    assert "Docker" in findings[0].title


def test_unauth_elasticsearch_open(routed_http_server):
    host, port, _ = routed_http_server(
        {"/": (200, b'{"cluster_name":"x","version":{"lucene_version":"9.0"}}'),
         "/_cat/indices": (200, b"green open logs-2024")}
    )
    findings = unauth_service_probe._elasticsearch(host, port)
    titles = " ".join(f.title for f in findings)
    assert "Elasticsearch" in titles
    assert any(f.severity == "CRITICAL" for f in findings)


def test_unauth_probe_skip_when_unreachable(fake_target):
    # Use an uncommon high port (not 6379): a real local Redis listening on the standard
    # port would otherwise make this "unreachable" test find a live service (BUG-4).
    t = fake_target(kind="hostport", host="127.0.0.1", port=1, raw="x")
    t.ports = [65401]
    res = unauth_service_probe.run(t)
    assert res.exploited is False
    assert res.error


# --- kafka-probe -----------------------------------------------------------
def test_kafka_broker_unauthenticated(tcp_server):
    def responder(_data):
        # size, correlation_id=1, error_code=0
        return struct.pack(">i", 6) + struct.pack(">i", 1) + struct.pack(">h", 0)

    host, port = tcp_server(responder)
    findings = kafka_probe._broker(host, port)
    assert findings and findings[0].severity == "CRITICAL"


def test_kafka_connect_rce_surface(routed_http_server):
    host, port, _ = routed_http_server(
        {"/connectors": (200, b"[]"), "/connector-plugins": (200, b'[{"class":"x"}]')}
    )
    findings = kafka_probe._connect(host, port)
    assert any(f.severity == "CRITICAL" for f in findings)
    assert any("plugins" in f.title.lower() for f in findings)


def test_kafka_schema_registry_open(routed_http_server):
    host, port, _ = routed_http_server({"/subjects": (200, b'["topic-value"]')})
    findings = kafka_probe._schema_registry(host, port)
    assert findings and findings[0].severity == "HIGH"


# --- metadata-ssrf ---------------------------------------------------------
def test_metadata_ssrf_reflects_aws(monkeypatch, fake_target):
    def fake_get(url, headers=None, timeout=None, **kw):
        if "security-credentials" in url:
            return 200, '{"Code":"Success","AccessKeyId":"ASIA...","InstanceProfile":"x"}', {}
        return 200, "nothing here", {}

    monkeypatch.setattr(metadata_ssrf.netutil, "http_get", fake_get)
    t = fake_target(kind="url", url="http://app.example/fetch?url=http://safe", raw="x")
    res = metadata_ssrf.run(t)
    assert res.exploited is True
    assert any("AWS" in f.title and f.severity == "CRITICAL" for f in res.findings)
    # Evidence must not leak the actual credential material.
    assert all("ASIA" not in (f.evidence or "") for f in res.findings)


def test_metadata_ssrf_no_reflection_is_skip(monkeypatch, fake_target):
    monkeypatch.setattr(metadata_ssrf.netutil, "http_get",
                        lambda *a, **k: (200, "plain page", {}))
    t = fake_target(kind="url", url="http://app.example/fetch?url=x", raw="x")
    res = metadata_ssrf.run(t)
    assert res.exploited is False
    assert res.error


def test_metadata_with_param_helper():
    out = metadata_ssrf._with_param("http://h/p?a=1", "url", "http://x")
    assert "url=http" in out


# --- argocd-probe ----------------------------------------------------------
def test_argocd_old_version_and_unauth_apps(routed_http_server):
    host, port, base = routed_http_server(
        {"/api/version": (200, b'{"Version":"v2.9.0+abc","KustomizeVersion":"v5.0.1"}'),
         "/api/v1/applications": (200, b'{"items":[{"metadata":{"name":"a"}}]}')}
    )
    t = type("T", (), {})()
    t.kind = "url"
    t.url = base
    res = argocd_probe.run(t)
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "predates" in titles or "Application inventory" in titles


def test_argocd_skip_when_absent(fake_target):
    t = fake_target(kind="url", url="http://127.0.0.1:1", raw="x")
    res = argocd_probe.run(t)
    assert res.exploited is False
    assert res.error


# --- netutil helpers -------------------------------------------------------
def test_version_helpers():
    assert netutil.parse_version("nginx/1.11.5") == (1, 11, 5)
    assert netutil.version_lt((1, 11, 4), (1, 11, 5)) is True
    assert netutil.version_lt((1, 12, 0), (1, 11, 5)) is False


# --- kyverno-probe ---------------------------------------------------------
_KYVERNO_METRICS_SSRF = (
    b'# HELP kyverno_build_info Build info\n'
    b'kyverno_build_info{version="v1.17.1"} 1\n'
    b'kyverno_policy_results_total{policy="x"} 3\n'
)
_KYVERNO_METRICS_PATCHED = (
    b'kyverno_build_info{version="v1.18.0"} 1\n'
)


def test_kyverno_ssrf_version_flagged(routed_http_server):
    host, port, _ = routed_http_server({"/metrics": (200, _KYVERNO_METRICS_SSRF)})
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    res = kyverno_probe.run(t)
    assert res.exploited is True
    refs = [r for f in res.findings for r in (f.references or [])]
    # 1.17.1 is affected by the apiCall SSRF advisory (fixed 1.18.0).
    assert "GHSA-qr4g-8hrp-c4rw" in refs


def test_kyverno_token_leak_old_version(routed_http_server):
    host, port, _ = routed_http_server(
        {"/metrics": (200, b'kyverno_build_info{version="v1.15.0"} 1\n')})
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    res = kyverno_probe.run(t)
    refs = [r for f in res.findings for r in (f.references or [])]
    assert "GHSA-8wfp-579w-6r25" in refs  # < 1.16.4 token leak


def test_kyverno_patched_version_only_exposure(routed_http_server):
    host, port, _ = routed_http_server({"/metrics": (200, _KYVERNO_METRICS_PATCHED)})
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    res = kyverno_probe.run(t)
    # Patched build: only the (MEDIUM) metrics-exposure finding, no advisory hits.
    assert res.exploited is False
    refs = [r for f in res.findings for r in (f.references or [])]
    assert "GHSA-qr4g-8hrp-c4rw" not in refs
    assert "GHSA-8wfp-579w-6r25" not in refs


def test_kyverno_skip_when_not_kyverno(routed_http_server):
    host, port, _ = routed_http_server({"/metrics": (200, b"go_gc_duration_seconds 0")})
    t = type("T", (), {})()
    t.kind = "hostport"
    t.host = host
    t.port = port
    t.ports = [port]
    res = kyverno_probe.run(t)
    assert res.exploited is False
    assert res.error


def test_kyverno_affected_helper():
    adv = kyverno_probe._ADVISORIES[1]  # SSRF: introduced 1.17.0, fixed 1.18.0
    assert kyverno_probe._affected((1, 17, 1), adv) is True
    assert kyverno_probe._affected((1, 18, 0), adv) is False
    assert kyverno_probe._affected((1, 16, 0), adv) is False
