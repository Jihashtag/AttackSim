"""Tests for k8s_service_enum module (Workstream 1)."""
import pytest
from unittest.mock import patch, MagicMock


class _FakeTarget:
    kind = "hostport"
    host = "10.0.0.1"
    port = 6443
    ports = [6443]
    pivot_targets = []
    discovered_urls = []
    prove_access = False


def _mock_api_response(url, **kwargs):
    """Mock K8s API responses based on URL path."""
    if "/version" in url:
        return (200, {"gitVersion": "v1.28.0"}, {})
    if "/api/v1/services" in url:
        return (200, {
            "items": [
                {"metadata": {"name": "cloud-run-svc", "namespace": "default"},
                 "spec": {"type": "ExternalName", "externalName": "my-svc.run.app",
                          "ports": [{"port": 443}]},
                 "status": {}},
                {"metadata": {"name": "lb-svc", "namespace": "prod"},
                 "spec": {"type": "LoadBalancer", "ports": [{"port": 8080}]},
                 "status": {"loadBalancer": {"ingress": [{"hostname": "a.elb.amazonaws.com"}]}}},
            ]
        }, {})
    if "/apis/networking.k8s.io/v1/ingresses" in url:
        return (200, {
            "items": [
                {"spec": {"tls": [{"hosts": ["app.example.com"]}],
                          "rules": [{"host": "app.example.com"}]}}
            ]
        }, {})
    if "/apis/gateway.networking.k8s.io" in url:
        return (200, {"items": []}, {})
    if "/apis/networking.istio.io" in url:
        return (200, {
            "items": [
                {"spec": {"hosts": ["internal-api.mesh.local", "*.wildcard.example"]}}
            ]
        }, {})
    if "/api/v1/configmaps" in url:
        return (200, {
            "items": [
                {"data": {"config": "endpoint=https://cloudrun-svc-xyz.run.app/api"}}
            ]
        }, {})
    if "/apis/admissionregistration.k8s.io" in url:
        return (200, {
            "items": [
                {"webhooks": [
                    {"clientConfig": {"url": "https://webhook.external.io/validate"}}
                ]}
            ]
        }, {})
    if "/apis/networking.k8s.io/v1/networkpolicies" in url:
        return (200, {"items": []}, {})
    return (404, "", {})


@patch("exploits.netutil.http_get_json")
def test_k8s_service_enum_discovers_urls(mock_json):
    mock_json.side_effect = _mock_api_response
    from exploits import k8s_service_enum
    target = _FakeTarget()
    result = k8s_service_enum.run(target)
    assert len(result.findings) > 0
    # Should have discovered pivot targets
    assert len(target.pivot_targets) > 0
    urls = [s.get("url") for s in target.pivot_targets if s.get("url")]
    assert any("run.app" in u for u in urls)


@patch("exploits.netutil.http_get_json")
def test_k8s_service_enum_no_api(mock_json):
    mock_json.return_value = (None, None, None)
    from exploits import k8s_service_enum
    target = _FakeTarget()
    result = k8s_service_enum.run(target)
    assert not result.exploited
    assert result.error


@patch("exploits.netutil.http_get_json")
def test_k8s_service_enum_network_policies_empty(mock_json):
    """Absent NetworkPolicies should be flagged."""
    def side_effect(url, **kwargs):
        if "/version" in url:
            return (200, {"gitVersion": "v1.28.0"}, {})
        if "/apis/networking.k8s.io/v1/networkpolicies" in url:
            return (200, {"items": []}, {})
        return (404, None, {})
    mock_json.side_effect = side_effect
    from exploits import k8s_service_enum
    target = _FakeTarget()
    result = k8s_service_enum.run(target)
    np_findings = [f for f in result.findings if "networkpolicy" in f.title.lower() or
                   "network-policy" in " ".join(f.tags)]
    assert len(np_findings) > 0


@patch("exploits.netutil.http_get_json")
def test_extract_service_urls(mock_json):
    """Verify URL extraction from services response."""
    from exploits.k8s_service_enum import _extract_service_urls
    data = {
        "items": [
            {"metadata": {"name": "ext", "namespace": "default"},
             "spec": {"type": "ExternalName", "externalName": "service.run.app",
                      "ports": [{"port": 443}]},
             "status": {}},
        ]
    }
    urls = _extract_service_urls(data)
    assert "https://service.run.app:443" in urls


@patch("exploits.netutil.http_get_json")
def test_extract_configmap_urls(mock_json):
    """Verify URL grep from configmap data."""
    from exploits.k8s_service_enum import _extract_configmap_urls
    data = {"items": [{"data": {"cfg": "url=https://my-api.internal.io/path other text"}}]}
    urls = _extract_configmap_urls(data)
    assert any("my-api.internal.io" in u for u in urls)


@patch("exploits.netutil.http_get_json")
def test_extract_webhook_urls(mock_json):
    """Verify webhook URL extraction."""
    from exploits.k8s_service_enum import _extract_webhook_urls
    data = {"items": [{"webhooks": [
        {"clientConfig": {"service": {"name": "webhook", "namespace": "system", "port": 443, "path": "/validate"}}}
    ]}]}
    urls = _extract_webhook_urls(data)
    assert any("webhook.system.svc" in u for u in urls)
