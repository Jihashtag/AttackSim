"""Tests for service mesh probe (Workstream 7)."""
import pytest
from unittest.mock import patch


class _FakeTarget:
    kind = "hostport"
    host = "10.0.0.5"
    port = 15000
    ports = [15000]
    pivot_targets = []
    discovered_urls = []


@patch("exploits.netutil.http_get")
def test_service_mesh_probe_envoy_detected(mock_get):
    """Service mesh probe detects Envoy admin interface."""
    def side_effect(url, **kwargs):
        if "/server_info" in url:
            return (200, '{"version": "1.28.0", "envoy": true}', {})
        if "/clusters" in url:
            return (200, "cluster1::10.0.1.5:8080::added_via_api\n", {})
        if "/listeners" in url:
            return (200, '{"listeners": []}', {})
        if "/config_dump" in url:
            return (200, '{"configs": [{"url": "https://backend.internal:443"}]}', {})
        return (404, "", {})
    mock_get.side_effect = side_effect

    from exploits import service_mesh_probe
    target = _FakeTarget()
    result = service_mesh_probe.run(target)
    assert result.exploited
    assert any("Envoy" in f.title or "sidecar" in f.title for f in result.findings)


@patch("exploits.netutil.http_get")
def test_service_mesh_probe_no_envoy(mock_get):
    """Service mesh probe returns clean when no Envoy found."""
    mock_get.return_value = (404, "", {})
    from exploits import service_mesh_probe
    target = _FakeTarget()
    result = service_mesh_probe.run(target)
    assert not result.exploited
    assert result.error


@patch("exploits.netutil.http_get")
def test_service_mesh_probe_discovers_upstreams(mock_get):
    """Service mesh probe discovers upstream service endpoints."""
    def side_effect(url, **kwargs):
        if "/server_info" in url:
            return (200, "envoy version 1.28.0", {})
        if "/clusters" in url:
            return (200, ("svc1::10.0.1.5:8080::added_via_api\n"
                          "svc2::10.0.1.6:9090::added_via_api\n"), {})
        if "/listeners" in url:
            return (200, "listener info", {})
        if "/config_dump" in url:
            return (404, "", {})
        return (404, "", {})
    mock_get.side_effect = side_effect

    from exploits import service_mesh_probe
    target = _FakeTarget()
    result = service_mesh_probe.run(target)
    assert any("upstream" in f.title.lower() for f in result.findings)


@patch("exploits.netutil.http_get")
def test_service_mesh_probe_config_dump_sensitive(mock_get):
    """Full config dump triggers HIGH severity finding."""
    def side_effect(url, **kwargs):
        if "/server_info" in url:
            return (200, "envoy v1.28", {})
        if "/clusters" in url:
            return (200, "", {})
        if "/listeners" in url:
            return (200, "", {})
        if "/config_dump" in url:
            return (200, "x" * 200, {})  # Large config dump
        return (404, "", {})
    mock_get.side_effect = side_effect

    from exploits import service_mesh_probe
    target = _FakeTarget()
    result = service_mesh_probe.run(target)
    assert any("config dump" in f.title.lower() for f in result.findings)
    config_findings = [f for f in result.findings if "config dump" in f.title.lower()]
    assert config_findings[0].severity == "HIGH"
