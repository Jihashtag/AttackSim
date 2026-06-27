"""Tests for GCP/Azure cloud pivot (Workstream 3)."""
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import dataclass, field
from typing import List


@dataclass
class _FakeCred:
    provider: str = "gcp"
    secret: dict = field(default_factory=lambda: {
        "access_token": "ya29.fake",
        "project_id": "my-project-123"
    })
    source: str = "gcp-metadata"
    region: str = ""


@dataclass
class _FakeAzureCred:
    provider: str = "azure"
    secret: dict = field(default_factory=lambda: {
        "access_token": "eyJ.fake",
        "subscription_id": "sub-123-456"
    })
    source: str = "azure-cli"
    region: str = ""


@dataclass
class _FakeInventory:
    credentials: list = field(default_factory=list)


class _FakeTarget:
    kind = "cloud"
    host = None
    port = None
    ports = []
    pivot_targets = []
    reached_via = "scanner"
    proof_ledger = None
    cloud_inventory = None
    cloud_endpoints = {}


@patch("exploits.netutil.http_get")
def test_gcp_pivot_discovers_instances(mock_get):
    """GCP pivot discovers Compute instances and queues their IPs."""
    from exploits.cloud_pivot import _gcp_pivot
    mock_get.side_effect = lambda url, **kwargs: _gcp_responses(url)
    target = _FakeTarget()
    cred = _FakeCred()
    findings = _gcp_pivot(target, cred)
    assert len(findings) > 0
    assert any("Compute instance" in f.title for f in findings)
    assert len(target.pivot_targets) > 0


@patch("exploits.netutil.http_get")
def test_gcp_pivot_discovers_cloud_run(mock_get):
    """GCP pivot discovers Cloud Run services as URL targets."""
    from exploits.cloud_pivot import _gcp_pivot
    mock_get.side_effect = lambda url, **kwargs: _gcp_responses(url)
    target = _FakeTarget()
    cred = _FakeCred()
    findings = _gcp_pivot(target, cred)
    url_specs = [s for s in target.pivot_targets if s.get("kind") == "url"]
    assert len(url_specs) > 0
    assert any("run.app" in s.get("url", "") for s in url_specs)


@patch("exploits.netutil.http_get")
def test_gcp_pivot_discovers_gke(mock_get):
    """GCP pivot discovers GKE cluster endpoints."""
    from exploits.cloud_pivot import _gcp_pivot
    mock_get.side_effect = lambda url, **kwargs: _gcp_responses(url)
    target = _FakeTarget()
    cred = _FakeCred()
    findings = _gcp_pivot(target, cred)
    assert any("GKE" in f.title for f in findings)


@patch("exploits.netutil.http_get")
def test_azure_pivot_discovers_vms(mock_get):
    """Azure pivot discovers VMs."""
    from exploits.cloud_pivot import _azure_pivot
    mock_get.side_effect = lambda url, **kwargs: _azure_responses(url)
    target = _FakeTarget()
    cred = _FakeAzureCred()
    findings = _azure_pivot(target, cred)
    assert any("VM" in f.title for f in findings)
    assert len(target.pivot_targets) > 0


@patch("exploits.netutil.http_get")
def test_azure_pivot_discovers_aks(mock_get):
    """Azure pivot discovers AKS clusters."""
    from exploits.cloud_pivot import _azure_pivot
    mock_get.side_effect = lambda url, **kwargs: _azure_responses(url)
    target = _FakeTarget()
    cred = _FakeAzureCred()
    findings = _azure_pivot(target, cred)
    assert any("AKS" in f.title or "aks" in f.title.lower() for f in findings)


@patch("exploits.netutil.http_get")
def test_cloud_pivot_dispatches_by_provider(mock_get):
    """run() dispatches to the right provider based on credential."""
    mock_get.return_value = (404, "", {})
    from exploits import cloud_pivot
    target = _FakeTarget()
    target.cloud_inventory = _FakeInventory(credentials=[_FakeCred()])
    result = cloud_pivot.run(target)
    # Should not error even if API returns 404
    assert result is not None


def _gcp_responses(url):
    import json
    if "aggregated/instances" in url:
        return (200, json.dumps({
            "items": {
                "zones/us-central1-a": {
                    "instances": [
                        {"name": "vm-1", "zone": "zones/us-central1-a",
                         "networkInterfaces": [{"networkIP": "10.128.0.5"}]}
                    ]
                }
            }
        }), {})
    if "/clusters" in url:
        return (200, json.dumps({
            "clusters": [
                {"name": "prod-gke", "endpoint": "34.123.45.67"}
            ]
        }), {})
    if "/services" in url and "run" in url:
        return (200, json.dumps({
            "services": [
                {"name": "projects/p/locations/us/services/api-svc",
                 "uri": "https://api-svc-abc.run.app"}
            ]
        }), {})
    if "/functions" in url:
        return (200, json.dumps({
            "functions": [
                {"name": "projects/p/locations/us/functions/hello",
                 "serviceConfig": {"uri": "https://hello-func.cloudfunctions.net"}}
            ]
        }), {})
    if "/global/networks" in url:
        return (200, json.dumps({
            "items": [
                {"name": "vpc-prod", "peerings": [
                    {"network": "projects/other/global/networks/vpc-shared",
                     "state": "ACTIVE"}
                ]}
            ]
        }), {})
    return (404, "", {})


def _azure_responses(url):
    import json
    if "virtualMachines" in url:
        return (200, json.dumps({
            "value": [
                {"name": "web-vm-1", "id": "/subscriptions/sub/vms/web-vm-1",
                 "properties": {"networkProfile": {"networkInterfaces": []}}}
            ]
        }), {})
    if "managedClusters" in url:
        return (200, json.dumps({
            "value": [
                {"name": "aks-prod", "properties": {"fqdn": "aks-prod.hcp.eastus.azmk8s.io"}}
            ]
        }), {})
    if "Microsoft.Web/sites" in url:
        return (200, json.dumps({
            "value": [
                {"name": "my-webapp", "properties": {"defaultHostName": "my-webapp.azurewebsites.net"}}
            ]
        }), {})
    if "virtualNetworks" in url:
        return (200, json.dumps({
            "value": [
                {"name": "vnet-prod", "properties": {
                    "virtualNetworkPeerings": [
                        {"properties": {"peeringState": "Connected",
                                        "remoteVirtualNetwork": {"id": "/vnets/vnet-shared"}}}
                    ]
                }}
            ]
        }), {})
    return (404, "", {})
