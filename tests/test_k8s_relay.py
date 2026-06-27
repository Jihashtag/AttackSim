"""Tests for KubeletRelay, K8sApiRelay, and relay enhancements (Workstream 2)."""
import pytest
from unittest.mock import patch, MagicMock


def test_kubelet_relay_sweep():
    """KubeletRelay executes nc -z via kubelet /run and parses OPEN markers."""
    from sandbox.relay import KubeletRelay, _parse_open_markers

    relay = KubeletRelay("10.0.0.1", 10250, pod_ns="default", pod_name="test-pod",
                         container="main")
    with patch.object(relay, "_exec_cmd", return_value="OPEN 10.0.1.5:6443\nOPEN 10.0.1.6:80"):
        result = relay.sweep(["10.0.1.5", "10.0.1.6", "10.0.1.7"], [6443, 80])
    assert ("10.0.1.5", 6443) in result
    assert ("10.0.1.6", 80) in result
    assert len(result) == 2  # one per host (dedup)


def test_kubelet_relay_resolve():
    """KubeletRelay resolves hostname from inside pod."""
    from sandbox.relay import KubeletRelay
    relay = KubeletRelay("10.0.0.1", 10250, pod_ns="default", pod_name="test-pod",
                         container="main")
    with patch.object(relay, "_exec_cmd", return_value="10.0.1.100\n"):
        ip = relay.resolve("my-service.run.app")
    assert ip == "10.0.1.100"


def test_kubelet_relay_resolve_failure():
    """KubeletRelay returns None on failed DNS."""
    from sandbox.relay import KubeletRelay
    relay = KubeletRelay("10.0.0.1", 10250, pod_ns="default", pod_name="test-pod",
                         container="main")
    with patch.object(relay, "_exec_cmd", return_value=""):
        ip = relay.resolve("nonexistent.host")
    assert ip is None


def test_kubelet_relay_http_probe():
    """KubeletRelay probes HTTP URL from inside pod."""
    from sandbox.relay import KubeletRelay
    relay = KubeletRelay("10.0.0.1", 10250, pod_ns="default", pod_name="test-pod",
                         container="main")
    with patch.object(relay, "_exec_cmd", return_value="  HTTP/1.1 200 OK\n"):
        status = relay.http_probe("https://service.run.app")
    assert status == 200


def test_k8s_api_relay_sweep():
    """K8sApiRelay executes via K8s API exec."""
    from sandbox.relay import K8sApiRelay
    relay = K8sApiRelay("https://k8s.example.com", "token123",
                        namespace="default", pod_name="runner", container="main")
    with patch.object(relay, "_exec_cmd", return_value="OPEN 10.0.2.3:443"):
        result = relay.sweep(["10.0.2.3"], [443])
    assert ("10.0.2.3", 443) in result


def test_direct_relay_resolve():
    """DirectRelay resolves via local socket."""
    from sandbox.relay import DirectRelay
    relay = DirectRelay()
    with patch("socket.getaddrinfo", return_value=[
        (2, 1, 6, '', ('1.2.3.4', 0))
    ]):
        ip = relay.resolve("example.com")
    assert ip == "1.2.3.4"


def test_direct_relay_http_probe():
    """DirectRelay probes via netutil."""
    from sandbox.relay import DirectRelay
    relay = DirectRelay()
    with patch("exploits.netutil.http_get", return_value=(200, "OK", {})):
        status = relay.http_probe("https://example.com")
    assert status == 200


def test_docker_relay_resolve():
    """DockerRelay resolves hostname from inside container."""
    from sandbox.relay import DockerRelay
    relay = DockerRelay("10.0.0.1", 2375)
    relay._base = "http://10.0.0.1:2375"  # skip resolve step
    with patch("exploits.netutil.http_request") as mock_req, \
         patch("exploits.netutil.http_get") as mock_get:
        # create -> success
        mock_req.side_effect = [
            (201, '{"Id": "abc123"}', {}),  # create
            (200, "", {}),                   # start
            (200, "", {}),                   # wait
            (200, "", {}),                   # stop
            (200, "", {}),                   # delete
        ]
        mock_get.return_value = (200, "10.0.1.50\n", {})
        ip = relay.resolve("internal-service.vpc")
    assert ip == "10.0.1.50"


def test_build_relay_kubelet():
    """build_relay constructs KubeletRelay from spec."""
    from sandbox.relay import build_relay, KubeletRelay
    spec = {"type": "kubelet", "host": "10.0.0.5", "port": 10250,
            "pod_ns": "kube-system", "pod_name": "kube-proxy-abc"}
    relay = build_relay(spec)
    assert isinstance(relay, KubeletRelay)
    assert relay.host == "10.0.0.5"


def test_build_relay_k8s_api():
    """build_relay constructs K8sApiRelay from spec."""
    from sandbox.relay import build_relay, K8sApiRelay
    spec = {"type": "k8s-api", "api_url": "https://k8s.example.com",
            "token": "eyJ...", "namespace": "default", "pod_name": "test"}
    relay = build_relay(spec)
    assert isinstance(relay, K8sApiRelay)
    assert relay.api_url == "https://k8s.example.com"


def test_proxy_relay_http_probe():
    """ProxyRelay routes HTTP through proxy env vars."""
    from sandbox.relay import ProxyRelay
    relay = ProxyRelay("http://proxy.local:8080")
    with patch("exploits.netutil.http_get", return_value=(403, "", {})):
        status = relay.http_probe("https://target.internal")
    assert status == 403


def test_parse_open_markers():
    """_parse_open_markers extracts OPEN host:port from logs."""
    from sandbox.relay import _parse_open_markers
    logs = "connecting...\nOPEN 10.0.1.5:6443\nfailed\nOPEN 10.0.1.6:80\n"
    targets = [("10.0.1.5", 6443), ("10.0.1.6", 80), ("10.0.1.7", 22)]
    result = _parse_open_markers(logs, targets)
    assert ("10.0.1.5", 6443) in result
    assert ("10.0.1.6", 80) in result
    assert ("10.0.1.7", 22) not in result
