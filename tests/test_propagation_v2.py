"""Tests for the new propagation system (v2): pack, transport, cloud."""
from __future__ import annotations

import base64
import io
import json
import os
import pathlib
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


# ===========================================================================
# propagate_pack tests
# ===========================================================================

class TestPropagatePack:
    """Tests for sandbox/propagate_pack.py"""

    def test_build_zipapp_payload_returns_bytes(self):
        from sandbox.propagate_pack import build_zipapp_payload
        payload = build_zipapp_payload()
        assert isinstance(payload, bytes)
        # Should start with shebang
        assert payload[:2] == b"#!"
        # Should contain a valid zip (after the shebang line)
        newline_idx = payload.index(b"\n")
        zip_data = payload[newline_idx + 1:]
        # Verify it's a valid zip
        zf = zipfile.ZipFile(io.BytesIO(zip_data))
        names = zf.namelist()
        assert "__main__.py" in names
        assert "main.py" in names
        zf.close()

    def test_build_source_payload_returns_targz(self):
        from sandbox.propagate_pack import build_source_payload
        import tarfile
        payload = build_source_payload()
        assert isinstance(payload, bytes)
        # Should be valid gzip
        tf = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
        names = tf.getnames()
        assert any("main.py" in n for n in names)
        tf.close()

    def test_select_strategy_auto_returns_zipapp_when_no_native(self):
        from sandbox.propagate_pack import select_strategy
        strat = select_strategy(platform=None, has_python=True, force=None)
        # Without pre-built binaries, should fall back to zipapp
        assert strat.name == "zipapp"
        assert strat.needs_python is True
        assert len(strat.payload) > 0

    def test_select_strategy_force_source(self):
        from sandbox.propagate_pack import select_strategy
        strat = select_strategy(force="source")
        assert strat.name == "source"
        assert strat.needs_python is True

    def test_select_strategy_force_zipapp(self):
        from sandbox.propagate_pack import select_strategy
        strat = select_strategy(force="zipapp")
        assert strat.name == "zipapp"
        assert strat.payload[:2] == b"#!"

    def test_payload_strategy_deploy_command_native(self):
        from sandbox.propagate_pack import PayloadStrategy
        strat = PayloadStrategy("native", b"\x7fELF...", needs_python=False)
        cmd = strat.deploy_command("/tmp/sectest", ["--targets", "10.0.0.0/24"])
        assert cmd == "/tmp/sectest --targets 10.0.0.0/24"

    def test_payload_strategy_deploy_command_zipapp(self):
        from sandbox.propagate_pack import PayloadStrategy
        strat = PayloadStrategy("zipapp", b"#!...", needs_python=True)
        cmd = strat.deploy_command("/tmp/sectest.pyz", ["--prove-access"])
        assert cmd == "python3 /tmp/sectest.pyz --prove-access"

    def test_payload_manifest(self):
        from sandbox.propagate_pack import payload_manifest
        m = payload_manifest()
        assert "strategies" in m
        assert "zipapp" in m["strategies"]
        assert "source" in m["strategies"]

    def test_native_available_returns_false_without_binaries(self):
        from sandbox.propagate_pack import native_available
        # No pre-built binaries should exist in test environment
        assert native_available("linux-amd64") is False


# ===========================================================================
# propagate_transport tests
# ===========================================================================

class TestPropagateTransport:
    """Tests for sandbox/propagate_transport.py"""

    def test_all_transports_have_names(self):
        from sandbox.propagate_transport import ALL_TRANSPORTS
        names = [t.name for t in ALL_TRANSPORTS]
        assert "ssh" in names
        assert "docker-volume" in names
        assert "kubelet" in names
        assert "k8s-api" in names
        assert "cloud-storage" in names

    def test_transports_sorted_by_priority(self):
        from sandbox.propagate_transport import ALL_TRANSPORTS
        priorities = [t.priority for t in ALL_TRANSPORTS]
        assert priorities == sorted(priorities)

    def test_select_transport_ssh(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "ssh", "host": "10.0.0.1", "port": 22}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "ssh"

    def test_select_transport_docker(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "docker", "host": "10.0.0.1", "port": 2375}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "docker-volume"

    def test_select_transport_kubelet(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "kubelet", "host": "10.0.0.1", "port": 10250,
                    "pod": "test-pod", "container": "app"}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "kubelet"

    def test_select_transport_k8s_api(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "k8s-api", "api_url": "https://k8s.example.com",
                    "token": "abc", "pod": "test"}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "k8s-api"

    def test_select_transport_cloud(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "aws-ssm", "instance_id": "i-123", "region": "us-east-1"}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "cloud-storage"

    def test_select_transport_unknown_returns_none(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "unknown", "host": "x"}
        t = select_transport(foothold)
        assert t is None

    def test_shell_escape(self):
        from sandbox.propagate_transport import _shell_escape
        assert _shell_escape("simple") == "simple"
        assert _shell_escape("") == "''"
        assert _shell_escape("has space") == "'has space'"
        assert _shell_escape("it's") == "'it'\\''s'"


# ===========================================================================
# propagate_cloud tests
# ===========================================================================

class TestPropagateCloud:
    """Tests for sandbox/propagate_cloud.py (structural, no network)."""

    def test_sh_escape(self):
        from sandbox.propagate_cloud import _sh_escape
        assert _sh_escape("abc") == "abc"
        assert _sh_escape("") == "''"
        assert _sh_escape("a b") == "'a b'"

    def test_nutanix_auth_header(self):
        from sandbox.propagate_cloud import _nutanix_auth_header
        cred = {"username": "admin", "password": "secret"}
        h = _nutanix_auth_header(cred)
        assert "Authorization" in h
        assert h["Authorization"].startswith("Basic ")
        decoded = base64.b64decode(h["Authorization"].split(" ")[1]).decode()
        assert decoded == "admin:secret"

    def test_nutanix_auth_header_empty_cred(self):
        from sandbox.propagate_cloud import _nutanix_auth_header
        assert _nutanix_auth_header({}) == {}

    def test_aws_api_headers_with_session_token(self):
        from sandbox.propagate_cloud import _aws_api_headers
        cred = {"session_token": "tok123"}
        h = _aws_api_headers(cred, "us-east-1", "ssm")
        assert h["X-Amz-Security-Token"] == "tok123"

    def test_oci_api_headers_with_token(self):
        from sandbox.propagate_cloud import _oci_api_headers
        cred = {"token": "oci-bearer-token"}
        h = _oci_api_headers(cred)
        assert h["Authorization"] == "Bearer oci-bearer-token"

    def test_oci_api_headers_with_rsa_signing(self):
        from sandbox.propagate_cloud import _oci_api_headers
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Generate a private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        cred = {
            "identity": "ocid1.tenancy.oc1..abc",
            "secret": pem,
            "extra": {
                "user": "ocid1.user.oc1..xyz",
                "fingerprint": "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34"
            }
        }
        url = "https://compute-management.us-phoenix-1.oci.oraclecloud.com/20160918/instanceAgentCommands"
        h = _oci_api_headers(cred, method="POST", url=url, headers={"Content-Type": "application/json"}, body=b"{}")

        assert "Authorization" in h
        auth = h["Authorization"]
        assert 'Signature version="1"' in auth
        assert 'keyId="ocid1.tenancy.oc1..abc/ocid1.user.oc1..xyz/20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34"' in auth
        assert 'algorithm="rsa-sha256"' in auth
        assert 'headers="(request-target) host date x-content-sha256 content-type content-length"' in auth
        assert 'signature=' in auth
        assert h["host"] == "compute-management.us-phoenix-1.oci.oraclecloud.com"
        assert "date" in h
        assert "x-content-sha256" in h

    def test_propagate_oci_instance_agent(self):
        from sandbox.propagate_cloud import propagate_oci_instance_agent
        from unittest.mock import patch
        import json
        import string

        # Mock netutil.http_request
        with patch("exploits.netutil.http_request", return_value=(200, "success", {})) as mock_req:
            cred = {"token": "my-token"}
            ok, resp = propagate_oci_instance_agent(
                instance_id="inst-1",
                compartment_id="comp-1",
                region="us-phoenix-1",
                cred=cred,
                payload=b"echo hello",
                args=["arg1"],
                timeout=10
            )
            assert ok is True
            assert resp == "success"

            # Check arguments sent to http_request
            assert mock_req.called
            args, kwargs = mock_req.call_args
            body = json.loads(kwargs["body"].decode("utf-8"))
            assert body["compartmentId"] == "comp-1"
            assert body["target"]["instanceId"] == "inst-1"
            assert "textSha256" in body["content"]["source"]
            sha = body["content"]["source"]["textSha256"]
            assert len(sha) == 64
            assert all(c in string.hexdigits for c in sha)




# ===========================================================================
# propagate.py universal entry point tests
# ===========================================================================

class TestPropagateUniversal:
    """Tests for the propagate_universal() entry point."""

    def test_legacy_deploy_unsupported_type(self):
        from sandbox.propagate import _legacy_deploy
        ok, output = _legacy_deploy({"type": "quantum"}, ["--help"], 10)
        assert ok is False
        assert "unsupported" in output

    def test_propagate_to_cloud_target_unsupported_provider(self):
        from sandbox.propagate import propagate_to_cloud_target
        ok, output = propagate_to_cloud_target(
            {"provider": "quantum-cloud"}, {}, ["--help"])
        assert ok is False
        assert "unsupported" in output


# ===========================================================================
# build_zipapp.py tests
# ===========================================================================

class TestBuildZipapp:
    """Tests for build/build_zipapp.py"""

    def test_build_pyz_creates_file(self):
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "build"))
        from build_zipapp import build_pyz
        with tempfile.NamedTemporaryFile(suffix=".pyz", delete=False) as f:
            tmp = f.name
        try:
            result = build_pyz(output=tmp)
            assert result.exists()
            assert result.stat().st_size > 1000
            # Should be executable as a zip
            content = result.read_bytes()
            assert content[:2] == b"#!"
        finally:
            os.unlink(tmp)

    def test_build_pyz_bytes(self):
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "build"))
        from build_zipapp import build_pyz_bytes
        data = build_pyz_bytes()
        assert isinstance(data, bytes)
        assert len(data) > 1000
        assert data[:2] == b"#!"


# ===========================================================================
# Relay platform detection tests
# ===========================================================================

class TestRelayPlatformDetection:
    """Tests for Relay.detect_platform() and detect_python()."""

    def test_base_relay_detect_platform_returns_none(self):
        from sandbox.relay import Relay
        r = Relay()
        assert r.detect_platform() is None

    def test_base_relay_detect_python_returns_false(self):
        from sandbox.relay import Relay
        r = Relay()
        assert r.detect_python() is False
