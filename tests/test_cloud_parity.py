"""Phase-4 tests: GCP/Azure read-only enum parity + GCP/Azure grant-nothing proofs.

Offline only: fake JSON servers stand in for GCP/Azure APIs. The tests also assert the
hard safety contract — the grant-nothing proofs never call a key/secret-creating or
role-assignment URL.
"""
from __future__ import annotations

import http.server
import json
import threading

from exploits import access_prover, cloud_enum
from sandbox import cloud_creds


def _json_server(routes):
    """routes: list of (method, path_prefix, status, dict|bytes). Returns (base, seen)."""
    seen = []

    class _H(http.server.BaseHTTPRequestHandler):
        def _serve(self, method):
            path = self.path
            seen.append(f"{method} {path}")
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                try:
                    self.rfile.read(length)
                except Exception:
                    pass
            for m, prefix, status, body in sorted(
                    routes, key=lambda r: len(r[1]), reverse=True):
                if m == method and path.split("?", 1)[0].startswith(prefix):
                    payload = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    if payload:
                        self.wfile.write(payload)
                    return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"{}")

        def do_GET(self):  # noqa: N802
            self._serve("GET")

        def do_POST(self):  # noqa: N802
            self._serve("POST")

        def do_PUT(self):  # noqa: N802
            self._serve("PUT")

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    return srv, f"http://{host}:{port}", seen


def _cloud_target(provider, base_overrides, *, prove=False):
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider=provider, source="test-fixture",
        secret={"access_token": "fake-token"}, region="us-east-1")])
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = inv
    t.cloud_endpoints = base_overrides
    t.prove_access = prove
    t.prove_access_writes = prove
    t.prove_access_shell = prove
    return t


# ---------------------------------------------------------------------------
# C1: GCP read-only enum
# ---------------------------------------------------------------------------
def test_cloud_enum_gcp_public_ip_and_open_firewall():
    routes = [
        ("GET", "/v1/projects", 200, {"projects": [{"projectId": "proj-1"}]}),
        ("GET", "/compute/v1/projects/proj-1/aggregated/instances", 200,
         {"items": {"zones/a": {"instances": [
             {"name": "vm1", "networkInterfaces": [{"accessConfigs": [{"natIP": "1.2.3.4"}]}]}]}}}),
        ("GET", "/compute/v1/projects/proj-1/global/firewalls", 200,
         {"items": [{"name": "open-all", "sourceRanges": ["0.0.0.0/0"],
                     "allowed": [{"IPProtocol": "tcp"}]}]}),
    ]
    srv, base, _seen = _json_server(routes)
    try:
        t = _cloud_target("gcp", {"GCP_RM_ENDPOINT": base, "GCP_COMPUTE_ENDPOINT": base})
        res = cloud_enum.run(t)
        titles = " ".join(f.title for f in res.findings).lower()
        assert "public ips" in titles and "open to 0.0.0.0/0" in titles
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


# ---------------------------------------------------------------------------
# C1: Azure read-only enum
# ---------------------------------------------------------------------------
def test_cloud_enum_azure_open_nsg():
    routes = [
        ("GET", "/subscriptions", 200, {"value": [{"subscriptionId": "sub-1"}]}),
        ("GET", "/subscriptions/sub-1/providers/Microsoft.Network/networkSecurityGroups",
         200, {"value": [{"name": "nsg1", "properties": {"securityRules": [
             {"name": "ssh", "properties": {"access": "Allow", "direction": "Inbound",
                                            "sourceAddressPrefix": "*",
                                            "destinationPortRange": "22"}}]}}]}),
    ]
    srv, base, _seen = _json_server(routes)
    try:
        t = _cloud_target("azure", {"AZURE_ARM_ENDPOINT": base})
        res = cloud_enum.run(t)
        assert res.exploited is True
        assert any("nsg rule" in f.title.lower() and "internet" in f.title.lower()
                   for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


# ---------------------------------------------------------------------------
# C2: GCP grant-nothing proof
# ---------------------------------------------------------------------------
def test_gcp_grant_nothing_proof_creates_sa_no_key():
    routes = [
        ("GET", "/v1/projects", 200, {"projects": [{"projectId": "proj-1"}]}),
        ("POST", "/v1/projects/proj-1:testIamPermissions", 200,
         {"permissions": ["iam.serviceAccounts.create"]}),
        ("POST", "/v1/projects/proj-1/serviceAccounts", 200,
         {"email": "sectest@proj-1.iam.gserviceaccount.com"}),
    ]
    srv, base, seen = _json_server(routes)
    try:
        t = _cloud_target("gcp", {"GCP_RM_ENDPOINT": base, "GCP_IAM_ENDPOINT": base}, prove=True)
        res = access_prover.run(t)
        assert any(f.severity == "CRITICAL" and "GCP IAM" in f.title for f in res.findings)
        # HARD CONTRACT: never a serviceAccountKeys (usable-credential) call.
        assert not any("serviceAccountKeys" in s or "/keys" in s for s in seen)
    finally:
        srv.shutdown(); srv.server_close()


def test_gcp_grant_nothing_skipped_when_not_permitted():
    routes = [
        ("GET", "/v1/projects", 200, {"projects": [{"projectId": "proj-1"}]}),
        ("POST", "/v1/projects/proj-1:testIamPermissions", 200, {"permissions": []}),
    ]
    srv, base, seen = _json_server(routes)
    try:
        t = _cloud_target("gcp", {"GCP_RM_ENDPOINT": base, "GCP_IAM_ENDPOINT": base}, prove=True)
        res = access_prover.run(t)
        assert any("create-permission not allowed" in f.title for f in res.findings)
        # The create call must NOT have been made.
        assert not any("serviceAccounts" in s and s.startswith("POST") and
                       ":testIamPermissions" not in s for s in seen)
    finally:
        srv.shutdown(); srv.server_close()


# ---------------------------------------------------------------------------
# C2: Azure grant-nothing proof
# ---------------------------------------------------------------------------
def test_azure_grant_nothing_proof_creates_empty_roledef():
    routes = [
        ("GET", "/subscriptions", 200, {"value": [{"subscriptionId": "sub-1"}]}),
        ("PUT", "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/",
         201, {"id": "role"}),
    ]
    srv, base, seen = _json_server(routes)
    try:
        t = _cloud_target("azure", {"AZURE_ARM_ENDPOINT": base}, prove=True)
        res = access_prover.run(t)
        assert any(f.severity == "CRITICAL" and "Azure RBAC" in f.title for f in res.findings)
        # HARD CONTRACT: never a roleAssignments (empowering) call.
        assert not any("roleAssignments" in s for s in seen)
    finally:
        srv.shutdown(); srv.server_close()


def test_assert_no_credential_creation_guard():
    import pytest
    with pytest.raises(ValueError):
        access_prover._assert_no_credential_creation(
            "https://iam.googleapis.com/v1/projects/p/serviceAccounts/x/keys")
