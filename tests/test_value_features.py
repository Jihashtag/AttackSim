"""Tests for the value-add feature modules + the lateral-movement pivot framework.

All offline: local HTTP/TCP fixtures and fake AWS/GCP/Azure JSON servers. The tests also
assert the hard safety contract for each module (read-only guards raise, no gadget/command
payloads, no credential creation, simulate-only pivot capability).
"""
from __future__ import annotations

import http.server
import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from exploits import (api_idor, web_spider, llm_probe, deserialization_probe,
                      saml_misconfig, http2_probe, sbom_scan, cve_enrich,
                      cloud_posture, cloud_pivot, cloud_service_exposure)
from exploits.base import ExploitResult, Finding
from sandbox import cloud_creds


# ===========================================================================
# Configurable HTTP server
# ===========================================================================
def _start(handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    return srv, f"http://{host}:{port}"


class _UTarget:
    """Minimal url target with the attributes the active modules read."""

    def __init__(self, url, **kw):
        self.kind = "url"
        self.url = url
        self.host = urlparse(url).hostname
        self.port = urlparse(url).port
        self.ports = [self.port] if self.port else []
        self.scope_guard = None
        self.budget = None
        self.proxy = None
        self.canary_url = None
        self.idor_alt_headers = {}
        self.discovered_urls = []
        self.pivot_targets = []
        self.pivot_depth = 0
        self.__dict__.update(kw)

    def request_headers(self):
        return dict(getattr(self, "_headers", {}) or {})


# ===========================================================================
# F1: api-idor
# ===========================================================================
def _idor_handler(routes, protected):
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            authed = bool(self.headers.get("Authorization") or self.headers.get("Cookie")
                          or self.headers.get("X-Alt"))
            if path in protected and not authed:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"unauthorized")
                return
            body = routes.get(path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"nope")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *_a):
            pass
    return _H


def test_api_idor_missing_auth():
    # Object returns the same body with or without auth -> missing object-level auth.
    routes = {"/api/orders/500": "ORDER-500-secret-data"}
    srv, base = _start(_idor_handler(routes, protected=set()))
    try:
        t = _UTarget(base + "/api/orders/500", _headers={"Authorization": "Bearer x"})
        res = api_idor.run(t)
        assert any("without authentication" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


def test_api_idor_neighbour():
    routes = {f"/api/users/{i}": f"user-{i}-distinct-body-{i*7}" for i in range(1, 1200)}
    srv, base = _start(_idor_handler(routes, protected=set()))
    try:
        t = _UTarget(base + "/api/users/100", _headers={"Authorization": "Bearer x"})
        res = api_idor.run(t)
        assert any(f.tags and "idor" in f.tags for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_api_idor_cross_identity():
    routes = {"/api/me/42": "alice-private-profile"}
    srv, base = _start(_idor_handler(routes, protected={"/api/me/42"}))
    try:
        t = _UTarget(base + "/api/me/42", _headers={"Authorization": "Bearer alice"})
        t.idor_alt_headers = {"X-Alt": "bob"}
        res = api_idor.run(t)
        assert any("bola confirmed" in f.title.lower() for f in res.findings)
        assert any(f.severity == "CRITICAL" for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_api_idor_no_object_id_skips():
    t = _UTarget("http://127.0.0.1:1/health")
    res = api_idor.run(t)
    assert res.exploited is False
    assert any("no object identifier" in f.title.lower() for f in res.findings)


def test_api_idor_read_only_guard():
    with pytest.raises(ValueError):
        api_idor._assert_read_only("DELETE")


# ===========================================================================
# F2: web-spider
# ===========================================================================
def test_web_spider_crawls_and_publishes_urls():
    pages = {
        "/": '<a href="/a">a</a><a href="/b">b</a><a href="https://evil.example/x">ext</a>',
        "/a": '<form action="/login"></form><a href="/secret-admin">admin</a>',
        "/b": 'nothing here',
        "/secret-admin": 'var apiKey = "AKIA0123456789ABCDEF";',
    }

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            body = pages.get(path)
            if body is None:
                self.send_response(404); self.end_headers(); self.wfile.write(b"x"); return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *_a):
            pass

    srv, base = _start(_H)
    try:
        t = _UTarget(base + "/")
        res = web_spider.run(t)
        assert len(t.discovered_urls) >= 3            # crawled multiple same-origin pages
        assert all("evil.example" not in u for u in t.discovered_urls)  # same-origin only
        assert any("inline secret" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


# ===========================================================================
# F3: llm-probe
# ===========================================================================
def test_llm_probe_prompt_injection():
    class _H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode() if length else ""
            # Echo the injected marker back inside an OpenAI-style envelope.
            reply = {"choices": [{"message": {"role": "assistant",
                     "content": llm_probe._MARKER if llm_probe._MARKER in body else "no"}}]}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())

        def log_message(self, *_a):
            pass

    srv, base = _start(_H)
    try:
        t = _UTarget(base)
        res = llm_probe.run(t)
        assert any("prompt injection confirmed" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


def test_llm_probe_non_llm_skips():
    class _H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.send_response(404); self.end_headers(); self.wfile.write(b"nope")

        def log_message(self, *_a):
            pass

    srv, base = _start(_H)
    try:
        res = llm_probe.run(_UTarget(base))
        assert res.exploited is False
        assert any("no llm endpoint" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


# ===========================================================================
# F4: deserialization-probe
# ===========================================================================
def test_deserialization_gadget_guard_raises():
    with pytest.raises(ValueError):
        deserialization_probe._assert_no_gadget("<x>Runtime.exec</x>")


def test_deserialization_fingerprint_java():
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"prefix rO0ABXNyABid more")  # base64 java-serialized magic

        def log_message(self, *_a):
            pass

    srv, base = _start(_H)
    try:
        res = deserialization_probe.run(_UTarget(base + "/app"))
        assert any("java serialized" in f.title.lower() for f in res.findings)
    finally:
        srv.shutdown(); srv.server_close()


def test_deserialization_oob_confirm():
    state = {"hit": False}

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            qs = parse_qs(urlparse(self.path).query)
            if "check" in qs:
                self.send_response(200); self.end_headers()
                self.wfile.write(b"HIT deser-canary" if state["hit"] else b"none")
                return
            if "data" in qs:
                state["hit"] = True
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *_a):
            pass

    srv, base = _start(_H)
    try:
        # base64-looking 'data' param so it is selected as a deser candidate.
        t = _UTarget(base + "/x?data=rO0ABXNyAAAAAA")
        t.canary_url = base
        res = deserialization_probe.run(t)
        assert any("sink confirmed via oob" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


# ===========================================================================
# F5: saml-misconfig
# ===========================================================================
def test_saml_unsigned_assertions():
    meta = ('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
            '<SPSSODescriptor WantAssertionsSigned="false" AuthnRequestsSigned="false">'
            '<AssertionConsumerService Location="http://sp.example/acs"/>'
            '</SPSSODescriptor></EntityDescriptor>')

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.split("?", 1)[0] in ("/", "/saml/metadata"):
                self.send_response(200); self.end_headers(); self.wfile.write(meta.encode())
            else:
                self.send_response(404); self.end_headers(); self.wfile.write(b"x")

        def log_message(self, *_a):
            pass

    srv, base = _start(_H)
    try:
        res = saml_misconfig.run(_UTarget(base))
        assert any("wantassertionssigned=false" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


# ===========================================================================
# F10: http2-rapid-reset
# ===========================================================================
def test_http2_endpoints_parse():
    t = _UTarget("https://example.test:8443/")
    eps = http2_probe._endpoints(t)
    assert ("example.test", 8443, True) in eps


def test_http2_h2c_detection(tcp_server):
    def responder(_data):
        return (b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                b"Upgrade: h2c\r\n\r\n")

    host, port = tcp_server(responder)
    t = _UTarget(f"http://{host}:{port}/")
    # Force the cleartext path (tls False since port not in TLS set).
    res = http2_probe.run(t)
    assert any("http/2 supported" in f.title.lower() for f in res.findings)
    assert res.exploited is False        # detection-only: never marks exploited


# ===========================================================================
# F8: sbom-scan (parsers + degrade-to-INFO)
# ===========================================================================
def test_sbom_parse_trivy():
    doc = json.dumps({"Results": [{"Vulnerabilities": [
        {"Severity": "HIGH", "PkgName": "openssl", "InstalledVersion": "1.1.1",
         "VulnerabilityID": "CVE-2022-3602", "Title": "punycode overflow"}]}]})
    rows = sbom_scan.parse_trivy(doc)
    assert rows and rows[0][3] == "CVE-2022-3602"


def test_sbom_parse_grype():
    doc = json.dumps({"matches": [{"vulnerability": {"id": "CVE-2021-1", "severity": "Critical",
                     "description": "x"}, "artifact": {"name": "lib", "version": "1.0"}}]})
    rows = sbom_scan.parse_grype(doc)
    assert rows and rows[0][0].lower() == "critical"


def test_sbom_no_scanner_degrades(monkeypatch, tmp_path):
    monkeypatch.setattr(sbom_scan.toolrunner, "available", lambda b: False)
    t = type("T", (), {})()
    t.kind = "repo"
    t.root = str(tmp_path)
    t.raw = str(tmp_path)
    res = sbom_scan.run(t)
    assert res.tool_available is False
    assert res.exploited is False


# ===========================================================================
# F9: EPSS + ATT&CK enrichment
# ===========================================================================
def test_epss_attack_annotation():
    fnd = Finding(title="SSH weakness", severity="HIGH", location="h:22",
                  detail="d", references=["CVE-2024-6387"], category="proto-auth",
                  tags=["ssh"])
    res = ExploitResult(name="x", description="d", exploited=True, findings=[fnd])
    summary = cve_enrich.annotate_epss_attack([res])
    # EPSS tag attached (CVE-2024-6387 is high in the bundled feed).
    assert any(t.startswith("epss:") for t in fnd.tags)
    assert "epss-high" in fnd.tags
    # ATT&CK technique attached from the proto-auth category.
    assert any(r.startswith("ATT&CK T") for r in fnd.references)
    assert summary and "high exploit probability" in summary[0].title.lower()


# ===========================================================================
# Fake AWS server (Query + JSON protocols) for cloud-posture / cloud-pivot
# ===========================================================================
def _aws_combined(query_responses, json_responses, seen):
    class _H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            target = self.headers.get("X-Amz-Target")
            if target:
                seen.append(target)
                body = json_responses.get(target, b"{}")
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.end_headers()
                self.wfile.write(payload)
                return
            params = {k: v[0] for k, v in parse_qs(raw.decode("utf-8")).items()}
            action = params.get("Action", "")
            seen.append(action)
            xml = query_responses.get(action, b"<Empty/>")
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(xml if isinstance(xml, bytes) else xml.encode())

        def log_message(self, *_a):
            pass
    return _H


def _cloud_target(base, *, prove=False):
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider="aws", source="test", secret={"access_key": "AKIA", "secret_key": "x"},
        region="us-east-1")])
    overrides = {k: base for k in (
        "AWS_EC2_ENDPOINT", "AWS_RDS_ENDPOINT", "AWS_IAM_ENDPOINT", "AWS_STS_ENDPOINT",
        "AWS_SSM_ENDPOINT", "AWS_CLOUDTRAIL_ENDPOINT")}
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = inv
    t.cloud_endpoints = overrides
    t.prove_access = prove
    t.pivot_targets = []
    t.pivot_depth = 0
    return t


def test_cloud_posture_public_ebs_and_root_keys():
    query = {
        "DescribeImages": b"<DescribeImagesResponse><imagesSet/></DescribeImagesResponse>",
        "DescribeSnapshots": (b"<DescribeSnapshotsResponse><snapshotSet><item>"
                              b"<snapshotId>snap-1</snapshotId></item></snapshotSet>"
                              b"</DescribeSnapshotsResponse>"),
        "DescribeSnapshotAttribute": (b"<DescribeSnapshotAttributeResponse>"
                                      b"<snapshotId>snap-1</snapshotId><createVolumePermission>"
                                      b"<item><group>all</group></item></createVolumePermission>"
                                      b"</DescribeSnapshotAttributeResponse>"),
        "GetAccountPasswordPolicy": (b"<GetAccountPasswordPolicyResponse><GetAccountPasswordPolicyResult>"
                                     b"<PasswordPolicy><MinimumPasswordLength>8</MinimumPasswordLength>"
                                     b"</PasswordPolicy></GetAccountPasswordPolicyResult>"
                                     b"</GetAccountPasswordPolicyResponse>"),
        "GetAccountSummary": (b"<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap>"
                              b"<entry><key>AccountAccessKeysPresent</key><value>1</value></entry>"
                              b"<entry><key>AccountMFAEnabled</key><value>0</value></entry>"
                              b"</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>"),
    }
    json_resp = {"com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails":
                 {"trailList": []}}
    seen = []
    srv, base = _start(_aws_combined(query, json_resp, seen))
    try:
        res = cloud_posture.run(_cloud_target(base))
        titles = " ".join(f.title.lower() for f in res.findings)
        assert "ebs snapshot(s) are public" in titles
        assert "root account has active access keys" in titles
        assert "no mfa" in titles
        assert "no cloudtrail trail" in titles
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


def test_cloud_posture_read_only_guard():
    with pytest.raises(ValueError):
        cloud_posture._assert_read_only("DeleteSnapshot")


# ===========================================================================
# Pivot: cloud-pivot (SSM + subnet mapping) + simulate-only capability
# ===========================================================================
def test_cloud_pivot_maps_subnet_peers():
    query = {
        "GetCallerIdentity": (b"<GetCallerIdentityResponse><GetCallerIdentityResult>"
                              b"<Arn>arn:aws:iam::123456789012:user/alice</Arn>"
                              b"<Account>123456789012</Account>"
                              b"</GetCallerIdentityResult></GetCallerIdentityResponse>"),
        "SimulatePrincipalPolicy": (b"<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>"
                                    b"<EvaluationResults>"
                                    b"<member><EvalActionName>ssm:SendCommand</EvalActionName>"
                                    b"<EvalDecision>allowed</EvalDecision></member>"
                                    b"<member><EvalActionName>ssm:StartSession</EvalActionName>"
                                    b"<EvalDecision>implicitDeny</EvalDecision></member>"
                                    b"</EvaluationResults></SimulatePrincipalPolicyResult>"
                                    b"</SimulatePrincipalPolicyResponse>"),
        "DescribeInstances": (b"<DescribeInstancesResponse><reservationSet><item><instancesSet>"
                              b"<item><instanceId>i-aaa</instanceId><subnetId>subnet-1</subnetId>"
                              b"<vpcId>vpc-1</vpcId><privateIpAddress>10.0.0.10</privateIpAddress></item>"
                              b"<item><instanceId>i-bbb</instanceId><subnetId>subnet-1</subnetId>"
                              b"<vpcId>vpc-1</vpcId><privateIpAddress>10.0.0.11</privateIpAddress></item>"
                              b"</instancesSet></item></reservationSet></DescribeInstancesResponse>"),
    }
    json_resp = {"AmazonSSM.DescribeInstanceInformation":
                 {"InstanceInformationList": [{"InstanceId": "i-aaa"}]}}
    seen = []
    srv, base = _start(_aws_combined(query, json_resp, seen))
    try:
        t = _cloud_target(base)
        res = cloud_pivot.run(t)
        # i-aaa is SSM-managed and shares subnet-1 with i-bbb (10.0.0.11) -> pivot queued.
        assert any("shares subnet" in f.title.lower() for f in res.findings)
        assert any(p["host"] == "10.0.0.11" for p in t.pivot_targets)
        # SendCommand was only SIMULATED, never sent.
        assert "ssm:SendCommand" not in seen
        assert "SendCommand" not in seen
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


def test_cloud_pivot_read_guard():
    with pytest.raises(ValueError):
        cloud_pivot._assert_read_or_simulate("SendCommand")


# ===========================================================================
# F7: cloud-service-exposure GCP/Azure parity
# ===========================================================================
def _json_get_server(routes):
    """routes: list of (path_prefix, dict). GET-only prefix dispatch."""
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            for prefix, body in sorted(routes, key=lambda r: len(r[0]), reverse=True):
                if path.startswith(prefix):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(body).encode())
                    return
            self.send_response(404); self.end_headers(); self.wfile.write(b"{}")

        def log_message(self, *_a):
            pass
    return _H


def _provider_target(provider, overrides):
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider=provider, source="test", secret={"access_token": "tok"}, region="us-east-1")])
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = inv
    t.cloud_endpoints = overrides
    return t


def test_cloud_service_exposure_gcp_public_bucket():
    routes = [
        ("/v1/projects", {"projects": [{"projectId": "proj-1"}]}),
        ("/storage/v1/b/pub-bucket/iam",
         {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}),
        ("/storage/v1/b", {"items": [{"name": "pub-bucket"}]}),
        ("/v1/projects/proj-1/locations/-/functions", {"functions": []}),
    ]
    srv, base = _start(_json_get_server(routes))
    try:
        t = _provider_target("gcp", {"GCP_RM_ENDPOINT": base, "GCP_STORAGE_ENDPOINT": base,
                                     "GCP_FUNCTIONS_ENDPOINT": base})
        res = cloud_service_exposure.run(t)
        assert any("gcs bucket(s) public" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()


def test_cloud_service_exposure_azure_public_storage():
    routes = [
        ("/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts",
         {"value": [{"name": "openacct", "properties": {"allowBlobPublicAccess": True}}]}),
        ("/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults", {"value": []}),
        ("/subscriptions", {"value": [{"subscriptionId": "sub-1"}]}),
    ]
    srv, base = _start(_json_get_server(routes))
    try:
        t = _provider_target("azure", {"AZURE_ARM_ENDPOINT": base})
        res = cloud_service_exposure.run(t)
        assert any("public blob access" in f.title.lower() for f in res.findings)
        assert res.exploited is True
    finally:
        srv.shutdown(); srv.server_close()
