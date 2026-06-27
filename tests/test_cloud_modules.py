"""Offline tests for the credentialed cloud path.

No live cloud is ever touched: a fake AWS Query-protocol server dispatches on the
``Action`` parameter and returns canned XML, so SigV4 signing, recon, IAM analysis,
and the gated grant-nothing proof are all exercised deterministically. The tests also
assert the hard safety contract — the proof never requests a credential-creating
action and is skipped unless the create permission simulates as allowed.
"""
from __future__ import annotations

import http.server
import threading
from urllib.parse import parse_qs

import pytest

from exploits import (access_prover, cloud_enum, cloud_iam_analyzer, cloud_recon,
                      cloudutil)
from sandbox import cloud_creds


# ---------------------------------------------------------------------------
# Fake AWS endpoint (STS + IAM share one server; dispatch by Action).
# ---------------------------------------------------------------------------
def _xml(inner: str) -> bytes:
    return ("<?xml version='1.0'?>" + inner).encode("utf-8")


_GET_CALLER = _xml(
    "<GetCallerIdentityResponse xmlns='https://sts.amazonaws.com/doc/2011-06-15/'>"
    "<GetCallerIdentityResult>"
    "<Arn>arn:aws:iam::123456789012:user/alice</Arn>"
    "<UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>"
    "</GetCallerIdentityResult></GetCallerIdentityResponse>")

_ACCOUNT_SUMMARY = _xml(
    "<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap>"
    "<entry><key>Users</key><value>5</value></entry>"
    "<entry><key>Roles</key><value>9</value></entry>"
    "<entry><key>Groups</key><value>2</value></entry>"
    "</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>")

_ATTACHED_ADMIN = _xml(
    "<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult>"
    "<AttachedPolicies><member><PolicyName>AdministratorAccess</PolicyName>"
    "<PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member>"
    "</AttachedPolicies></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>")

_LIST_ROLES = _xml(
    "<ListRolesResponse><ListRolesResult><Roles><member>"
    "<RoleName>app-role</RoleName>"
    "<Arn>arn:aws:iam::123456789012:role/app-role</Arn>"
    "</member></Roles></ListRolesResult></ListRolesResponse>")

_ASSUME_OK = _xml(
    "<AssumeRoleResponse><AssumeRoleResult><Credentials>"
    "<AccessKeyId>ASIAEXAMPLE</AccessKeyId>"
    "<SecretAccessKey>wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY</SecretAccessKey>"
    "<SessionToken>FAKESESSIONTOKEN</SessionToken>"
    "</Credentials></AssumeRoleResult></AssumeRoleResponse>")

_CREATE_USER = _xml(
    "<CreateUserResponse><CreateUserResult><User>"
    "<UserName>sectest</UserName><Arn>arn:aws:iam::123456789012:user/sectest</Arn>"
    "</User></CreateUserResult></CreateUserResponse>")

_PUT_POLICY = _xml("<PutUserPolicyResponse></PutUserPolicyResponse>")


def _simulate_xml(decision: str) -> bytes:
    return _xml(
        "<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>"
        "<EvaluationResults><member>"
        "<EvalActionName>iam:CreateUser</EvalActionName>"
        f"<EvalDecision>{decision}</EvalDecision>"
        "</member></EvaluationResults>"
        "</SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>")


@pytest.fixture
def aws_server():
    """Factory: given an {action: xml_bytes} map, yield (base_url, actions_seen)."""
    servers = []
    seen: list = []

    def _start(responses: dict):
        def handler_factory(*a, **k):
            return _Handler(responses, seen, *a, **k)

        srv = http.server.HTTPServer(("127.0.0.1", 0), handler_factory)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        host, port = srv.server_address
        return f"http://{host}:{port}/", seen

    try:
        yield _start
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


class _Handler(http.server.BaseHTTPRequestHandler):
    def __init__(self, responses, seen, *a, **k):
        self._responses = responses
        self._seen = seen
        super().__init__(*a, **k)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = {k: v[0] for k, v in parse_qs(body).items()}
        action = params.get("Action", "")
        self._seen.append(action)
        resp = self._responses.get(action)
        if resp is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(_xml(
                "<ErrorResponse><Error><Code>AccessDenied</Code>"
                f"<Message>no canned response for {action}</Message></Error></ErrorResponse>"))
            return
        status, payload = resp if isinstance(resp, tuple) else (200, resp)
        self.send_response(status)
        self.send_header("Content-Type", "text/xml")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        pass


def _cloud_target(base, prove=False):
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider="aws", source="test-fixture",
        secret={"access_key": "AKIAEXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
        region="us-east-1")])
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = inv
    t.cloud_endpoints = {"AWS_STS_ENDPOINT": base, "AWS_IAM_ENDPOINT": base}
    t.prove_access = prove
    t.prove_access_writes = prove
    t.prove_access_shell = prove
    return t


# ---------------------------------------------------------------------------
# SigV4
# ---------------------------------------------------------------------------
def test_sigv4_matches_aws_reference_vector():
    # AWS-documented derived signing key test vector.
    from exploits.cloudutil import _signing_key
    key = _signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                       "20120215", "us-east-1", "iam").hex()
    assert key == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"


def test_sign_aws_request_sets_authorization_and_token():
    headers = cloudutil.sign_aws_request(
        access_key="AKIA", secret_key="secret", session_token="tok",
        method="POST", endpoint="https://sts.amazonaws.com/", region="us-east-1",
        service="sts", body=b"Action=GetCallerIdentity&Version=2011-06-15")
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA/")
    assert headers["x-amz-security-token"] == "tok"
    assert "host" not in headers  # host is signed but not returned as a header to set


# ---------------------------------------------------------------------------
# cloud_recon
# ---------------------------------------------------------------------------
def test_recon_reports_identity_and_admin(aws_server):
    base, _ = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "GetAccountSummary": _ACCOUNT_SUMMARY,
        "ListAttachedUserPolicies": _ATTACHED_ADMIN,
    })
    res = cloud_recon.run(_cloud_target(base))
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "Valid AWS credential discovered" in titles
    assert any(f.severity == "CRITICAL" and "AdministratorAccess" in f.title
               for f in res.findings)
    # No secret material is ever echoed in evidence.
    assert all("wJalrX" not in f.evidence for f in res.findings)


def test_recon_handles_invalid_credential(aws_server):
    base, _ = aws_server({})  # any action -> AccessDenied error XML
    res = cloud_recon.run(_cloud_target(base))
    assert res.exploited is False
    assert any("not usable" in f.title for f in res.findings)


def test_recon_inactive_without_inventory():
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = None
    res = cloud_recon.run(t)
    assert res.exploited is False
    assert "no cloud credentials" in (res.error or "")


# ---------------------------------------------------------------------------
# cloud_iam_analyzer
# ---------------------------------------------------------------------------
def test_analyzer_simulates_and_walks_assume(aws_server):
    base, seen = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "SimulatePrincipalPolicy": _simulate_xml("allowed"),
        "ListRoles": _LIST_ROLES,
        "AssumeRole": _ASSUME_OK,
    })
    res = cloud_iam_analyzer.run(_cloud_target(base))
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "ALLOWED" in titles or "allowed" in titles
    assert "Privilege transition PROVEN" in titles
    assert "AssumeRole" in seen


def test_analyzer_reports_least_privilege_when_denied(aws_server):
    base, _ = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "SimulatePrincipalPolicy": _simulate_xml("implicitDeny"),
        "ListRoles": _xml("<ListRolesResponse><ListRolesResult><Roles/>"
                          "</ListRolesResult></ListRolesResponse>"),
    })
    res = cloud_iam_analyzer.run(_cloud_target(base))
    assert res.exploited is False
    assert any("denied" in f.title for f in res.findings)


def _simulate_privesc_xml(allowed_actions):
    """SimulatePrincipalPolicy result marking ``allowed_actions`` allowed, rest denied.

    The fake server returns the SAME body for every SimulatePrincipalPolicy call, so the
    analyzer's privesc engine (which simulates the union of all rule actions) sees these
    decisions. Any action not listed defaults to implicitDeny via the catch-all member.
    """
    members = "".join(
        "<member><EvalActionName>{a}</EvalActionName>"
        "<EvalDecision>allowed</EvalDecision></member>".format(a=a)
        for a in allowed_actions)
    return _xml(
        "<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>"
        "<EvaluationResults>" + members + "</EvaluationResults>"
        "</SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>")


def test_analyzer_detects_privesc_primitive(aws_server):
    # iam:CreateAccessKey allowed -> the 'create access key for another user' primitive fires.
    base, seen = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "SimulatePrincipalPolicy": _simulate_privesc_xml(["iam:CreateAccessKey"]),
        "ListRoles": _xml("<ListRolesResponse><ListRolesResult><Roles/>"
                          "</ListRolesResult></ListRolesResponse>"),
    })
    res = cloud_iam_analyzer.run(_cloud_target(base))
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "privilege-escalation primitive available" in titles
    assert any("privilege-escalation path(s) reachable" in f.title for f in res.findings)
    # the privesc finding carries the chain-friendly tag and never performs the action
    assert any("cloud-privesc" in f.tags for f in res.findings)
    assert "CreateAccessKey" not in seen  # simulate-only; never actually created


def test_analyzer_multi_action_privesc_requires_all(aws_server):
    # Only iam:PassRole allowed (not lambda:* or ec2:RunInstances) -> no passrole primitive fires.
    base, _ = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "SimulatePrincipalPolicy": _simulate_privesc_xml(["iam:PassRole"]),
        "ListRoles": _xml("<ListRolesResponse><ListRolesResult><Roles/>"
                          "</ListRolesResult></ListRolesResponse>"),
    })
    res = cloud_iam_analyzer.run(_cloud_target(base))
    assert not any("privilege-escalation primitive available" in f.title for f in res.findings)


def test_privesc_rules_file_loads():
    rules = cloud_iam_analyzer._load_privesc_rules()
    assert rules and all(r.get("actions") for r in rules)
    ids = {r["id"] for r in rules}
    assert "iam-create-access-key" in ids
    assert "iam-passrole-lambda" in ids



# ---------------------------------------------------------------------------
# access_prover cloud grant-nothing proof
# ---------------------------------------------------------------------------
def test_cloud_proof_off_by_default(aws_server):
    base, seen = aws_server({"GetCallerIdentity": _GET_CALLER})
    res = access_prover.run(_cloud_target(base, prove=False))
    assert res.exploited is False
    assert "OFF" in (res.error or "")
    assert seen == []  # nothing was even attempted


def test_cloud_proof_creates_grant_nothing_user_no_access_key(aws_server):
    base, seen = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "SimulatePrincipalPolicy": _simulate_xml("allowed"),
        "CreateUser": _CREATE_USER,
        "PutUserPolicy": _PUT_POLICY,
    })
    res = access_prover.run(_cloud_target(base, prove=True))
    assert res.exploited is True
    assert any("grant-nothing principal created" in f.title for f in res.findings)
    # HARD SAFETY CONTRACT: a user was created, but NO usable credential ever requested.
    assert "CreateUser" in seen
    assert "CreateAccessKey" not in seen
    assert "CreateLoginProfile" not in seen
    assert all(forbidden not in seen for forbidden in (
        "AttachUserPolicy", "AttachRolePolicy", "PutRolePolicy"))


def test_cloud_proof_skipped_when_create_denied(aws_server):
    base, seen = aws_server({
        "GetCallerIdentity": _GET_CALLER,
        "SimulatePrincipalPolicy": _simulate_xml("implicitDeny"),
    })
    res = access_prover.run(_cloud_target(base, prove=True))
    # Simulate-first guard: CreateUser must NOT be attempted when not allowed.
    assert "CreateUser" not in seen
    assert any("create-permission not simulated as allowed" in f.title for f in res.findings)


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
def test_discovery_finds_env_aws_credential(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secretvalue")
    monkeypatch.setenv("HOME", str(tmp_path))
    inv = cloud_creds.discover(probe_imds=False)
    assert bool(inv) is True
    aws = inv.for_provider("aws")
    assert aws and aws[0].source.startswith("AWS_* environment")
    # masked() must not leak the secret key.
    assert "secretvalue" not in aws[0].masked()


def test_discovery_empty_when_no_creds(monkeypatch, tmp_path):
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    inv = cloud_creds.discover(probe_imds=False)
    assert bool(inv) is False
    assert inv.providers() == []


# ---------------------------------------------------------------------------
# cloud_enum (read-only resource enumeration)
# ---------------------------------------------------------------------------
_DESCRIBE_INSTANCES = _xml(
    "<DescribeInstancesResponse><reservationSet><item><instancesSet>"
    "<item><instanceId>i-0public</instanceId><ipAddress>203.0.113.10</ipAddress></item>"
    "<item><instanceId>i-0private</instanceId></item>"
    "</instancesSet></item></reservationSet></DescribeInstancesResponse>")

_DESCRIBE_SGS = _xml(
    "<DescribeSecurityGroupsResponse><securityGroupInfo>"
    "<item><groupId>sg-0open</groupId><ipPermissions>"
    "<item><fromPort>22</fromPort><toPort>22</toPort>"
    "<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>"
    "</ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>")

_DESCRIBE_DBS = _xml(
    "<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances>"
    "<DBInstance><DBInstanceIdentifier>prod-db</DBInstanceIdentifier>"
    "<Engine>postgres</Engine><PubliclyAccessible>true</PubliclyAccessible></DBInstance>"
    "</DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>")


def _enum_target(base):
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider="aws", source="test-fixture",
        secret={"access_key": "AKIAEXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
        region="us-east-1")])
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = inv
    t.cloud_endpoints = {"AWS_EC2_ENDPOINT": base, "AWS_RDS_ENDPOINT": base}
    return t


def test_cloud_enum_reports_public_resources(aws_server):
    base, seen = aws_server({
        "DescribeInstances": _DESCRIBE_INSTANCES,
        "DescribeSecurityGroups": _DESCRIBE_SGS,
        "DescribeDBInstances": _DESCRIBE_DBS,
    })
    res = cloud_enum.run(_enum_target(base))
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "public IPs" in titles
    assert "0.0.0.0/0" in titles
    assert "publicly accessible" in titles
    # world-open SSH should be rated HIGH
    assert any(f.severity == "HIGH" and "security-group" in f.tags for f in res.findings)
    # only read actions were ever issued
    assert all(a.startswith(("Describe", "List", "Get")) for a in seen)
    # no secret material leaked
    assert all("wJalrX" not in f.evidence for f in res.findings)


def test_cloud_enum_read_only_guard_blocks_write_action():
    import pytest as _pytest
    with _pytest.raises(ValueError):
        cloud_enum._assert_read_only("CreateUser")
    # sanity: a real read action passes
    cloud_enum._assert_read_only("DescribeInstances")


def test_cloud_enum_inactive_without_inventory():
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = None
    res = cloud_enum.run(t)
    assert res.exploited is False
    assert "no cloud credentials" in (res.error or "")


def test_cloud_enum_metadata():
    assert cloud_enum.SUPPORTS == {"cloud"}
    assert cloud_enum.INTENSITY == "active"

