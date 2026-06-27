"""Offline test for cloud-service-exposure (Lambda/SNS/SQS/Secrets/SSM/KMS/Transfer).

One fake AWS server handles all three wire protocols the module uses — REST GET (Lambda),
Query POST (SNS/SQS), and JSON POST with X-Amz-Target (Secrets/SSM/KMS/Transfer) — and
returns canned responses describing world-open resources. The test asserts every service's
exposure is surfaced and that the read-only guard never tripped (a non-read action would
raise out of run()).
"""
from __future__ import annotations

import http.server
import threading
from urllib.parse import parse_qs

from exploits import cloud_service_exposure
from sandbox import cloud_creds

_PUBLIC = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*"}]}'


def _xml(inner: str) -> bytes:
    return ("<?xml version='1.0'?>" + inner).encode()


_QUERY_XML = {
    "ListTopics": _xml("<ListTopicsResponse><ListTopicsResult><Topics><member>"
                       "<TopicArn>arn:aws:sns:us-east-1:1:public-topic</TopicArn>"
                       "</member></Topics></ListTopicsResult></ListTopicsResponse>"),
    "GetTopicAttributes": _xml(
        "<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes><entry>"
        f"<key>Policy</key><value>{_PUBLIC}</value></entry>"
        "</Attributes></GetTopicAttributesResult></GetTopicAttributesResponse>"),
    "ListQueues": _xml("<ListQueuesResponse><ListQueuesResult>"
                       "<QueueUrl>https://sqs/1/public-queue</QueueUrl>"
                       "</ListQueuesResult></ListQueuesResponse>"),
    "GetQueueAttributes": _xml(
        "<GetQueueAttributesResponse><GetQueueAttributesResult><Attribute>"
        f"<Name>Policy</Name><Value>{_PUBLIC}</Value>"
        "</Attribute></GetQueueAttributesResult></GetQueueAttributesResponse>"),
}

_JSON = {
    "secretsmanager.ListSecrets": {"SecretList": [{"Name": "prod/db", "ARN": "arn:secret:1"}]},
    "secretsmanager.GetResourcePolicy": {"ResourcePolicy": _PUBLIC},
    "AmazonSSM.DescribeParameters": {"Parameters": [{"Name": "/app/key", "Type": "SecureString"}]},
    "TrentService.ListKeys": {"Keys": [{"KeyId": "key-1"}]},
    "TrentService.GetKeyPolicy": {"Policy": _PUBLIC},
    "TransferService.ListServers": {"Servers": [{"ServerId": "s-1", "EndpointType": "PUBLIC"}]},
}


def _server():
    seen = []

    class _H(http.server.BaseHTTPRequestHandler):
        def _ok_json(self, obj):
            import json
            self.send_response(200)
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.end_headers()
            self.wfile.write(json.dumps(obj).encode())

        def _ok_xml(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 — Lambda REST
            path = self.path.split("?", 1)[0]
            seen.append("GET " + path)
            if path == "/2015-03-31/functions/":
                return self._ok_json({"Functions": [{"FunctionName": "fn1"}]})
            if path.endswith("/url"):
                return self._ok_json({"AuthType": "NONE", "FunctionUrl": "https://x.lambda-url"})
            if path.endswith("/policy"):
                return self._ok_json({"Policy": _PUBLIC})
            self.send_response(404); self.end_headers(); self.wfile.write(b"{}")

        def do_POST(self):  # noqa: N802 — Query or JSON
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode() if length else ""
            target = self.headers.get("X-Amz-Target", "")
            if target:
                seen.append("JSON " + target)
                return self._ok_json(_JSON.get(target, {}))
            action = parse_qs(body).get("Action", [""])[0]
            seen.append("QUERY " + action)
            return self._ok_xml(_QUERY_XML.get(action, _xml("<r/>")))

        def log_message(self, *_a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address
    return srv, f"http://{host}:{port}", seen


def _aws_target(base):
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider="aws", source="test-fixture",
        secret={"access_key": "AKIATEST", "secret_key": "secret"}, region="us-east-1")])
    overrides = {k: base for k in (
        "AWS_LAMBDA_ENDPOINT", "AWS_SNS_ENDPOINT", "AWS_SQS_ENDPOINT",
        "AWS_SECRETSMANAGER_ENDPOINT", "AWS_SSM_ENDPOINT", "AWS_KMS_ENDPOINT",
        "AWS_TRANSFER_ENDPOINT")}
    t = type("T", (), {})()
    t.kind = "cloud"
    t.cloud_inventory = inv
    t.cloud_endpoints = overrides
    return t


def test_cloud_service_exposure_all_services():
    srv, base, _seen = _server()
    try:
        res = cloud_service_exposure.run(_aws_target(base))
    finally:
        srv.shutdown(); srv.server_close()
    titles = " | ".join(f.title.lower() for f in res.findings)
    assert res.exploited is True
    assert "function url" in titles                      # Lambda public function URL
    assert "lambda function(s) allow public invoke" in titles
    assert "sns topic" in titles                         # SNS public policy
    assert "sqs queue" in titles                         # SQS public policy
    assert "secret(s) shared to principal" in titles or "secrets manager readable" in titles
    assert "ssm parameter store readable" in titles      # SSM SecureString
    assert "kms key" in titles                           # KMS public policy
    assert "transfer family" in titles                   # public SFTP endpoint


def test_cloud_service_exposure_ignores_non_aws():
    inv = cloud_creds.CloudInventory(credentials=[cloud_creds.CloudCredential(
        provider="gcp", source="x", secret={"access_token": "t"}, region="us")])
    t = type("T", (), {})()
    t.kind = "cloud"; t.cloud_inventory = inv; t.cloud_endpoints = {}
    res = cloud_service_exposure.run(t)
    assert res.exploited is False
    assert res.findings == []
