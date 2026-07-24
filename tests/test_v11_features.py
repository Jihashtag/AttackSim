"""Tests for the v11 web/network coverage features and related fixes.

Covers: cors-probe, ssrf-probe, waf-detect, nosqli-confirm, dns-attack-probe, api-enum,
netutil retry/backoff, and IPv6 CIDR support in --cidr/--scope.
"""
import json

import pytest

from exploits import (cors_probe, ssrf_probe, waf_detect, nosqli_confirm,
                      dns_attack_probe, api_enum, netutil, forbidden_bypass,
                      post_exploit, graphql_mutation_executor, grpc_method_invoker)


# ---------------------------------------------------------------------------
# cors-probe
# ---------------------------------------------------------------------------
def _cors_target(fake_target):
    return fake_target(kind="url", url="http://victim.example/api")


def test_cors_reflection_with_credentials_critical(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        return 200, "", {"access-control-allow-origin": origin,
                         "access-control-allow-credentials": "true"}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    res = cors_probe.run(_cors_target(fake_target))
    assert res.exploited is True
    assert any(f.severity == "CRITICAL" and "reflect" in f.title.lower()
               for f in res.findings)


def test_cors_wildcard_with_credentials_critical(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        return 200, "", {"access-control-allow-origin": "*",
                         "access-control-allow-credentials": "true"}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    res = cors_probe.run(_cors_target(fake_target))
    assert res.exploited is True
    assert any(f.severity == "CRITICAL" for f in res.findings)


def test_cors_null_origin_high(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin == "null":
            return 200, "", {"access-control-allow-origin": "null",
                             "access-control-allow-credentials": "true"}
        return 200, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    res = cors_probe.run(_cors_target(fake_target))
    assert any(f.severity == "HIGH" and "null" in f.title.lower() for f in res.findings)


def test_cors_strict_allowlist_no_finding(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        return 200, "", {"access-control-allow-origin": "https://trusted.example",
                         "access-control-allow-credentials": "true"}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    res = cors_probe.run(_cors_target(fake_target))
    assert res.exploited is False
    assert not [f for f in res.findings if f.severity in ("CRITICAL", "HIGH")]


def test_cors_budget_acquired_per_request(fake_target, monkeypatch):
    calls = {"n": 0}

    class Budget:
        def acquire(self, n=1):
            calls["n"] += 1
            return True
    t = _cors_target(fake_target)
    t.budget = Budget()
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (200, "", {}))
    cors_probe.run(t)
    assert calls["n"] >= 2  # one per tested origin


# ---------------------------------------------------------------------------
# ssrf-probe
# ---------------------------------------------------------------------------
def test_ssrf_file_scheme_critical(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        # The injected value is URL-encoded in the query string ("file%3A%2F%2F..."),
        # so match on the un-encoded tail 'passwd' that survives encoding.
        if "passwd" in url:
            return 200, "root:x:0:0:root:/root:/bin/bash\n", {}
        return 200, "normal", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    t = fake_target(kind="url", url="http://victim.example/fetch?url=x")
    res = ssrf_probe.run(t)
    assert res.exploited is True
    assert any("file://" in f.title for f in res.findings)


def test_ssrf_metadata_critical(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        if "169.254.169.254" in url:
            return 200, "ami-id\ninstance-id\niam/", {}
        return 200, "base", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    t = fake_target(kind="url", url="http://victim.example/img?image=y")
    res = ssrf_probe.run(t)
    assert any("metadata" in f.title.lower() for f in res.findings)


def test_ssrf_oob_callback_critical(fake_target, monkeypatch):
    class OOB:
        def new_token(self):
            return "tok123"

        def was_hit(self, token):
            return token == "tok123"
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (200, "", {}))
    t = fake_target(kind="url", url="http://victim.example/f?url=z")
    t.oob_listener = OOB()
    t.canary_url = "http://oob.example"
    res = ssrf_probe.run(t)
    assert res.exploited is True
    assert any("out-of-band" in f.title.lower() for f in res.findings)


def test_ssrf_no_change_no_finding(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (200, "identical body", {}))
    t = fake_target(kind="url", url="http://victim.example/fetch?url=x")
    res = ssrf_probe.run(t)
    assert res.exploited is False


def test_ssrf_non_candidate_param_not_tested(fake_target, monkeypatch):
    # A URL whose only param is non-candidate ('color') should still test injected
    # candidate names but never treat 'color' as a family.
    t = fake_target(kind="url", url="http://victim.example/p?color=red")
    params = ssrf_probe._select_params(t.url)
    assert "color" not in params


# ---------------------------------------------------------------------------
# waf-detect
# ---------------------------------------------------------------------------
def test_waf_passive_cloudflare(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "http_get",
                        lambda *a, **k: (200, "", {"server": "cloudflare",
                                                   "cf-ray": "89a2-CDG"}))
    t = fake_target(kind="url", url="http://victim.example/")
    res = waf_detect.run(t)
    assert res.findings and "cloudflare" in res.findings[0].title.lower()


def test_waf_active_blocking(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        if "q=" in url:  # payload request
            return 403, "Request blocked by our web application firewall", {}
        return 200, "home", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    t = fake_target(kind="url", url="http://victim.example/")
    res = waf_detect.run(t)
    assert res.findings and "waf" in " ".join(res.findings[0].tags).lower()


def test_waf_none_detected(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "http_get",
                        lambda *a, **k: (200, "hello", {"server": "nginx"}))
    t = fake_target(kind="url", url="http://victim.example/")
    res = waf_detect.run(t)
    assert res.findings and "not-detected" in res.findings[0].tags


# ---------------------------------------------------------------------------
# nosqli-confirm
# ---------------------------------------------------------------------------
def test_nosqli_mongo_ne_auth_bypass(fake_target, monkeypatch):
    def fake_post(url, method, headers=None, body=None, **kw):
        payload = json.loads(body.decode())
        if isinstance(payload.get("username"), dict):  # {"$ne": null}
            return 200, '{"token":"abc"}', {}
        return 401, "unauthorized", {}
    monkeypatch.setattr(netutil, "http_request", fake_post)
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (401, "", {}))
    t = fake_target(kind="url", url="http://victim.example/api/login")
    res = nosqli_confirm.run(t)
    assert res.exploited is True
    assert any("auth" in f.title.lower() and "mongo" in f.title.lower()
               for f in res.findings)


def test_nosqli_no_bypass_no_finding(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "http_request", lambda *a, **k: (401, "no", {}))
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (200, "same", {}))
    t = fake_target(kind="url", url="http://victim.example/api/login")
    res = nosqli_confirm.run(t)
    assert res.exploited is False


# ---------------------------------------------------------------------------
# dns-attack-probe
# ---------------------------------------------------------------------------
def test_dns_axfr_internal_records_critical(fake_target, monkeypatch):
    monkeypatch.setattr(dns_attack_probe.shutil, "which", lambda _b: "/usr/bin/dig")
    monkeypatch.setattr(dns_attack_probe.dnsutil, "resolve",
                        lambda *a, **k: ["10 ns1.target.com."])
    monkeypatch.setattr(dns_attack_probe, "_attempt_axfr",
                        lambda ns, zone: "www\tA\t10.0.0.5\n_acme-challenge\tTXT\tx\n")
    monkeypatch.setattr(dns_attack_probe, "_test_rebinding", lambda *a, **k: None)
    t = fake_target(kind="host", host="target.com")
    res = dns_attack_probe.run(t)
    assert res.exploited is True
    assert any(f.severity == "CRITICAL" and "axfr" in " ".join(f.tags)
               for f in res.findings)


def test_dns_axfr_refused_no_finding(fake_target, monkeypatch):
    monkeypatch.setattr(dns_attack_probe.shutil, "which", lambda _b: "/usr/bin/dig")
    monkeypatch.setattr(dns_attack_probe.dnsutil, "resolve",
                        lambda *a, **k: ["10 ns1.target.com."])
    monkeypatch.setattr(dns_attack_probe, "_attempt_axfr", lambda ns, zone: None)
    monkeypatch.setattr(dns_attack_probe, "_test_rebinding", lambda *a, **k: None)
    t = fake_target(kind="host", host="target.com")
    res = dns_attack_probe.run(t)
    assert res.exploited is False


def test_dns_rebinding_medium(fake_target, monkeypatch):
    monkeypatch.setattr(dns_attack_probe.shutil, "which", lambda _b: None)  # no dig
    monkeypatch.setattr(dns_attack_probe, "_test_rebinding",
                        lambda *a, **k: {"varied": True, "short_ttl": False,
                                         "answers": [["1.2.3.4"], ["5.6.7.8"]]})
    t = fake_target(kind="host", host="target.com")
    res = dns_attack_probe.run(t)
    assert any(f.severity == "MEDIUM" and "rebinding" in f.title.lower()
               for f in res.findings)


# ---------------------------------------------------------------------------
# api-enum
# ---------------------------------------------------------------------------
def test_api_enum_openapi_spec_exposed(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        if "openapi.json" in url:
            return 200, '{"openapi":"3.0.0","paths":{}}', {}
        return 404, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    monkeypatch.setattr(netutil, "http_request", lambda *a, **k: (404, "", {}))
    t = fake_target(kind="url", url="http://victim.example/")
    res = api_enum.run(t)
    assert any("specification" in f.title.lower() for f in res.findings)


def test_api_enum_actuator_env_high(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        if "actuator/env" in url:
            return 200, '{"propertySources":[]}', {}
        return 404, "", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    monkeypatch.setattr(netutil, "http_request", lambda *a, **k: (404, "", {}))
    t = fake_target(kind="url", url="http://victim.example/")
    res = api_enum.run(t)
    assert res.exploited is True
    assert any(f.severity == "HIGH" and "actuator/env" in f.location for f in res.findings)


def test_api_enum_nothing_exposed(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (404, "", {}))
    monkeypatch.setattr(netutil, "http_request", lambda *a, **k: (404, "", {}))
    t = fake_target(kind="url", url="http://victim.example/")
    res = api_enum.run(t)
    assert res.exploited is False
    assert not res.findings


# ---------------------------------------------------------------------------
# netutil retry/backoff (M3)
# ---------------------------------------------------------------------------
def test_netutil_retries_transient_503(monkeypatch):
    seq = [(503, "", {}), (200, "ok", {})]
    calls = {"n": 0}

    def once(*a, **k):
        calls["n"] += 1
        return seq[min(calls["n"] - 1, len(seq) - 1)]
    monkeypatch.setattr(netutil, "_http_get_once", once)
    monkeypatch.setattr(netutil._time, "sleep", lambda *_a: None)
    monkeypatch.setattr(netutil, "_MAX_RETRIES", 2)
    status, body, _ = netutil.http_get("http://x/")
    assert status == 200 and calls["n"] == 2


def test_netutil_no_retry_on_500(monkeypatch):
    calls = {"n": 0}

    def once(*a, **k):
        calls["n"] += 1
        return 500, "err", {}
    monkeypatch.setattr(netutil, "_http_get_once", once)
    monkeypatch.setattr(netutil._time, "sleep", lambda *_a: None)
    monkeypatch.setattr(netutil, "_MAX_RETRIES", 3)
    status, _b, _h = netutil.http_get("http://x/")
    assert status == 500 and calls["n"] == 1  # 500 is definitive: no retry


def test_netutil_retry_disabled(monkeypatch):
    calls = {"n": 0}

    def once(*a, **k):
        calls["n"] += 1
        return 503, "", {}
    monkeypatch.setattr(netutil, "_http_get_once", once)
    monkeypatch.setattr(netutil, "_MAX_RETRIES", 0)
    netutil.http_get("http://x/")
    assert calls["n"] == 1  # retries disabled -> single attempt


def test_netutil_honours_retry_after(monkeypatch):
    slept = {"secs": []}
    monkeypatch.setattr(netutil._time, "sleep", lambda s: slept["secs"].append(s))
    monkeypatch.setattr(netutil, "_MAX_RETRIES", 1)
    # 429 retry is opt-in (off by default so lockout-abort works); enable it here.
    monkeypatch.setattr(netutil, "_RETRY_ON_429", True)
    seq = [(429, "", {"retry-after": "3"}), (200, "ok", {})]
    calls = {"n": 0}
    monkeypatch.setattr(netutil, "_http_get_once",
                        lambda *a, **k: seq[min(calls.__setitem__("n", calls["n"] + 1)
                                                or calls["n"] - 1, 1)])
    netutil.http_get("http://x/")
    assert slept["secs"] and slept["secs"][0] == 3.0


# ---------------------------------------------------------------------------
# IPv6 support (M4)
# ---------------------------------------------------------------------------
def test_ipv6_cidr_netrange_parsing():
    from targets import model
    assert model._NETRANGE_RE.match("2001:db8::/126")
    assert model._NETRANGE_RE.match("[2001:db8::]/126")
    t = model._make_netrange("2001:db8::/126", None)
    assert t.kind == "netrange"
    assert "2001:db8::1" in t.hosts


def test_ipv6_scope_authorize():
    from sandbox import scope_guard
    g = scope_guard.ScopeGuard.from_specs(["2001:db8::/32"], intensity="intrusive")
    assert g.authorize("2001:db8::5")[0] is True
    assert g.authorize("2002::5")[0] is False


def test_ipv4_netrange_still_parses():
    from targets import model
    assert model._NETRANGE_RE.match("10.0.0.0/24")
    assert model._NETRANGE_RE.match("10.0.0.0/24:8080")
    assert not model._NETRANGE_RE.match("not-a-range")


# ---------------------------------------------------------------------------
# forbidden-bypass + discovery-driven chaining
# ---------------------------------------------------------------------------
def _intrusive_target(fake_target, url):
    t = fake_target(kind="url", url=url)
    t.intensity = "intrusive"
    t.pivot_targets = []
    return t


def test_forbidden_bypass_path_trick(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        if "%2f" in url:                       # encoded-slash mutation bypasses
            return 200, "S" * 120, {}
        return 403, "forbidden", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    t = _intrusive_target(fake_target, "http://victim.example/admin")
    res = forbidden_bypass.run(t)
    assert res.exploited is True
    assert any("403" in f.title and "path" in f.title.lower() for f in res.findings)
    # Chain: the bypassed URL is published to the web-confirmation chain.
    assert getattr(t, "discovered_urls", []) and "%2f" in t.discovered_urls[0]


def test_forbidden_bypass_header_trick(fake_target, monkeypatch):
    def fake_get(url, headers=None, **kw):
        if headers and "X-Original-URL" in headers:
            return 200, "A" * 120, {}
        return 403, "forbidden", {}
    monkeypatch.setattr(netutil, "http_get", fake_get)
    t = _intrusive_target(fake_target, "http://victim.example/admin")
    res = forbidden_bypass.run(t)
    assert res.exploited is True
    assert any("header" in f.title.lower() for f in res.findings)


def test_forbidden_bypass_no_forbidden_endpoint(fake_target, monkeypatch):
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (200, "ok", {}))
    t = _intrusive_target(fake_target, "http://victim.example/public")
    res = forbidden_bypass.run(t)
    assert res.exploited is False


def test_forbidden_bypass_not_bypassable(fake_target, monkeypatch):
    # Everything stays 403 -> no bypass.
    monkeypatch.setattr(netutil, "http_get", lambda *a, **k: (403, "forbidden", {}))
    t = _intrusive_target(fake_target, "http://victim.example/admin")
    res = forbidden_bypass.run(t)
    assert res.exploited is False


# ---------------------------------------------------------------------------
# shared pivot helpers (post_exploit.publish_pivot / publish_url)
# ---------------------------------------------------------------------------
def test_publish_pivot_intrusive_only(fake_target):
    t = fake_target(kind="url", url="http://x/")
    t.pivot_targets = []
    t.intensity = "active"
    assert post_exploit.publish_pivot(t, host="10.0.0.9", via="test") is False
    assert t.pivot_targets == []
    t.intensity = "intrusive"
    assert post_exploit.publish_pivot(t, host="10.0.0.9", via="test") is True
    assert t.pivot_targets and t.pivot_targets[0]["host"] == "10.0.0.9"
    # Default common-port set applied so the host actually gets probed.
    assert 443 in t.pivot_targets[0]["ports"]


def test_publish_pivot_high_confidence_propagates_at_active(fake_target):
    # High-confidence discoveries (public cloud IPs, resolved DNS records) propagate
    # at the active tier; medium/default confidence still requires intrusive+.
    t = fake_target(kind="url", url="http://x/")
    t.pivot_targets = []
    t.intensity = "active"
    # default (medium) confidence: still gated to intrusive+
    assert post_exploit.publish_pivot(t, host="10.0.0.9", via="test") is False
    # high confidence: allowed at active
    assert post_exploit.publish_pivot(
        t, host="10.0.0.9", via="test", confidence="high") is True
    assert t.pivot_targets and t.pivot_targets[0]["host"] == "10.0.0.9"


def test_publish_pivot_detective_never_propagates(fake_target):
    # detective is pure reconnaissance: even high-confidence discoveries are not
    # auto-propagated.
    t = fake_target(kind="url", url="http://x/")
    t.pivot_targets = []
    t.intensity = "detective"
    assert post_exploit.publish_pivot(
        t, host="10.0.0.9", via="test", confidence="high") is False
    assert t.pivot_targets == []


def test_publish_pivot_dedup(fake_target):
    t = fake_target(kind="url", url="http://x/")
    t.pivot_targets = []
    t.intensity = "intrusive"
    assert post_exploit.publish_pivot(t, host="10.0.0.9", port=22, via="a") is True
    assert post_exploit.publish_pivot(t, host="10.0.0.9", port=22, via="b") is False
    assert len(t.pivot_targets) == 1


def test_publish_pivot_scope_checked(fake_target):
    class Guard:
        def authorize(self, value):
            return (False, "out of scope")
    t = fake_target(kind="url", url="http://x/")
    t.pivot_targets = []
    t.intensity = "intrusive"
    t.scope_guard = Guard()
    assert post_exploit.publish_pivot(t, host="10.0.0.9", via="test") is False


def test_publish_url_intrusive_only(fake_target):
    t = fake_target(kind="url", url="http://x/")
    t.intensity = "active"
    assert post_exploit.publish_url(t, "http://x/secret") is False
    t.intensity = "intrusive"
    assert post_exploit.publish_url(t, "http://x/secret") is True
    assert "http://x/secret" in t.discovered_urls


def test_cloud_enum_publishes_public_ip_pivots(fake_target, monkeypatch):
    from exploits import cloud_enum, cloudutil
    xml = ("<DescribeInstancesResponse><reservationSet><item><instancesSet>"
           "<item><instanceId>i-1</instanceId><ipAddress>203.0.113.5</ipAddress></item>"
           "</instancesSet></item></reservationSet></DescribeInstancesResponse>")
    monkeypatch.setattr(cloud_enum, "_query", lambda *a, **k: (200, xml))
    monkeypatch.setattr(cloudutil, "aws_error", lambda _b: False)
    t = fake_target(kind="cloud", url=None)
    t.host = "aws"
    t.intensity = "intrusive"
    t.pivot_targets = []
    cloud_enum._ec2_instances(t, cred={}, region="us-east-1")
    assert any(e["host"] == "203.0.113.5" for e in t.pivot_targets)


def test_cloud_enum_public_ip_pivots_at_active_tier(fake_target, monkeypatch):
    # Item 1: public cloud instance IPs are high-confidence discoveries and must
    # propagate on active-tier runs, not only intrusive+.
    from exploits import cloud_enum, cloudutil
    xml = ("<DescribeInstancesResponse><reservationSet><item><instancesSet>"
           "<item><instanceId>i-1</instanceId><ipAddress>203.0.113.7</ipAddress></item>"
           "</instancesSet></item></reservationSet></DescribeInstancesResponse>")
    monkeypatch.setattr(cloud_enum, "_query", lambda *a, **k: (200, xml))
    monkeypatch.setattr(cloudutil, "aws_error", lambda _b: False)
    t = fake_target(kind="cloud", url=None)
    t.host = "aws"
    t.intensity = "active"
    t.pivot_targets = []
    cloud_enum._ec2_instances(t, cred={}, region="us-east-1")
    assert any(e["host"] == "203.0.113.7" for e in t.pivot_targets)


# ---------------------------------------------------------------------------
# Item 2: credential-to-pivot chaining
# ---------------------------------------------------------------------------
def test_publish_credential_queues_cloud_pivot(fake_target):
    from sandbox.cloud_creds_extended import ExtendedCloudCredential
    t = fake_target(kind="repo")
    t.intensity = "intrusive"
    t.extended_cloud_creds = []
    t.pivot_targets = []
    cred = ExtendedCloudCredential(provider="digitalocean", source="foo.py:1", secret="dop_v1_" + "a" * 64)
    assert post_exploit.publish_credential(t, cred, via="secret-harvester") is True
    assert t.extended_cloud_creds == [cred]
    assert any(e["kind"] == "cloud" for e in t.pivot_targets)
    # Idempotent: same (provider, source) doesn't duplicate
    assert post_exploit.publish_credential(t, cred, via="secret-harvester") is False
    assert len(t.extended_cloud_creds) == 1
    assert len([e for e in t.pivot_targets if e["kind"] == "cloud"]) == 1


def test_publish_credential_gated_below_intrusive(fake_target):
    from sandbox.cloud_creds_extended import ExtendedCloudCredential
    t = fake_target(kind="repo")
    t.intensity = "active"
    t.extended_cloud_creds = []
    t.pivot_targets = []
    cred = ExtendedCloudCredential(provider="digitalocean", source="foo.py:1", secret="x")
    assert post_exploit.publish_credential(t, cred) is False
    assert t.extended_cloud_creds == []


def test_secret_scanner_digitalocean_token_triggers_credential_publish(fake_target, monkeypatch, tmp_path):
    from exploits import secret_scanner
    (tmp_path / "leak.env").write_text(
        "DIGITALOCEAN_TOKEN=dop_v1_" + "a" * 64 + "\n")
    t = fake_target(kind="repo", root=str(tmp_path))
    t.intensity = "intrusive"
    t.extended_cloud_creds = []
    t.pivot_targets = []
    monkeypatch.setattr("exploits.netutil.http_request",
                         lambda *a, **k: (403, "InvalidClientTokenId", None))
    secret_scanner.run(t)
    assert any(c.provider == "digitalocean" for c in t.extended_cloud_creds)
    assert any(e["kind"] == "cloud" for e in t.pivot_targets)


# ---------------------------------------------------------------------------
# Item 3: schema discoveries executed (graphql-mutation-executor, grpc-method-invoker)
# ---------------------------------------------------------------------------
def test_graphql_mutation_executor_invokes_discovered_mutation(fake_target, monkeypatch):
    t = fake_target(kind="url", url="http://victim.example/graphql")
    t.discovered_apis = [
        {"kind": "graphql", "endpoint": "http://victim.example/graphql",
         "name": "createWidget", "via": "graphql-probe"},
        {"kind": "graphql", "endpoint": "http://victim.example/graphql",
         "name": "deleteWidget", "via": "graphql-probe"},
    ]

    def fake_request(url, method, headers=None, body=None, **kw):
        return 200, '{"data": {"createWidget": {"id": 1}}}', {}
    monkeypatch.setattr(netutil, "http_request", fake_request)

    res = graphql_mutation_executor.run(t)
    assert res.exploited is True
    titles = [f.title for f in res.findings]
    assert any("createWidget" in t for t in titles)
    assert not any("deleteWidget" in t for t in titles)  # destructive name never invoked


def test_graphql_mutation_executor_no_discoveries(fake_target):
    t = fake_target(kind="url", url="http://victim.example/graphql")
    t.discovered_apis = []
    res = graphql_mutation_executor.run(t)
    assert res.exploited is False
    assert res.findings == []


def test_grpc_method_invoker_invokes_discovered_method(fake_target, monkeypatch):
    from exploits import toolrunner

    class _Res:
        available = True
        ok = True
        stdout = '{"status": "SERVING"}'
        stderr = ""

    monkeypatch.setattr(toolrunner, "available", lambda _b: True)
    monkeypatch.setattr(toolrunner, "run_tool", lambda *a, **k: _Res())

    t = fake_target(kind="hostport", host="10.0.0.5", port=50051)
    t.discovered_apis = [
        {"kind": "grpc", "host": "10.0.0.5", "port": 50051,
         "name": "grpc.health.v1.Health/Check", "via": "grpc-reflection"},
    ]
    res = grpc_method_invoker.run(t)
    assert res.exploited is True
    assert any("Health/Check" in f.title for f in res.findings)
