"""Tests for the attack-chain correlation engine (exploits/attack_chain.py)."""
from __future__ import annotations

from exploits import attack_chain
from exploits.base import ExploitResult, Finding


def _res(name, findings):
    return ExploitResult(name=name, description="", exploited=bool(findings), findings=findings)


def _f(title, severity="HIGH", location="t", detail="", evidence=""):
    return Finding(title=title, severity=severity, location=location, detail=detail,
                   evidence=evidence)


# --------------------------------------------------------------------- positive chains
def test_source_to_secret_to_jwt_chain_fires():
    results = [
        _res("path-probe", [_f("Exposed .git/config (source retrievable)", "HIGH")]),
        _res("secret-harvester", [_f("Leaked secret: jwt signing secret in config", "HIGH")]),
        _res("jwt-attacker", [_f("alg:none token accepted (auth bypass)", "CRITICAL")]),
    ]
    out = attack_chain.correlate(results)
    assert out.exploited
    titles = [f.title for f in out.findings]
    assert any("Source disclosure" in t for t in titles)
    chain = next(f for f in out.findings if "Source disclosure" in f.title)
    assert chain.severity == "CRITICAL"
    assert "->" in chain.evidence


def test_unauth_datastore_plus_proof_chain():
    results = [
        _res("unauth-service-probe", [_f("Unauthenticated Redis on 6379", "CRITICAL")]),
        _res("access-prover", [_f("Harmless marker key SET on Redis", "HIGH")]),
    ]
    out = attack_chain.correlate(results)
    assert any("datastore" in f.title.lower() for f in out.findings)


def test_open_service_plus_cve_chain():
    results = [
        _res("nmap-probe", [_f("Open 22/tcp on 10.0.0.5: ssh OpenSSH 9.2p1", "MEDIUM")]),
        _res("cve-enrich", [_f("CVE-2024-6387: openssh 9.2 affected (HIGH)", "HIGH")]),
    ]
    out = attack_chain.correlate(results)
    assert any("known CVE" in f.title for f in out.findings)


def test_default_creds_chain():
    results = [
        _res("path-probe", [_f("Grafana login panel exposed", "LOW")]),
        _res("default-creds", [_f("Default credentials accepted: admin/admin on Grafana", "CRITICAL")]),
    ]
    out = attack_chain.correlate(results)
    assert any("default credentials" in f.title.lower() for f in out.findings)


# --------------------------------------------------------------------- negative cases
def test_no_chain_when_links_missing():
    results = [
        _res("path-probe", [_f("Exposed .git/config", "HIGH")]),
        # no secret, no jwt -> chain must not fire
    ]
    out = attack_chain.correlate(results)
    assert not out.exploited
    assert any(f.severity == "INFO" for f in out.findings)


def test_severity_floor_respected():
    # a LOW unauth finding should NOT satisfy the HIGH-floor datastore stage
    results = [
        _res("unauth-service-probe", [_f("Redis reachable but requires auth", "LOW")]),
        _res("access-prover", [_f("marker", "HIGH")]),
    ]
    out = attack_chain.correlate(results)
    assert not any("datastore" in f.title.lower() for f in out.findings)


def test_empty_results():
    out = attack_chain.correlate([])
    assert not out.exploited
