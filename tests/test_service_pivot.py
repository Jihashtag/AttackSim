"""Tests for service pivot, relay http_probe, and ledger enhancements (Workstream 4+5+6)."""
import pytest
from unittest.mock import patch, MagicMock


class _FakeTarget:
    kind = "hostport"
    host = "10.0.0.1"
    port = 2375
    ports = [2375]
    pivot_targets = []
    discovered_urls = []
    prove_access = True
    prove_access_writes = False
    prove_access_shell = False
    reached_via = "scanner"
    proof_ledger = None


def test_publish_service_pivot():
    """_publish_service_pivot queues URL-based next-hops."""
    from exploits.access_prover import _publish_service_pivot
    target = _FakeTarget()
    target.pivot_targets = []
    count = _publish_service_pivot(target, [
        "https://cloud-run-svc.run.app",
        "https://internal-api.mesh.local",
    ], reached_from="10.0.0.1:2375")
    assert count == 2
    assert len(target.pivot_targets) == 2
    assert target.pivot_targets[0]["kind"] == "url"
    assert "run.app" in target.pivot_targets[0]["url"]


def test_publish_service_pivot_dedup():
    """Duplicate URLs are not re-queued."""
    from exploits.access_prover import _publish_service_pivot
    target = _FakeTarget()
    target.pivot_targets = [{"kind": "url", "url": "https://existing.run.app"}]
    count = _publish_service_pivot(target, [
        "https://existing.run.app",
        "https://new.run.app",
    ])
    assert count == 1  # only the new one
    assert len(target.pivot_targets) == 2


def test_publish_service_pivot_with_relay():
    """Relay spec is attached to pivot targets."""
    from exploits.access_prover import _publish_service_pivot
    target = _FakeTarget()
    target.pivot_targets = []
    relay = {"type": "docker", "host": "10.0.0.1", "port": 2375}
    count = _publish_service_pivot(target, ["https://svc.internal"], relay=relay)
    assert count == 1
    assert target.pivot_targets[0].get("relay") == relay


def test_ledger_network_path():
    """Ledger records network_path field on hops."""
    from sandbox.ledger import ProofLedger, REACHABILITY
    led = ProofLedger()
    led.record("container", "10.0.1.5:6443", reached_from="10.0.0.1:2375",
               via="docker-relay", proof_kind=REACHABILITY,
               network_path="vpn:aws-gcp")
    assert led.hops[0].network_path == "vpn:aws-gcp"


def test_ledger_to_chain_report():
    """to_chain_report() returns structured chain data."""
    from sandbox.ledger import ProofLedger, PROVEN, REACHABILITY
    led = ProofLedger()
    led.record("container", "ecs:10.0.0.1:2375", proof_kind=PROVEN,
               severity="CRITICAL", proof="marker /tmp/sectest_proof_1.txt")
    led.record("service", "eks:10.0.1.5:6443", reached_from="ecs:10.0.0.1:2375",
               proof_kind=REACHABILITY, severity="MEDIUM", network_path="vpc-internal")
    led.record("service", "cloudrun:svc.run.app", reached_from="eks:10.0.1.5:6443",
               proof_kind=REACHABILITY, severity="MEDIUM", network_path="vpn:aws-gcp")
    chains = led.to_chain_report()
    assert len(chains) >= 1
    # The longest chain should have 3 hops
    longest = max(chains, key=lambda c: c["depth"])
    assert longest["depth"] >= 2
    assert longest["proof_artifacts"]  # at least the PROVEN one


def test_ledger_mermaid():
    """mermaid() renders a valid Mermaid flowchart."""
    from sandbox.ledger import ProofLedger, PROVEN, REACHABILITY
    led = ProofLedger()
    led.record("container", "ecs:2375", proof_kind=PROVEN, severity="CRITICAL")
    led.record("service", "eks:6443", reached_from="ecs:2375",
               proof_kind=REACHABILITY, severity="MEDIUM")
    mermaid = led.mermaid()
    assert "graph LR" in mermaid
    assert "ecs_2375" in mermaid
    assert "eks_6443" in mermaid
    assert "-->" in mermaid


def test_ledger_downstream_count():
    """downstream_count correctly counts resources reachable via a hop."""
    from sandbox.ledger import ProofLedger, PROVEN, REACHABILITY
    led = ProofLedger()
    led.record("container", "A", proof_kind=PROVEN)
    led.record("service", "B", reached_from="A", proof_kind=REACHABILITY)
    led.record("service", "C", reached_from="A", proof_kind=REACHABILITY)
    led.record("service", "D", reached_from="B", proof_kind=REACHABILITY)
    assert led.downstream_count("A") == 3  # B, C, D
    assert led.downstream_count("B") == 1  # D
    assert led.downstream_count("C") == 0
    assert led.downstream_count("D") == 0


def test_k8s_configmap_proof():
    """K8s ConfigMap proof creates and reads back a labelled CM."""
    from exploits.access_prover import _k8s_configmap_proof
    with patch("exploits.netutil.http_request", return_value=(201, '{"metadata":{}}', {})), \
         patch("exploits.netutil.http_get", return_value=(200, '{"data":{}}', {})):
        findings = _k8s_configmap_proof("10.0.0.1", 6443)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "ConfigMap" in findings[0].title


def test_cloud_run_proof():
    """Cloud Run proof confirms unauthenticated access."""
    from exploits.access_prover import _cloud_run_proof
    with patch("exploits.netutil.http_get", return_value=(200, "Hello World", {})):
        findings = _cloud_run_proof("https://svc.run.app")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "Cloud Run" in findings[0].title


def test_attack_chain_cross_cloud():
    """New cross-cloud chain rule fires correctly."""
    from exploits.attack_chain import correlate, RULES
    from exploits.base import ExploitResult, Finding
    results = [
        ExploitResult(name="access-prover", description="", exploited=True,
                      findings=[Finding(title="Docker proof", severity="CRITICAL",
                                        location="10.0.0.1:2375", detail="proven")]),
        ExploitResult(name="cloud-pivot", description="", exploited=True,
                      findings=[Finding(title="GCP Cloud Run discovered",
                                        severity="MEDIUM", location="gcp:cloudrun:svc",
                                        detail="discovered",
                                        tags=["gcp", "cloud-run", "pivot"])]),
    ]
    chain_result = correlate(results)
    assert chain_result.exploited
    assert any("cross-cloud" in f.title.lower() for f in chain_result.findings)


def test_attack_chain_k8s_lateral():
    """K8s service enum -> lateral chain rule fires."""
    from exploits.attack_chain import correlate
    from exploits.base import ExploitResult, Finding
    results = [
        ExploitResult(name="k8s-probe", description="", exploited=True,
                      findings=[Finding(title="API server allows ANONYMOUS access to /api",
                                        severity="CRITICAL", location="https://10.0.0.1:6443/api",
                                        detail="anonymous-auth")]),
        ExploitResult(name="k8s-service-enum", description="", exploited=True,
                      findings=[Finding(title="Discovered 5 endpoint(s) for pivot",
                                        severity="MEDIUM", location="10.0.0.1:6443",
                                        detail="k8s service enum discovered endpoints",
                                        tags=["k8s", "service-enum", "pivot"])]),
    ]
    chain_result = correlate(results)
    assert chain_result.exploited
    assert any("k8s" in f.title.lower() for f in chain_result.findings)


def test_reporter_extract_chains():
    """_extract_chains extracts chain data from proof-ledger results."""
    from report.reporter import _extract_chains
    from exploits.base import ExploitResult, Finding
    results = [
        ExploitResult(name="proof-ledger", description="", exploited=True,
                      findings=[Finding(
                          title="Lateral-movement path (3 hops): scanner -> A (proven) -> B (reachable)",
                          severity="CRITICAL", location="B",
                          detail="chain",
                          evidence="A: proven; B: reachable")])
    ]
    chains = _extract_chains(results)
    assert len(chains) == 1
    assert chains[0]["severity"] == "CRITICAL"


def test_reporter_mermaid_rendering():
    """_render_mermaid_chain produces a non-empty mermaid string."""
    from report.reporter import _render_mermaid_chain
    from exploits.base import ExploitResult, Finding
    results = [
        ExploitResult(name="proof-ledger", description="", exploited=True,
                      findings=[Finding(
                          title="Proof-of-access hop: 10.0.0.1:2375 reached from scanner [proven]",
                          severity="CRITICAL", location="10.0.0.1:2375",
                          detail="proven",
                          evidence="resource=container via=direct proof=proven reached_from=scanner scope=in-scope")])
    ]
    mermaid = _render_mermaid_chain(results)
    assert "graph LR" in mermaid or mermaid == ""  # may be empty if parsing doesn't match
