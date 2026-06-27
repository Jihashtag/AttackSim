"""Phase 4 tests: offline CVE enrichment matching + post-pass over findings."""
from __future__ import annotations

from exploits import cve_enrich
from exploits.base import ExploitResult, Finding


_FEED = [
    {"product": "openssh", "ranges": [{"introduced": "8.5", "fixed": "9.8"}],
     "cve": "CVE-2024-6387", "severity": "HIGH", "summary": "regreSSHion RCE.",
     "references": ["https://example.test/regresshion"]},
    {"product": "redis", "ranges": [{"introduced": "0", "fixed": "6.2.7"}],
     "cve": "CVE-2022-24735", "severity": "HIGH", "summary": "Lua sandbox escape."},
    {"product": "nginx", "ranges": [{"introduced": "0", "fixed": "1.21.0"}],
     "cve": "CVE-2021-23017", "severity": "HIGH", "summary": "resolver off-by-one."},
]


# --------------------------------------------------------------------- version matching
def test_match_hits_in_range():
    hits = cve_enrich.match("OpenSSH", "9.2", _FEED)
    assert [h["cve"] for h in hits] == ["CVE-2024-6387"]


def test_match_misses_when_fixed():
    assert cve_enrich.match("openssh", "9.8", _FEED) == []
    assert cve_enrich.match("openssh", "10.0", _FEED) == []


def test_match_below_introduced_is_miss():
    assert cve_enrich.match("openssh", "8.4", _FEED) == []


def test_match_no_version_is_conservative():
    # Without a parseable version we must not guess.
    assert cve_enrich.match("redis", "", _FEED) == []


def test_match_unknown_product():
    assert cve_enrich.match("postgres", "12.0", _FEED) == []


# --------------------------------------------------------------------- feed loading
def test_load_feed_real_file_has_records():
    feed = cve_enrich.load_feed()
    assert isinstance(feed, list) and feed
    assert all("cve" in r for r in feed)


def test_load_feed_missing_is_empty():
    assert cve_enrich.load_feed("/nonexistent/feed.json") == []


# --------------------------------------------------------------------- enrich post-pass
def test_enrich_attaches_refs_and_summarises():
    results = [ExploitResult(
        name="nmap-probe", description="", exploited=True,
        findings=[
            Finding(title="Open 22/tcp on 10.0.0.5: ssh OpenSSH 9.2p1",
                    severity="MEDIUM", location="10.0.0.5:22",
                    detail="nmap identified an exposed service running OpenSSH 9.2p1."),
            Finding(title="Open 6379/tcp on 10.0.0.5: redis Redis 6.0.5",
                    severity="MEDIUM", location="10.0.0.5:6379",
                    detail="redis 6.0.5"),
        ],
    )]
    summary = cve_enrich.enrich_results(results, feed=_FEED)
    assert summary.exploited is True
    # CVE refs attached to originating findings
    ssh_finding = results[0].findings[0]
    assert "CVE-2024-6387" in ssh_finding.references
    redis_finding = results[0].findings[1]
    assert "CVE-2022-24735" in redis_finding.references
    # summary contains both CVEs
    cves = " ".join(f.title for f in summary.findings)
    assert "CVE-2024-6387" in cves
    assert "CVE-2022-24735" in cves


def test_enrich_no_match_reports_info():
    results = [ExploitResult(
        name="port-probe", description="", exploited=True,
        findings=[Finding(title="Open 5432/tcp on h: postgres 16.1",
                          severity="MEDIUM", location="h:5432", detail="postgres 16.1")],
    )]
    summary = cve_enrich.enrich_results(results, feed=_FEED)
    assert summary.exploited is False
    assert any(f.severity == "INFO" for f in summary.findings)


def test_enrich_empty_feed_skips():
    summary = cve_enrich.enrich_results([], feed=[])
    assert summary.exploited is False
    assert summary.tool_available is False
