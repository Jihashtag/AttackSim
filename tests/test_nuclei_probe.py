"""Phase 3 tests: nuclei_probe argv safety, JSONL parsing, target derivation, skip."""
from __future__ import annotations

import json

from exploits import nuclei_probe
from targets import model


# --------------------------------------------------------------------- argv safety
def test_build_argv_excludes_dangerous_tags():
    argv = nuclei_probe.build_argv()
    assert "-exclude-tags" in argv
    tags = argv[argv.index("-exclude-tags") + 1].split(",")
    for bad in ("intrusive", "dos", "rce", "sqli", "ssrf", "oast"):
        assert bad in tags


def test_build_argv_disables_oast_and_update():
    argv = nuclei_probe.build_argv()
    assert "-no-interactsh" in argv
    assert "-disable-update-check" in argv
    assert "-jsonl" in argv
    assert "-rate-limit" in argv


# --------------------------------------------------------------------- target derivation
def test_build_targets_hostport_picks_scheme_by_port():
    t = model.resolve(positional="10.0.0.5:80,443")
    urls = nuclei_probe.build_targets(t)
    assert "http://10.0.0.5:80" in urls
    assert "https://10.0.0.5:443" in urls


def test_build_targets_netrange_uses_live_hosts():
    t = model.resolve(cidr="10.0.0.0/30", ports="443")
    t.live_hosts = ["10.0.0.1"]
    urls = nuclei_probe.build_targets(t)
    assert urls == ["https://10.0.0.1:443"]


def test_build_targets_url():
    t = model.Target(kind="url", raw="x", url="http://example.test/app")
    assert nuclei_probe.build_targets(t) == ["http://example.test/app"]


# --------------------------------------------------------------------- JSONL parsing
_SAMPLE = "\n".join([
    json.dumps({
        "template-id": "exposed-panel",
        "info": {"name": "Admin Panel", "severity": "medium",
                 "description": "An admin panel is exposed.",
                 "classification": {"cve-id": ["CVE-2021-1234"]},
                 "reference": ["https://example.test/adv"]},
        "matched-at": "http://10.0.0.5:80/admin",
    }),
    "garbage-not-json",
    json.dumps({
        "template-id": "info-disclosure",
        "info": {"name": "Server Header", "severity": "info"},
        "matched-at": "http://10.0.0.5:80/",
    }),
])


def test_parse_jsonl_skips_bad_lines():
    rows = nuclei_probe.parse_jsonl(_SAMPLE)
    assert len(rows) == 2
    assert rows[0]["template-id"] == "exposed-panel"


# --------------------------------------------------------------------- run() behaviour
def test_run_skips_cleanly_when_nuclei_absent(monkeypatch):
    monkeypatch.setattr(nuclei_probe.toolrunner, "available", lambda b: False)
    t = model.resolve(positional="10.0.0.5:80")
    res = nuclei_probe.run(t)
    assert res.exploited is False
    assert res.tool_available is False
    assert any("not installed" in f.title for f in res.findings)


def test_run_parses_findings_with_fake_nuclei(monkeypatch):
    monkeypatch.setattr(nuclei_probe.toolrunner, "available", lambda b: True)
    captured = {}

    class _TR:
        available = True
        timed_out = False
        error = ""
        output = _SAMPLE

    def _run_tool(argv, *a, **k):
        captured["argv"] = argv
        captured["input"] = k.get("input_text")
        return _TR()

    monkeypatch.setattr(nuclei_probe.toolrunner, "run_tool", _run_tool)
    t = model.resolve(positional="10.0.0.5:80")
    res = nuclei_probe.run(t)
    assert res.exploited is True  # the medium finding counts
    # CVE ref propagated
    refs = [r for f in res.findings for r in f.references]
    assert "CVE-2021-1234" in refs
    # safety flags really reached the tool
    assert "-no-interactsh" in captured["argv"]
    assert "http://10.0.0.5:80" in captured["input"]


def test_supports():
    assert nuclei_probe.SUPPORTS == {"url", "hostport", "netrange"}
