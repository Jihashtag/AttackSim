"""Tests for the F12 reporter outputs: SARIF, HTML, and baseline diff."""
from __future__ import annotations

import json

from exploits.base import ExploitResult, Finding
from report import reporter


def _results():
    return [
        ExploitResult(
            name="path-probe", description="d", exploited=True,
            findings=[Finding(title="Heap dump exposed", severity="CRITICAL",
                              location="http://h/actuator/heapdump", detail="leaks creds",
                              cwe="CWE-200", category="exposed-actuator")],
            attacker_value="creds", mitigation="disable actuator"),
        ExploitResult(
            name="tls-grader", description="d", exploited=False,
            findings=[Finding(title="TLS 1.0 enabled", severity="MEDIUM",
                              location="h:443", detail="weak tls", category="weak-tls")]),
    ]


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------
def test_write_sarif_is_valid_structure(tmp_path):
    p = tmp_path / "out.sarif"
    reporter.write_sarif(_results(), "http://h", str(p))
    data = json.loads(p.read_text())
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "security_test"
    # one rule per distinct module/category, two results total
    assert len(run["results"]) == 2
    crit = [r for r in run["results"] if r["level"] == "error"]
    assert crit and crit[0]["properties"]["security-severity"] == "9.5"
    assert crit[0]["properties"]["module"] == "path-probe"


def test_sarif_rules_have_ids(tmp_path):
    p = tmp_path / "out.sarif"
    reporter.write_sarif(_results(), "http://h", str(p))
    data = json.loads(p.read_text())
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    ids = {r["id"] for r in rules}
    assert "path-probe/exposed-actuator" in ids


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def test_write_html_contains_findings(tmp_path):
    p = tmp_path / "out.html"
    reporter.write_html(_results(), "http://h", str(p), llm_text="briefing text")
    html = p.read_text()
    assert "<!doctype html>" in html.lower()
    assert "Heap dump exposed" in html
    assert "EXPLOITATION SUCCESSFUL" in html
    assert "briefing text" in html


def test_html_escapes_payloads(tmp_path):
    res = [ExploitResult(name="m", description="d", exploited=True,
                         findings=[Finding(title="<script>alert(1)</script>",
                                           severity="HIGH", location="h", detail="x")],
                         attacker_value="v", mitigation="fix")]
    p = tmp_path / "x.html"
    reporter.write_html(res, "t", str(p))
    html = p.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Baseline diff
# ---------------------------------------------------------------------------
def test_diff_against_baseline_classifies(tmp_path):
    # baseline contains the TLS finding + an OLD finding that is now fixed.
    baseline = {
        "modules": [
            {"name": "tls-grader", "findings": [
                {"title": "TLS 1.0 enabled", "severity": "MEDIUM", "location": "h:443",
                 "category": "weak-tls"}]},
            {"name": "path-probe", "findings": [
                {"title": "Old .git exposed", "severity": "HIGH", "location": "http://h/.git",
                 "category": "exposed-vcs"}]},
        ]
    }
    diff = reporter.diff_against_baseline(_results(), baseline)
    new_titles = {i["title"] for i in diff["new"]}
    fixed_titles = {i["title"] for i in diff["fixed"]}
    unchanged_titles = {i["title"] for i in diff["unchanged"]}
    assert "Heap dump exposed" in new_titles          # not in baseline -> new
    assert "Old .git exposed" in fixed_titles          # in baseline, gone now -> fixed
    assert "TLS 1.0 enabled" in unchanged_titles       # present in both -> unchanged


def test_gate_new_only(tmp_path):
    baseline = {"modules": [
        {"name": "path-probe", "findings": [
            {"title": "Heap dump exposed", "severity": "CRITICAL",
             "location": "http://h/actuator/heapdump", "category": "exposed-actuator"}]},
        {"name": "tls-grader", "findings": [
            {"title": "TLS 1.0 enabled", "severity": "MEDIUM", "location": "h:443",
             "category": "weak-tls"}]},
    ]}
    diff = reporter.diff_against_baseline(_results(), baseline)
    # everything is in the baseline -> no NEW findings -> gate passes (no fail)
    assert diff["new"] == []
    assert reporter.gate_new_only(diff, None) is False


def test_gate_new_only_fails_on_new_critical():
    diff = {"new": [{"severity": "CRITICAL", "module": "m", "title": "t", "location": "l"}]}
    assert reporter.gate_new_only(diff, None) is True
    assert reporter.gate_new_only(diff, "high") is True
    assert reporter.gate_new_only(diff, "critical") is True
    # a new LOW must not fail a 'high' gate
    diff_low = {"new": [{"severity": "LOW", "module": "m", "title": "t", "location": "l"}]}
    assert reporter.gate_new_only(diff_low, "high") is False


def test_load_baseline_missing_returns_none(tmp_path):
    assert reporter.load_baseline(str(tmp_path / "nope.json")) is None
