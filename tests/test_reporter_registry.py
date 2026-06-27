"""Tests for the reporter exit-code gate and the module registry."""
from exploits import registry
from exploits.base import ExploitResult, Finding
from report import reporter


def _result(name, exploited, severity=None):
    findings = []
    if severity:
        findings.append(Finding(title="x", severity=severity, location="l", detail="d"))
    return ExploitResult(name=name, description="", exploited=exploited, findings=findings)


def test_gate_any_exploited_fails_by_default():
    results = [_result("a", True, "LOW")]
    assert reporter.gate(results, None) is True


def test_gate_none_exploited_passes():
    results = [_result("a", False)]
    assert reporter.gate(results, None) is False


def test_gate_fail_on_high_ignores_low_win():
    results = [_result("a", True, "LOW")]
    assert reporter.gate(results, "HIGH") is False


def test_gate_fail_on_high_trips_on_high_win():
    results = [_result("a", True, "HIGH")]
    assert reporter.gate(results, "HIGH") is True


def test_gate_fail_on_high_trips_on_critical_win():
    results = [_result("a", True, "CRITICAL")]
    assert reporter.gate(results, "HIGH") is True


def test_registry_modules_for_kinds():
    repo_mods = {registry.name_of(m) for m in registry.modules_for("repo")}
    assert "secret-harvester" in repo_mods
    url_mods = {registry.name_of(m) for m in registry.modules_for("url")}
    assert "http-probe" in url_mods
    assert "tls-grader" in url_mods


def test_registry_catalogue_complete():
    cat = registry.catalogue()
    names = {row["name"] for row in cat}
    assert {"http-probe", "port-probe", "cred-tester", "tls-grader"} <= names
    for row in cat:
        assert row["supports"]
        assert row["description"]


def test_every_module_has_contract():
    for m in registry.ALL_MODULES:
        assert isinstance(registry.name_of(m), str)
        assert callable(m.run)
        assert registry.supports(m)
