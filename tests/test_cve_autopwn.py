"""Tests for the CVE autopwn pipeline (resolver, planner, generator)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exploits.cve_resolver import (
    CVERecord, _cache_get, _cache_key, _cache_put, _parse_ver,
    load_cpe_aliases, resolve_cpe, resolve_for_service,
)
from exploits.exploit_planner import (
    CveTestPlan, _assign_strategy, _infer_protocol, _should_skip, prioritize, summarize_plans,
)
from exploits.exploit_generator import (
    CveVerifyResult, _generate_nuclei_template, _select_builtin_template,
    _validate_script, execute_plans,
)


# ---------------------------------------------------------------------------
# cve_resolver tests
# ---------------------------------------------------------------------------

class TestCVEResolver:
    def test_parse_ver_simple(self):
        assert _parse_ver("1.2.3") == (1, 2, 3)

    def test_parse_ver_four(self):
        assert _parse_ver("9.3.0.2") == (9, 3, 0, 2)

    def test_parse_ver_none(self):
        assert _parse_ver("") is None
        assert _parse_ver(None) is None

    def test_load_cpe_aliases(self):
        aliases = load_cpe_aliases()
        assert isinstance(aliases, dict)
        # Should have at least the common products
        assert "openssh" in aliases or "nginx" in aliases

    def test_resolve_cpe_known(self):
        vendor, product, version = resolve_cpe("openssh", "8.9")
        assert vendor == "openbsd"
        assert product == "openssh"
        assert version == "8.9"

    def test_resolve_cpe_unknown(self):
        vendor, product, version = resolve_cpe("unknownthing", "1.0")
        assert product == "unknownthing"
        assert version == "1.0"

    def test_cache_roundtrip(self):
        """Verify cache write + read returns data."""
        with tempfile.TemporaryDirectory() as td:
            import exploits.cve_resolver as mod
            orig_dir = mod._CACHE_DIR
            mod._CACHE_DIR = td
            try:
                _cache_put("test_query", {"records": [{"cve_id": "CVE-2024-1234"}]})
                result = _cache_get("test_query")
                assert result is not None
                assert result["records"][0]["cve_id"] == "CVE-2024-1234"
            finally:
                mod._CACHE_DIR = orig_dir

    def test_cve_record_to_dict(self):
        rec = CVERecord(cve_id="CVE-2024-6387", product="openssh", severity="HIGH",
                        cvss=8.1, epss=0.72, summary="regreSSHion")
        d = rec.to_dict()
        assert d["cve_id"] == "CVE-2024-6387"
        assert d["epss"] == 0.72


# ---------------------------------------------------------------------------
# exploit_planner tests
# ---------------------------------------------------------------------------

class TestExploitPlanner:
    def _make_cve(self, **kwargs) -> CVERecord:
        defaults = {
            "cve_id": "CVE-2024-0001", "product": "nginx", "severity": "HIGH",
            "cvss": 7.5, "epss": 0.4, "summary": "Test vuln",
            "attack_vector": "NETWORK", "attack_complexity": "LOW", "cwe": "CWE-22",
        }
        defaults.update(kwargs)
        return CVERecord(**defaults)

    def test_infer_protocol(self):
        assert _infer_protocol(22) == "ssh"
        assert _infer_protocol(80) == "http"
        assert _infer_protocol(443) == "https"
        assert _infer_protocol(6379) == "redis"
        assert _infer_protocol(9999) == "tcp"

    def test_should_skip_local_vector(self):
        cve = self._make_cve(attack_vector="LOCAL")
        assert _should_skip(cve, have_local_access=False) is True
        assert _should_skip(cve, have_local_access=True) is False

    def test_should_skip_low_epss(self):
        cve = self._make_cve(epss=0.01, cvss=5.0, poc_urls=[])
        assert _should_skip(cve, have_local_access=False) is True

    def test_should_not_skip_high_epss(self):
        cve = self._make_cve(epss=0.8)
        assert _should_skip(cve, have_local_access=False) is False

    def test_assign_strategy_nuclei_for_web(self):
        cve = self._make_cve(cwe="CWE-22")
        assert _assign_strategy(cve, "http", has_llm=False) == "nuclei_template"

    def test_assign_strategy_banner_for_high_complexity(self):
        cve = self._make_cve(attack_complexity="HIGH", poc_urls=[])
        assert _assign_strategy(cve, "ssh", has_llm=False) == "banner_match"

    def test_assign_strategy_script_poc_with_known_poc(self):
        cve = self._make_cve(cwe="CWE-787", poc_urls=["https://github.com/x/poc"])
        assert _assign_strategy(cve, "ssh", has_llm=False) == "script_poc"

    def test_assign_strategy_llm_when_available(self):
        cve = self._make_cve(cwe="CWE-787", poc_urls=[])
        assert _assign_strategy(cve, "ssh", has_llm=True) == "llm_generated"

    def test_prioritize_respects_max(self):
        cves = [self._make_cve(cve_id=f"CVE-2024-{i:04d}", epss=0.5 - i * 0.01)
                for i in range(20)]
        plans = prioritize(cves, "10.0.0.1", 80, max_plans=5)
        assert len(plans) <= 5

    def test_prioritize_order(self):
        cve_high = self._make_cve(cve_id="CVE-HIGH", epss=0.9, cvss=9.0)
        cve_low = self._make_cve(cve_id="CVE-LOW", epss=0.1, cvss=5.0)
        plans = prioritize([cve_low, cve_high], "10.0.0.1", 80)
        assert plans[0].cve.cve_id == "CVE-HIGH"

    def test_nuclei_plan_no_confirmation(self):
        cve = self._make_cve(cwe="CWE-22")
        plans = prioritize([cve], "10.0.0.1", 80)
        assert plans[0].requires_confirmation is False

    def test_script_poc_requires_confirmation(self):
        cve = self._make_cve(cwe="CWE-787", poc_urls=["https://poc.example.com"])
        plans = prioritize([cve], "10.0.0.1", 22)
        assert plans[0].requires_confirmation is True

    def test_summarize_plans(self):
        cve = self._make_cve()
        plans = prioritize([cve], "10.0.0.1", 80)
        summary = summarize_plans(plans)
        assert "CVE-2024-0001" in summary
        assert "Test Plan" in summary


# ---------------------------------------------------------------------------
# exploit_generator tests
# ---------------------------------------------------------------------------

class TestExploitGenerator:
    def _make_plan(self, **kwargs) -> CveTestPlan:
        cve = CVERecord(
            cve_id="CVE-2021-42013", product="apache httpd", severity="CRITICAL",
            cvss=9.8, epss=0.95, summary="Path traversal and RCE",
            cwe="CWE-22", attack_vector="NETWORK", attack_complexity="LOW",
            affected_range={"version_detected": "2.4.49"},
        )
        defaults = {
            "cve": cve, "target_host": "10.0.0.1", "target_port": 80,
            "protocol": "http", "test_strategy": "nuclei_template",
            "requires_confirmation": False,
        }
        defaults.update(kwargs)
        return CveTestPlan(**defaults)

    def test_generate_nuclei_template_path_traversal(self):
        plan = self._make_plan()
        template = _generate_nuclei_template(plan)
        assert "CVE-2021-42013" in template.lower().replace("-", "_") or "cve_2021_42013" in template.lower()
        assert "path" in template.lower()
        assert "matchers" in template

    def test_select_builtin_template(self):
        plan = self._make_plan(test_strategy="script_poc")
        script = _select_builtin_template(plan)
        assert script is not None
        assert "def check" in script
        assert "RESULT:" in script

    def test_validate_script_safe(self):
        script = """
import socket
def check(host, port):
    return True, "ok"
vulnerable, evidence = check("10.0.0.1", 80)
print(f"RESULT:{vulnerable}:{evidence}")
"""
        safe, reason = _validate_script(script)
        assert safe is True

    def test_validate_script_rejects_os_system(self):
        script = """
import os
os.system("rm -rf /")
"""
        safe, reason = _validate_script(script)
        assert safe is False
        assert "os.system" in reason

    def test_validate_script_rejects_subprocess(self):
        script = """
import subprocess
subprocess.run(["ls"])
"""
        safe, reason = _validate_script(script)
        assert safe is False
        assert "subprocess" in reason

    def test_validate_script_rejects_eval(self):
        script = 'x = eval("1+1")'
        safe, reason = _validate_script(script)
        assert safe is False

    def test_execute_plans_banner_match(self):
        plan = self._make_plan(test_strategy="banner_match")
        result = execute_plans([plan], auto_confirm=True)
        assert result.exploited is True
        assert any("version confirmed" in f.title for f in result.findings)

    def test_execute_plans_skips_unconfirmed(self):
        plan = self._make_plan(test_strategy="script_poc", requires_confirmation=True)
        result = execute_plans([plan], auto_confirm=False, interactive=False)
        assert result.exploited is False
        assert any("skipped" in f.title for f in result.findings)

    def test_execute_plans_auto_confirm(self):
        """With auto_confirm, script_poc plans execute."""
        plan = self._make_plan(test_strategy="script_poc", requires_confirmation=True)
        # The builtin template will try to connect to 10.0.0.1:80 and fail gracefully
        result = execute_plans([plan], auto_confirm=True, interactive=False)
        # Should have run (not skipped) — either confirmed or not-confirmed
        assert not any("skipped" in f.title for f in result.findings)


# ---------------------------------------------------------------------------
# propagate.py LLM bundling test
# ---------------------------------------------------------------------------

class TestPropagateLLMBundle:
    def test_pack_includes_llm_dir(self):
        from sandbox.propagate import pack_scanner
        import tarfile
        import io
        archive = pack_scanner(exclude_tests=True, bundle_llm=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            names = tar.getnames()
        llm_files = [n for n in names if "/llm/" in n]
        assert len(llm_files) > 0, "LLM directory should be bundled"

    def test_pack_excludes_llm_when_opted_out(self):
        from sandbox.propagate import pack_scanner
        import tarfile
        import io
        archive = pack_scanner(exclude_tests=True, bundle_llm=False)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            names = tar.getnames()
        llm_files = [n for n in names if "/llm/" in n]
        assert len(llm_files) == 0, "LLM directory should NOT be bundled"

    def test_deploy_script_detects_ollama(self):
        from sandbox.propagate import _deploy_script, _args_list_to_json
        import json
        args = ["--yes", "--scope", "test.local", "--cve-lookup", "--cve-test"]
        args_json = _args_list_to_json(args)
        script = _deploy_script("BASE64DATA", "/tmp/.test", args_json)
        assert "ollama" in script
        assert "--llm" in script
        # CVE flags are now passed via JSON sidecar, not hardcoded in LLM_FLAG
        assert "cve-lookup" in args_json
        assert "cve-test" in args_json
        # Verify JSON sidecar is embedded in the script
        assert "_propagate_args.json" in script
