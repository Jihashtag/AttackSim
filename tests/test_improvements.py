"""Tests for dependency_integrity module, propagation, LLM enhancements, and SUPPORTS fixes."""
from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from exploits.base import ExploitResult, Finding


# ===========================================================================
# Tests: dependency_integrity module
# ===========================================================================

class TestDependencyIntegrity:
    """Tests for the dependency-integrity static scanner."""

    def _run_with_files(self, files: dict) -> ExploitResult:
        """Create a temp dir with the given file structure and run the module."""
        from exploits import dependency_integrity
        with tempfile.TemporaryDirectory() as td:
            for relpath, content in files.items():
                full = Path(td) / relpath
                full.parent.mkdir(parents=True, exist_ok=True)
                full.write_text(content)
            target = type("T", (), {"root": Path(td), "kind": "repo"})()
            return dependency_integrity.run(target)

    def test_missing_lock_file(self):
        """Detects package.json without a companion lock file."""
        result = self._run_with_files({"package.json": '{"name": "app"}'})
        assert any("lock file" in f.title.lower() for f in result.findings)

    def test_lock_file_missing_integrity(self):
        """Detects package-lock.json without integrity hashes."""
        result = self._run_with_files({
            "package.json": '{"name": "app"}',
            "package-lock.json": '{"name": "app", "lockfileVersion": 2, "packages": {}}',
        })
        assert any("integrity" in f.title.lower() for f in result.findings)

    def test_lock_file_with_integrity_ok(self):
        """Lock file with integrity hashes does not flag."""
        result = self._run_with_files({
            "package.json": '{"name": "app"}',
            "package-lock.json": '{"name": "app", "lockfileVersion": 2, '
                                 '"packages": {"foo": {"integrity": "sha512-abc123"}}}',
        })
        # Should not flag missing integrity (it's present)
        assert not any("lacks integrity" in f.title.lower() for f in result.findings)

    def test_http_registry_in_npmrc(self):
        """Detects HTTP registry URL in .npmrc."""
        result = self._run_with_files({
            ".npmrc": "registry=http://internal.corp/npm/\n",
        })
        assert any("http" in f.title.lower() and "registry" in f.title.lower()
                   for f in result.findings)
        assert any(f.severity == "CRITICAL" for f in result.findings)

    def test_pip_extra_index_url(self):
        """Detects dependency confusion risk from extra-index-url."""
        result = self._run_with_files({
            "pip.conf": "[global]\nextra-index-url = https://internal.corp/simple\n",
        })
        assert any("confusion" in f.title.lower() for f in result.findings)

    def test_token_in_url(self):
        """Detects credential in URL query parameters (CWE-598)."""
        result = self._run_with_files({
            "deploy.sh": "curl https://api.example.com/data?token=s3cr3t_key_123\n",
        })
        assert any("credential" in f.title.lower() or "token" in f.title.lower()
                   for f in result.findings)
        # Evidence should be redacted
        cred_finding = next(f for f in result.findings if "token" in f.title.lower())
        assert "s3cr3t" not in cred_finding.evidence

    def test_resolved_http_in_lockfile(self):
        """Detects HTTP resolved URLs in lock files."""
        result = self._run_with_files({
            "package.json": '{"name": "app"}',
            "package-lock.json": '{"name": "app", "lockfileVersion": 2, "integrity": "sha512-x",'
                                 ' "packages": {"foo": {"resolved": "http://evil.com/foo.tgz", '
                                 '"integrity": "sha512-abc"}}}',
        })
        assert any("resolved" in f.title.lower() or "http" in f.detail.lower()
                   for f in result.findings if "lock file" in f.title.lower())

    def test_clean_repo_no_findings(self):
        """A clean repo with proper lock files and HTTPS produces no high findings."""
        result = self._run_with_files({
            "package.json": '{"name": "@myorg/app"}',
            "package-lock.json": '{"name": "@myorg/app", "lockfileVersion": 3, '
                                 '"packages": {"foo": {"resolved": "https://registry.npmjs.org/foo", '
                                 '"integrity": "sha512-abc123"}}}',
            ".npmrc": "registry=https://registry.npmjs.org/\n",
        })
        assert not any(f.severity in ("CRITICAL", "HIGH") for f in result.findings)


# ===========================================================================
# Tests: k8s_service_enum and service_mesh_probe SUPPORTS fix
# ===========================================================================

class TestModuleSupports:
    """Verify SUPPORTS sets include both 'url' and 'hostport'."""

    def test_k8s_service_enum_supports_url(self):
        from exploits import k8s_service_enum
        assert "url" in k8s_service_enum.SUPPORTS
        assert "hostport" in k8s_service_enum.SUPPORTS

    def test_service_mesh_probe_supports_url(self):
        from exploits import service_mesh_probe
        assert "url" in service_mesh_probe.SUPPORTS
        assert "hostport" in service_mesh_probe.SUPPORTS

    def test_registry_dispatches_url_modules(self):
        """URL-kind target dispatch includes the k8s/mesh modules."""
        from exploits import registry
        url_modules = registry.modules_for("url")
        names = {registry.name_of(m) for m in url_modules}
        assert "k8s-service-enum" in names
        assert "service-mesh-probe" in names


# ===========================================================================
# Tests: LLM probe enhancements (tool-abuse + RAG injection)
# ===========================================================================

class TestLLMProbeEnhancements:
    """Tests for the tool-abuse and RAG injection additions to llm_probe."""

    def _fake_target(self, url="https://llm.example.com"):
        return type("T", (), {
            "url": url,
            "kind": "url",
            "scope_guard": None,
            "budget": None,
            "proxy": None,
        })()

    @patch("exploits.llm_probe._post_json")
    def test_tool_schema_disclosure(self, mock_post):
        """Detects tool/function schema disclosure."""
        from exploits import llm_probe
        # First call: injection test (LLM responds, no marker)
        # Second call: system-prompt leak (no leak signs)
        # Third call: tool leak (discloses tools)
        # Fourth call: RAG (no canary)
        responses = [
            (200, '{"choices": [{"message": {"content": "I cannot help with that."}}]}'),
            (200, '{"choices": [{"message": {"content": "I am a helpful assistant."}}]}'),
            (200, '{"choices": [{"message": {"content": "Available tools: function search_api(query: string, description: endpoint for internal API parameters: {query: string})"}}]}'),
            (200, '{"choices": [{"message": {"content": "No documents found."}}]}'),
        ]
        mock_post.side_effect = responses
        target = self._fake_target()
        result = llm_probe.run(target)
        # Should detect tool disclosure
        tool_findings = [f for f in result.findings if "tool" in f.title.lower()]
        assert len(tool_findings) >= 1
        assert tool_findings[0].severity == "MEDIUM"
        assert "excessive-agency" in tool_findings[0].tags

    @patch("exploits.llm_probe._post_json")
    def test_rag_injection(self, mock_post):
        """Detects RAG pipeline injection."""
        from exploits import llm_probe
        canary = llm_probe._RAG_CANARY
        responses = [
            (200, f'{{"choices": [{{"message": {{"content": "{canary}"}}}}]}}'),
            (200, '{"choices": [{"message": {"content": "ok"}}]}'),
            (200, '{"choices": [{"message": {"content": "ok"}}]}'),
            (200, f'{{"choices": [{{"message": {{"content": "Found: {canary}"}}}}]}}'),
        ]
        mock_post.side_effect = responses
        target = self._fake_target()
        result = llm_probe.run(target)
        rag_findings = [f for f in result.findings if "rag" in f.title.lower()]
        assert len(rag_findings) >= 1
        assert rag_findings[0].severity == "HIGH"
        assert "rag-injection" in rag_findings[0].tags


# ===========================================================================
# Tests: Attack chain rules (LLM + dependency-integrity)
# ===========================================================================

class TestNewChainRules:
    """Tests for the new attack chain rules."""

    def test_llm_tool_abuse_chain(self):
        """LLM injection + tool disclosure fires the tool-abuse chain."""
        from exploits.attack_chain import correlate
        results = [
            ExploitResult(name="llm-probe", description="", exploited=True,
                          findings=[
                              Finding(title="Prompt injection confirmed: model echoed the injected canary",
                                      severity="HIGH", location="https://llm.example.com/v1/chat/completions",
                                      detail="canary reflected",
                                      tags=["llm", "prompt-injection"]),
                              Finding(title="LLM tool/function schema disclosed",
                                      severity="MEDIUM", location="https://llm.example.com/v1/chat/completions",
                                      detail="tool schema visible",
                                      tags=["llm", "tool-abuse", "excessive-agency"]),
                          ]),
        ]
        chain_result = correlate(results)
        assert chain_result.exploited
        chain_titles = [f.title for f in chain_result.findings]
        assert any("tool schema disclosure" in t.lower() or "internal api" in t.lower()
                   for t in chain_titles)

    def test_llm_rag_poisoning_chain(self):
        """LLM injection + RAG injectable fires the RAG poisoning chain."""
        from exploits.attack_chain import correlate
        results = [
            ExploitResult(name="llm-probe", description="", exploited=True,
                          findings=[
                              Finding(title="Prompt injection confirmed: model echoed the injected canary",
                                      severity="HIGH", location="https://llm.example.com",
                                      detail="injection canary",
                                      tags=["llm", "prompt-injection"]),
                              Finding(title="RAG retrieval pipeline injectable (canary echoed)",
                                      severity="HIGH", location="https://llm.example.com",
                                      detail="rag-injection data-poisoning",
                                      tags=["llm", "rag-injection", "data-poisoning"]),
                          ]),
        ]
        chain_result = correlate(results)
        assert chain_result.exploited
        assert any("rag" in f.title.lower() for f in chain_result.findings)

    def test_dependency_confusion_chain(self):
        """Dependency confusion + missing integrity fires the supply-chain chain."""
        from exploits.attack_chain import correlate
        results = [
            ExploitResult(name="dependency-integrity", description="", exploited=True,
                          findings=[
                              Finding(title="pip extra-index-url configured (dependency confusion risk)",
                                      severity="MEDIUM", location="pip.conf",
                                      detail="dependency confusion extra-index",
                                      tags=["supply-chain", "dependency-confusion"]),
                              Finding(title="Lock file lacks integrity hashes (Pipfile.lock)",
                                      severity="HIGH", location="Pipfile.lock",
                                      detail="integrity hash missing",
                                      tags=["supply-chain", "integrity", "lock"]),
                          ]),
        ]
        chain_result = correlate(results)
        assert chain_result.exploited
        assert any("dependency confusion" in f.title.lower() or "supply-chain" in f.title.lower()
                   for f in chain_result.findings)


# ===========================================================================
# Tests: Propagation module
# ===========================================================================

class TestPropagation:
    """Tests for sandbox/propagate.py."""

    def test_pack_scanner(self):
        """pack_scanner produces a non-empty tar.gz archive."""
        from sandbox import propagate
        archive = propagate.pack_scanner()
        assert len(archive) > 1000  # should be > 1KB
        # Verify it's a valid gzip
        import tarfile, io
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            names = tar.getnames()
            assert any("main.py" in n for n in names)
            assert any("config.py" in n for n in names)

    def test_parse_propagated_results_valid(self):
        """parse_propagated_results extracts JSON from mixed output."""
        from sandbox import propagate
        import json
        data = {"results": [{"name": "test", "exploited": False, "findings": []}]}
        output = f"some log prefix\n{json.dumps(data)}"
        parsed = propagate.parse_propagated_results(output)
        assert parsed is not None
        assert parsed["results"][0]["name"] == "test"

    def test_parse_propagated_results_empty(self):
        """parse_propagated_results returns None for empty/non-JSON output."""
        from sandbox import propagate
        assert propagate.parse_propagated_results("") is None
        assert propagate.parse_propagated_results("no json here") is None

    def test_merge_propagated_findings(self):
        """merge_propagated_findings produces annotated ExploitResults."""
        from sandbox import propagate
        propagated = {
            "results": [{
                "name": "rootkit-ioc",
                "description": "Rootkit detection",
                "exploited": True,
                "findings": [{
                    "title": "LD_PRELOAD set on PID 1",
                    "severity": "CRITICAL",
                    "location": "/proc/1/environ",
                    "detail": "rootkit indicator",
                }],
            }],
        }
        merged = propagate.merge_propagated_findings([], propagated, reached_from="10.0.0.5:2375")
        assert len(merged) == 1
        assert "propagated from 10.0.0.5:2375" in merged[0].findings[0].title
        assert "propagated" in merged[0].findings[0].tags

    def test_deploy_script_format(self):
        """_deploy_script generates a valid shell script."""
        from sandbox import propagate
        script = propagate._deploy_script("AAAA==", "/tmp/.test", "--local")
        assert "#!/bin/sh" in script
        assert "AAAA==" in script
        assert "rm -rf" in script
        assert "--local" in script


# ===========================================================================
# Tests: --propagate-script confirmation
# ===========================================================================

class TestPropagateConfirmation:
    """Tests for _confirm_propagate in main.py."""

    def test_confirm_propagate_with_yes(self):
        """--yes bypasses the propagation confirmation."""
        from main import _confirm_propagate
        args = type("A", (), {"assume_yes": True})()
        out = io.StringIO()
        assert _confirm_propagate(args, isatty=True, out=out) is True

    def test_confirm_propagate_non_interactive_refuses(self):
        """Non-interactive without --yes refuses propagation."""
        from main import _confirm_propagate
        args = type("A", (), {"assume_yes": False})()
        out = io.StringIO()
        assert _confirm_propagate(args, isatty=False, out=out) is False
        assert "REFUSING" in out.getvalue()

    def test_confirm_propagate_interactive_accept(self):
        """Interactive user answering 'y' permits propagation."""
        from main import _confirm_propagate
        args = type("A", (), {"assume_yes": False})()
        out = io.StringIO()
        assert _confirm_propagate(args, isatty=True, input_fn=lambda _: "y", out=out) is True

    def test_confirm_propagate_interactive_decline(self):
        """Interactive user answering 'n' declines propagation."""
        from main import _confirm_propagate
        args = type("A", (), {"assume_yes": False})()
        out = io.StringIO()
        assert _confirm_propagate(args, isatty=True, input_fn=lambda _: "n", out=out) is False

    def test_confirm_propagate_eof(self):
        """EOF/KeyboardInterrupt during prompt declines propagation."""
        from main import _confirm_propagate
        args = type("A", (), {"assume_yes": False})()
        out = io.StringIO()
        def raise_eof(_):
            raise EOFError()
        assert _confirm_propagate(args, isatty=True, input_fn=raise_eof, out=out) is False
