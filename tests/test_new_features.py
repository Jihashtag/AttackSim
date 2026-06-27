"""Tests for the new F1-F6 feature modules.

Covers: scope guard relaxation (F4), dependency_integrity TLS-flag detection (F2),
pkg_tls_probe (F2-active), passive_discovery (F3), git_push_proof (F5),
db_cred_access (F6), datastore_access (F6), cloud_lateral (F1), attack_chain new rules.
"""
from __future__ import annotations

import os
import socket
import struct
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from sandbox import scope_guard as sg


# =====================================================================
# F4: Scope guard relaxation (proof/fuzz without allow-list)
# =====================================================================

class TestScopeRelaxation:
    def test_proof_does_not_require_scope(self):
        g = sg.ScopeGuard.from_specs([], intensity="proof")
        assert not g.requires_scope
        ok, reason = g.authorize("10.0.0.1")
        assert ok
        assert "peak tier" in reason or "opted in" in reason

    def test_fuzz_does_not_require_scope(self):
        g = sg.ScopeGuard.from_specs([], intensity="fuzz")
        assert not g.requires_scope
        ok, _ = g.authorize("anything.test")
        assert ok

    def test_intrusive_no_scope_allowed_with_confirmation(self):
        """Intrusive + empty scope is allowed (target-derived); requires confirmation."""
        g = sg.ScopeGuard.from_specs([], intensity="intrusive")
        # requires_scope is True (signals confirmation needed) but authorize still passes
        assert g.requires_scope
        assert g.requires_confirmation
        ok, reason = g.authorize("10.0.0.1")
        assert ok
        assert "target-derived" in reason.lower()

    def test_proof_with_scope_still_enforces(self):
        """If scope IS provided at proof tier, it's still enforced."""
        g = sg.ScopeGuard.from_specs(["10.0.0.0/24"], intensity="proof")
        ok, _ = g.authorize("10.0.0.5")
        assert ok
        ok2, _ = g.authorize("172.16.0.1")
        assert not ok2


# =====================================================================
# F2: Static TLS-flag detection (dependency_integrity)
# =====================================================================

class TestInsecureTLSDetection:
    def _run_on(self, filename: str, content: str):
        from exploits import dependency_integrity as di
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / filename
            p.write_text(content)
            target = SimpleNamespace(root=tmp)
            return di.run(target)

    def test_detects_pip_trusted_host(self):
        result = self._run_on("Makefile", "install:\n\tpip install --trusted-host internal.corp -r requirements.txt\n")
        assert result.exploited
        titles = [f.title for f in result.findings]
        assert any("trusted-host" in t.lower() for t in titles)

    def test_detects_node_tls_reject(self):
        result = self._run_on("Dockerfile", "ENV NODE_TLS_REJECT_UNAUTHORIZED=0\nRUN npm install\n")
        assert result.exploited
        titles = [f.title for f in result.findings]
        assert any("NODE_TLS" in t for t in titles)

    def test_detects_curl_insecure(self):
        result = self._run_on("setup.sh", "#!/bin/bash\ncurl -k https://example.com/pkg.tar.gz\n")
        assert result.exploited

    def test_detects_git_ssl_no_verify(self):
        result = self._run_on(".env", "GIT_SSL_NO_VERIFY=true\n")
        assert result.exploited

    def test_detects_verify_false(self):
        result = self._run_on("client.py", "resp = requests.get(url, verify=False)\n")
        assert result.exploited

    def test_detects_strict_ssl_false(self):
        result = self._run_on(".npmrc", "strict-ssl=false\nregistry=https://registry.npmjs.org/\n")
        assert result.exploited

    def test_clean_file_no_false_positive(self):
        result = self._run_on("config.yaml", "host: example.com\nport: 443\n")
        tls_findings = [f for f in result.findings if "tls" in (f.category or "").lower()
                        or "insecure" in f.title.lower()]
        assert not tls_findings


# =====================================================================
# F2-active: pkg_tls_probe
# =====================================================================

class TestPkgTlsProbe:
    def test_module_contract(self):
        from exploits import pkg_tls_probe
        assert pkg_tls_probe.NAME == "pkg-tls-probe"
        assert "hostport" in pkg_tls_probe.SUPPORTS
        assert "url" in pkg_tls_probe.SUPPORTS
        assert pkg_tls_probe.INTENSITY == "active"

    def test_run_no_host_returns_error(self):
        from exploits import pkg_tls_probe
        target = SimpleNamespace(host=None, url=None, scope_guard=None)
        result = pkg_tls_probe.run(target)
        assert not result.exploited
        assert result.error


# =====================================================================
# F3: Passive discovery
# =====================================================================

class TestPassiveDiscovery:
    def test_module_contract(self):
        from exploits import passive_discovery
        assert passive_discovery.NAME == "passive-discovery"
        assert "local" in passive_discovery.SUPPORTS
        assert passive_discovery.INTENSITY == "active"

    @patch("exploits.passive_discovery._read_arp_table")
    @patch("exploits.passive_discovery._listen_multicast")
    @patch("exploits.passive_discovery._send_ssdp_msearch")
    def test_arp_harvest(self, mock_ssdp, mock_listen, mock_arp):
        from exploits import passive_discovery
        mock_arp.return_value = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"},
            {"ip": "10.0.0.2", "mac": "11:22:33:44:55:66", "state": "STALE"},
        ]
        mock_listen.return_value = []
        mock_ssdp.return_value = []

        target = SimpleNamespace(kind="LOCAL", local=True, pivot_targets=[],
                                 scope_guard=None)
        result = passive_discovery.run(target)
        assert any("ARP" in f.title or "neighbor" in f.title for f in result.findings)
        assert len(target.pivot_targets) >= 2

    @patch("exploits.passive_discovery._read_arp_table")
    @patch("exploits.passive_discovery._listen_multicast")
    @patch("exploits.passive_discovery._send_ssdp_msearch")
    def test_llmnr_detection(self, mock_ssdp, mock_listen, mock_arp):
        from exploits import passive_discovery
        mock_arp.return_value = []
        # LLMNR returns packets for LLMNR multicast, empty for mDNS
        def side_effect(group, port, timeout):
            if port == 5355:  # LLMNR
                return [b"\x00\x01\x00\x00test"]
            return []
        mock_listen.side_effect = side_effect
        mock_ssdp.return_value = []

        target = SimpleNamespace(kind="local", local=True, pivot_targets=[], scope_guard=None)
        result = passive_discovery.run(target)
        assert any("LLMNR" in f.title for f in result.findings)
        assert result.exploited  # LLMNR is HIGH severity


# =====================================================================
# F5: Git push proof
# =====================================================================

class TestGitPushProof:
    def test_module_contract(self):
        from exploits import git_push_proof
        assert git_push_proof.NAME == "git-push-proof"
        assert "local" in git_push_proof.SUPPORTS
        assert git_push_proof.INTENSITY == "proof"

    def test_requires_prove_access(self):
        from exploits import git_push_proof
        target = SimpleNamespace(prove_access=False)
        result = git_push_proof.run(target)
        assert not result.exploited
        assert "opt-in" in result.error

    def test_no_repos_found(self):
        from exploits import git_push_proof
        target = SimpleNamespace(prove_access=True, root="/nonexistent_path_xyz")
        with patch.object(git_push_proof, "_find_git_repos", return_value=[]):
            result = git_push_proof.run(target)
            assert not result.exploited

    def test_has_git_credentials_env(self):
        from exploits import git_push_proof
        # Clear other credential sources that might be detected first
        clean_env = {k: v for k, v in os.environ.items()
                     if k not in ("GIT_ASKPASS", "SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN")}
        clean_env["GITHUB_TOKEN"] = "ghp_faketoken1234567890abcdefghij"
        with patch.dict(os.environ, clean_env, clear=True):
            has, source = git_push_proof._has_git_credentials("/tmp")
            assert has
            # Could be GITHUB_TOKEN or an SSH key found on disk
            assert "GITHUB_TOKEN" in source or "SSH" in source or "credential" in source.lower()

    def test_protected_branch_guard(self):
        from exploits import git_push_proof
        with pytest.raises(ValueError, match="protected branch"):
            git_push_proof._assert_not_protected_branch("main")
        with pytest.raises(ValueError, match="protected branch"):
            git_push_proof._assert_not_protected_branch("master")
        # Should not raise for our proof branch
        git_push_proof._assert_not_protected_branch("sectest-proof-access-1234567890")


# =====================================================================
# F6: DB credential access
# =====================================================================

class TestDbCredAccess:
    def test_module_contract(self):
        from exploits import db_cred_access
        assert db_cred_access.NAME == "db-cred-access"
        assert "hostport" in db_cred_access.SUPPORTS
        assert db_cred_access.INTENSITY == "proof"

    def test_requires_prove_access(self):
        from exploits import db_cred_access
        target = SimpleNamespace(prove_access=False)
        result = db_cred_access.run(target)
        assert not result.exploited
        assert "opt-in" in result.error

    def test_no_creds_found(self):
        from exploits import db_cred_access
        target = SimpleNamespace(prove_access=True, host="10.0.0.1",
                                 scope_guard=None, discovered_creds=None, budget=None)
        with patch.dict(os.environ, {}, clear=True):
            result = db_cred_access.run(target)
            assert not result.exploited
            assert any("No database credentials" in f.title for f in result.findings)

    def test_redis_ping_success(self):
        from exploits import db_cred_access
        with patch("exploits.netutil.redis_command", return_value="+PONG"):
            success, detail = db_cred_access._prove_redis("localhost", 6379, "")
            assert success
            assert "PING" in detail or "PONG" in detail or "succeeded" in detail


# =====================================================================
# F6: Datastore access
# =====================================================================

class TestDatastoreAccess:
    def test_module_contract(self):
        from exploits import datastore_access
        assert datastore_access.NAME == "datastore-access"
        assert "cloud" in datastore_access.SUPPORTS
        assert datastore_access.INTENSITY == "proof"

    def test_requires_prove_access(self):
        from exploits import datastore_access
        target = SimpleNamespace(prove_access=False)
        result = datastore_access.run(target)
        assert not result.exploited
        assert "opt-in" in result.error

    def test_no_cloud_creds(self):
        from exploits import datastore_access
        target = SimpleNamespace(prove_access=True, cloud_inventory=None)
        result = datastore_access.run(target)
        assert not result.exploited


# =====================================================================
# F1: Cloud lateral broadening
# =====================================================================

class TestCloudLateral:
    def test_module_contract(self):
        from exploits import cloud_lateral
        assert cloud_lateral.NAME == "cloud-lateral"
        assert "cloud" in cloud_lateral.SUPPORTS
        assert cloud_lateral.INTENSITY == "active"

    def test_no_creds_returns_empty(self):
        from exploits import cloud_lateral
        target = SimpleNamespace(cloud_inventory=None, pivot_targets=[])
        result = cloud_lateral.run(target)
        assert not result.exploited

    def test_read_only_guard_raises(self):
        from exploits import cloud_lateral
        with pytest.raises(ValueError, match="refuses"):
            cloud_lateral._assert_read_only("CreateRole")

    def test_read_only_guard_passes(self):
        from exploits import cloud_lateral
        # Should not raise
        cloud_lateral._assert_read_only("ListRoles")
        cloud_lateral._assert_read_only("GetCallerIdentity")
        cloud_lateral._assert_read_only("SimulatePrincipalPolicy")


# =====================================================================
# Attack chain new rules
# =====================================================================

class TestNewChainRules:
    def test_tls_chain_fires(self):
        from exploits.attack_chain import correlate, RULES
        from exploits.base import ExploitResult, Finding

        results = [
            ExploitResult(name="dependency-integrity", description="", exploited=True, findings=[
                Finding(title="Insecure TLS bypass: npm strict-ssl=false",
                        severity="HIGH", location="test", detail="",
                        category="transport-security", tags=["tls", "certificate-validation"]),
            ]),
            ExploitResult(name="pkg-tls-probe", description="", exploited=True, findings=[
                Finding(title="Missing HSTS header on https://example.com",
                        severity="MEDIUM", location="test", detail="",
                        category="transport-security", tags=["tls", "hsts"]),
            ]),
        ]
        chain_result = correlate(results)
        assert chain_result.exploited
        assert any("TLS" in f.title or "MITM" in f.title for f in chain_result.findings)

    def test_git_push_chain_fires(self):
        from exploits.attack_chain import correlate
        from exploits.base import ExploitResult, Finding

        results = [
            ExploitResult(name="git-push-proof", description="", exploited=True, findings=[
                Finding(title="Git credentials discovered: SSH_AUTH_SOCK",
                        severity="HIGH", location="test", detail="credential discovered",
                        category="credential-exposure", tags=["git", "credentials"]),
                Finding(title="CRITICAL: Git push proof SUCCEEDED — write access",
                        severity="CRITICAL", location="test",
                        detail="push succeeded", evidence="push succeeded",
                        category="proof-of-access", tags=["git", "push"]),
            ]),
        ]
        chain_result = correlate(results)
        assert chain_result.exploited
        assert any("Git" in f.title or "supply-chain" in f.title for f in chain_result.findings)

    def test_db_cred_chain_fires(self):
        from exploits.attack_chain import correlate
        from exploits.base import ExploitResult, Finding

        results = [
            ExploitResult(name="secret-harvester", description="", exploited=True, findings=[
                Finding(title="Discovered credential in config",
                        severity="HIGH", location="test",
                        detail="database_url found", tags=["credentials"]),
            ]),
            ExploitResult(name="db-cred-access", description="", exploited=True, findings=[
                Finding(title="CRITICAL: Discovered postgres credential is LIVE — authenticated access proven",
                        severity="CRITICAL", location="test",
                        detail="proven live authenticated", tags=["database", "proof-of-access"]),
            ]),
        ]
        chain_result = correlate(results)
        assert chain_result.exploited


# =====================================================================
# URL/hostport companion + email URL companion
# =====================================================================

class TestUrlCompanionAndEmailUrl:
    """URL targets get a hostport companion in the pivot queue, and email-only
    JSON entries also produce a URL companion so the web surface is covered."""

    def _make_url_target(self, url="https://example.com"):
        import targets as targetmod
        from sandbox import scope_guard as sg
        t = targetmod.Target(kind=targetmod.URL, raw=url, url=url)
        t.pivot_targets = []
        t.pivot_depth = 0
        t.scope_guard = sg.ScopeGuard.from_specs(["0.0.0.0/0"], intensity="active")
        t.intensity = "active"
        return t

    def test_url_target_pushes_hostport_companion(self):
        """_push_url_hostport_companion appends a hostport spec to pivot_targets."""
        import main as cli
        t = self._make_url_target("https://target.example.com")
        cli._push_url_hostport_companion(t)
        assert len(t.pivot_targets) == 1
        spec = t.pivot_targets[0]
        assert spec["kind"] == "hostport"
        assert spec["host"] == "target.example.com"
        assert 22 in spec["ports"]
        assert 443 in spec["ports"]

    def test_push_companion_is_idempotent(self):
        """Calling _push_url_hostport_companion twice does not add a second spec."""
        import main as cli
        t = self._make_url_target("https://target.example.com")
        cli._push_url_hostport_companion(t)
        cli._push_url_hostport_companion(t)
        assert len(t.pivot_targets) == 1

    def test_companion_skipped_when_out_of_scope(self):
        """Host out of scope is not pushed as a companion."""
        import main as cli
        import targets as targetmod
        from sandbox import scope_guard as sg
        t = targetmod.Target(kind=targetmod.URL, raw="https://evil.com", url="https://evil.com")
        t.pivot_targets = []
        t.scope_guard = sg.ScopeGuard.from_specs(["192.168.0.0/24"], intensity="intrusive")
        cli._push_url_hostport_companion(t)
        # evil.com won't resolve into 192.168.0.0/24, so no companion
        assert len(t.pivot_targets) == 0

    def test_email_only_dict_creates_url_companion(self):
        """resolve_from_dict with email but no url produces both SMTP hostport and URL targets."""
        from targets.model import resolve_from_dict, HOSTPORT, URL
        targets = resolve_from_dict({"email": "user@example.com"})
        kinds = {t.kind for t in targets}
        assert HOSTPORT in kinds, "SMTP hostport target missing"
        assert URL in kinds, "URL companion missing for email-only entry"
        url_target = next(t for t in targets if t.kind == URL)
        assert url_target.url == "https://example.com"
        assert url_target.email == "user@example.com"

    def test_email_with_explicit_url_does_not_duplicate_url(self):
        """When url is also present, no extra companion is added (url entry covers it)."""
        from targets.model import resolve_from_dict, URL
        targets = resolve_from_dict({"email": "user@foo.com", "url": "https://custom.foo.com"})
        url_targets = [t for t in targets if t.kind == URL]
        urls = {t.url for t in url_targets}
        # The explicit URL is present; the email domain must NOT produce a second URL companion.
        assert "https://custom.foo.com" in urls
        assert "https://foo.com" not in urls

    def test_resolve_from_dict_email_smtp_ports(self):
        """Email-only entry's SMTP hostport target has ports [25, 587, 465]."""
        from targets.model import resolve_from_dict, HOSTPORT
        targets = resolve_from_dict({"email": "x@mail.org"})
        smtp = next(t for t in targets if t.kind == HOSTPORT)
        assert smtp.host == "mail.org"
        assert set(smtp.ports) == {25, 587, 465}
