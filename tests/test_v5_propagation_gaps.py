"""Tests for v5 propagation gaps — SSH auth, Shellshock, PHP-CGI, cmd-inject, LLM enum."""
from __future__ import annotations

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# SSH Auth Module Tests
# ===========================================================================

class TestSSHAuth:
    def test_module_contract(self):
        from exploits import ssh_auth
        assert ssh_auth.NAME == "ssh-auth"
        assert ssh_auth.SUPPORTS == {"hostport"}
        assert ssh_auth.INTENSITY == "intrusive"

    def test_skips_non_ssh_port(self):
        from exploits import ssh_auth
        target = MagicMock()
        target.host = "10.0.0.1"
        target.port = 80
        target.spray = True
        result = ssh_auth.run(target)
        assert not result.exploited

    def test_skips_without_spray(self):
        from exploits import ssh_auth
        target = MagicMock()
        target.host = "10.0.0.1"
        target.port = 22
        target.spray = False
        result = ssh_auth.run(target)
        assert not result.exploited

    def test_skips_no_banner(self):
        from exploits import ssh_auth
        target = MagicMock()
        target.host = "10.0.0.1"
        target.port = 22
        target.spray = True
        target.scope_guard = None
        with patch.object(ssh_auth, "_banner_check", return_value=None):
            result = ssh_auth.run(target)
        assert not result.exploited

    def test_password_spray_failure(self):
        from exploits import ssh_auth
        target = MagicMock()
        target.host = "10.0.0.1"
        target.port = 22
        target.spray = True
        target.scope_guard = None
        target.proof_ledger = None
        with patch.object(ssh_auth, "_banner_check", return_value="SSH-2.0-OpenSSH_8.9"):
            with patch.object(ssh_auth, "_try_password_auth", return_value=(False, "")):
                with patch.object(ssh_auth, "_try_key_auth", return_value=(False, "")):
                    with patch.object(ssh_auth, "_discover_keys", return_value=[]):
                        result = ssh_auth.run(target)
        assert not result.exploited
        assert any("no default credentials" in f.title.lower() for f in result.findings)

    def test_password_spray_success(self):
        from exploits import ssh_auth
        target = MagicMock()
        target.host = "10.0.0.1"
        target.port = 22
        target.spray = True
        target.scope_guard = None
        target.proof_ledger = None
        with patch.object(ssh_auth, "_banner_check", return_value="SSH-2.0-OpenSSH_8.9"):
            with patch.object(ssh_auth, "_try_password_auth", return_value=(True, "SECTEST_AUTH_OK\nuid=0(root)")):
                with patch.object(ssh_auth, "_discover_keys", return_value=[]):
                    result = ssh_auth.run(target)
        assert result.exploited
        assert result.findings[0].severity == "CRITICAL"


# ===========================================================================
# Shellshock Module Tests
# ===========================================================================

class TestShellshockProbe:
    def test_module_contract(self):
        from exploits import shellshock_probe
        assert shellshock_probe.NAME == "shellshock-probe"
        assert shellshock_probe.SUPPORTS == {"url"}
        assert shellshock_probe.INTENSITY == "active"

    def test_no_url(self):
        from exploits import shellshock_probe
        target = MagicMock()
        target.url = ""
        result = shellshock_probe.run(target)
        assert not result.exploited

    def test_not_vulnerable(self):
        from exploits import shellshock_probe
        target = MagicMock()
        target.url = "http://example.com/cgi-bin/test.cgi"
        target.scope_guard = None
        with patch("exploits.netutil.http_get", return_value=(200, "Normal response", {})):
            result = shellshock_probe.run(target)
        assert not result.exploited

    def test_vulnerable_detected(self):
        from exploits import shellshock_probe
        target = MagicMock()
        target.url = "http://example.com/cgi-bin/test.cgi"
        target.scope_guard = None
        target.proof_ledger = None
        canary = shellshock_probe._CANARY

        def mock_get(url, timeout=None, extra_headers=None, **kw):
            if extra_headers and any("() {" in str(v) for v in extra_headers.values()):
                return (200, f"SECTEST-SHELLSHOCK-{canary}", {})
            return (200, "Normal response", {})

        with patch("exploits.netutil.http_get", side_effect=mock_get):
            result = shellshock_probe.run(target)
        assert result.exploited
        assert result.findings[0].severity == "CRITICAL"
        assert "CVE-2014-6271" in result.findings[0].references


# ===========================================================================
# PHP-CGI Module Tests
# ===========================================================================

class TestPhpCgiProbe:
    def test_module_contract(self):
        from exploits import php_cgi_probe
        assert php_cgi_probe.NAME == "php-cgi-probe"
        assert php_cgi_probe.SUPPORTS == {"url"}
        assert php_cgi_probe.INTENSITY == "active"

    def test_no_url(self):
        from exploits import php_cgi_probe
        target = MagicMock()
        target.url = ""
        result = php_cgi_probe.run(target)
        assert not result.exploited

    def test_not_vulnerable(self):
        from exploits import php_cgi_probe
        target = MagicMock()
        target.url = "http://example.com/index.php"
        target.scope_guard = None
        with patch("exploits.netutil.http_get", return_value=(200, "<html>Normal</html>", {})):
            result = php_cgi_probe.run(target)
        assert not result.exploited

    def test_source_disclosure_detected(self):
        from exploits import php_cgi_probe
        target = MagicMock()
        target.url = "http://example.com/index.php"
        target.scope_guard = None
        php_source = "<?php\nfunction login($user) {\n  $password = $_POST['pass'];\n}\n?>"

        def mock_get(url, timeout=None, **kw):
            if "?-s" in url:
                return (200, php_source, {})
            return (200, "<html>Normal</html>", {})

        with patch("exploits.netutil.http_get", side_effect=mock_get):
            result = php_cgi_probe.run(target)
        assert result.exploited
        assert "CVE-2012-1823" in result.findings[0].references


# ===========================================================================
# Command Injection Module Tests
# ===========================================================================

class TestCmdInjectConfirm:
    def test_module_contract(self):
        from exploits import cmd_inject_confirm
        assert cmd_inject_confirm.NAME == "cmd-inject-confirm"
        assert cmd_inject_confirm.SUPPORTS == {"url"}
        assert cmd_inject_confirm.INTENSITY == "intrusive"

    def test_no_url(self):
        from exploits import cmd_inject_confirm
        target = MagicMock()
        target.url = ""
        result = cmd_inject_confirm.run(target)
        assert not result.exploited

    def test_not_vulnerable(self):
        from exploits import cmd_inject_confirm
        target = MagicMock()
        target.url = "http://example.com/search?q=hello"
        target.scope_guard = None
        with patch("exploits.netutil.http_get", return_value=(200, "Results for hello", {})):
            result = cmd_inject_confirm.run(target)
        assert not result.exploited

    def test_injection_detected(self):
        from exploits import cmd_inject_confirm
        target = MagicMock()
        target.url = "http://example.com/search?q=hello"
        target.scope_guard = None
        target.proof_ledger = None
        canary = cmd_inject_confirm._CANARY

        def mock_get(url, timeout=None, extra_headers=None, **kw):
            # Simulate command execution: return the canary (computed result)
            # but NOT the raw payload string (which would indicate reflection)
            if "expr" in url or (extra_headers and any("expr" in str(v) for v in extra_headers.values())):
                return (200, f"Results: {canary} found", {})
            return (200, "Results for hello", {})

        with patch("exploits.netutil.http_get", side_effect=mock_get):
            result = cmd_inject_confirm.run(target)
        assert result.exploited
        assert result.findings[0].severity == "CRITICAL"


# ===========================================================================
# LLM Endpoint Enum Tests
# ===========================================================================

class TestLlmEndpointEnum:
    def test_module_contract(self):
        from exploits import llm_endpoint_enum
        assert llm_endpoint_enum.NAME == "llm-endpoint-enum"
        assert "hostport" in llm_endpoint_enum.SUPPORTS
        assert llm_endpoint_enum.INTENSITY == "active"

    def test_no_target(self):
        from exploits import llm_endpoint_enum
        target = MagicMock()
        target.host = ""
        target.port = None
        target.url = ""
        result = llm_endpoint_enum.run(target)
        assert not result.exploited

    def test_ollama_detected(self):
        from exploits import llm_endpoint_enum
        target = MagicMock()
        target.host = "10.0.0.5"
        target.port = 11434
        target.url = ""
        target.scope_guard = None

        def mock_get(url, timeout=None, **kw):
            if "/api/tags" in url:
                return (200, '{"models": [{"name": "llama3"}]}', {})
            return (404, "", {})

        with patch("exploits.netutil.http_get", side_effect=mock_get):
            result = llm_endpoint_enum.run(target)
        assert result.exploited
        assert any("Ollama" in f.title for f in result.findings)


# ===========================================================================
# Transport Registry Tests
# ===========================================================================

class TestTransportRegistry:
    def test_all_transports_count(self):
        from sandbox.propagate_transport import ALL_TRANSPORTS
        assert len(ALL_TRANSPORTS) == 8  # +1 for AdbTransport (v8 Android propagation)

    def test_transport_names(self):
        from sandbox.propagate_transport import ALL_TRANSPORTS
        names = [t.name for t in ALL_TRANSPORTS]
        assert "ssh" in names
        assert "docker-volume" in names
        assert "shell-exec" in names
        assert "http-upload" in names

    def test_select_shell_exec(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "shell-exec", "url": "http://example.com/cgi-bin/test.cgi"}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "shell-exec"

    def test_select_http_upload(self):
        from sandbox.propagate_transport import select_transport
        foothold = {"type": "http-upload", "upload_url": "http://example.com/upload"}
        t = select_transport(foothold)
        assert t is not None
        assert t.name == "http-upload"


# ===========================================================================
# SSH Relay Tests
# ===========================================================================

class TestSSHRelay:
    def test_relay_type(self):
        from sandbox.relay import SSHRelay
        relay = SSHRelay("10.0.0.1", 22, "root", key_path="/tmp/id_rsa")
        assert relay.type == "ssh"
        assert relay.describe() == "ssh-relay via root@10.0.0.1:22"

    def test_build_relay_ssh(self):
        from sandbox.relay import build_relay, SSHRelay
        spec = {"type": "ssh", "host": "10.0.0.1", "port": 22,
                "user": "admin", "key_path": "/tmp/key"}
        relay = build_relay(spec)
        assert isinstance(relay, SSHRelay)
        assert relay.host == "10.0.0.1"
        assert relay.user == "admin"


# ===========================================================================
# Platform Detection Tests
# ===========================================================================

class TestPlatformDetection:
    def test_musl_detection_map(self):
        from sandbox.propagate_pack import _MUSL_PLATFORM_MAP
        assert ("Linux", "x86_64") in _MUSL_PLATFORM_MAP
        assert _MUSL_PLATFORM_MAP[("Linux", "x86_64")] == "linux-musl-amd64"

    def test_darwin_in_platform_map(self):
        from sandbox.propagate_pack import _PLATFORM_MAP
        assert ("Darwin", "x86_64") in _PLATFORM_MAP
        assert ("Darwin", "arm64") in _PLATFORM_MAP
        assert _PLATFORM_MAP[("Darwin", "x86_64")] == "darwin-amd64"
        assert _PLATFORM_MAP[("Darwin", "arm64")] == "darwin-arm64"

    def test_detect_musl_via_relay(self):
        from sandbox.propagate_pack import _detect_musl_via_relay
        relay = MagicMock()
        relay._exec_cmd.return_value = "MUSL"
        assert _detect_musl_via_relay(relay) is True

    def test_detect_glibc_via_relay(self):
        from sandbox.propagate_pack import _detect_musl_via_relay
        relay = MagicMock()
        relay._exec_cmd.return_value = "GLIBC"
        assert _detect_musl_via_relay(relay) is False
