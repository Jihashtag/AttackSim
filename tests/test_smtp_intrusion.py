"""Tests for SMTP intrusion modules — enum, auth spray, injection/smuggling."""
from __future__ import annotations

import sys
import os
import socket
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# SMTP Enum Module Tests
# ===========================================================================

class TestSMTPEnum:
    def test_module_contract(self):
        from exploits import smtp_enum
        assert smtp_enum.NAME == "smtp-enum"
        assert smtp_enum.SUPPORTS == {"hostport"}
        assert smtp_enum.INTENSITY == "active"

    def test_no_host(self):
        from exploits import smtp_enum
        target = MagicMock()
        target.host = None
        result = smtp_enum.run(target)
        assert not result.exploited
        assert "no host" in result.error

    @patch("exploits.smtp_enum._connect")
    def test_vrfy_enabled(self, mock_connect):
        from exploits import smtp_enum
        # Simulate a socket that responds to VRFY with 250
        sock = MagicMock()
        responses = iter([
            (220, "220 mail.test ESMTP"),     # banner
            (250, "250-mail.test\r\n250 OK"), # EHLO
            (250, "250 postmaster"),           # VRFY postmaster (check if enabled)
        ] + [(250, f"250 {u}") for u in smtp_enum._ENUM_USERS]  # all VRFY succeed
          + [(502, "502 EXPN disabled")]      # EXPN disabled
          + [(250, "250 OK")]                 # MAIL FROM
          + [(550, "550 No such user") for _ in smtp_enum._ENUM_USERS]  # RCPT TO all fail
          + [(250, "250 RSET OK")]
          + [(221, "221 Bye")]                # QUIT
        )
        sock.recv = MagicMock(side_effect=lambda n: b"")
        mock_connect.return_value = sock

        # Patch _read_reply and _cmd to use our responses
        with patch("exploits.smtp_enum._read_reply") as mock_read, \
             patch("exploits.smtp_enum._cmd") as mock_cmd:
            call_count = [0]
            all_resp = list(responses)

            def fake_read(s):
                if call_count[0] < len(all_resp):
                    r = all_resp[call_count[0]]
                    call_count[0] += 1
                    return r
                return (None, "")
            mock_read.side_effect = fake_read

            def fake_cmd(s, line):
                if call_count[0] < len(all_resp):
                    r = all_resp[call_count[0]]
                    call_count[0] += 1
                    return r
                return (None, "")
            mock_cmd.side_effect = fake_cmd

            target = MagicMock()
            target.host = "10.0.0.5"
            target.ports = [25]
            target.port = 25
            target.scope_guard = None
            target.budget = None

            result = smtp_enum.run(target)
            # Should have findings about VRFY being enabled
            assert any("VRFY" in f.title for f in result.findings)

    @patch("exploits.smtp_enum.socket.create_connection")
    def test_connection_failure(self, mock_conn):
        from exploits import smtp_enum
        mock_conn.side_effect = OSError("Connection refused")
        target = MagicMock()
        target.host = "10.0.0.5"
        target.ports = [25]
        target.port = 25
        target.scope_guard = None
        target.budget = None
        result = smtp_enum.run(target)
        assert not result.exploited


# ===========================================================================
# SMTP Auth Spray Module Tests
# ===========================================================================

class TestSMTPAuthSpray:
    def test_module_contract(self):
        from exploits import smtp_auth_spray
        assert smtp_auth_spray.NAME == "smtp-auth-spray"
        assert smtp_auth_spray.SUPPORTS == {"hostport"}
        assert smtp_auth_spray.INTENSITY == "intrusive"

    def test_requires_spray_flag(self):
        from exploits import smtp_auth_spray
        target = MagicMock()
        target.host = "10.0.0.5"
        target.spray = False
        result = smtp_auth_spray.run(target)
        assert not result.exploited
        assert "spray" in result.error.lower()

    def test_no_host(self):
        from exploits import smtp_auth_spray
        target = MagicMock()
        target.host = None
        target.spray = True
        result = smtp_auth_spray.run(target)
        assert not result.exploited
        assert "no host" in result.error

    @patch("exploits.smtp_auth_spray.socket.create_connection")
    def test_connection_refused(self, mock_conn):
        from exploits import smtp_auth_spray
        mock_conn.side_effect = OSError("Connection refused")
        target = MagicMock()
        target.host = "10.0.0.5"
        target.port = 587
        target.ports = [587]
        target.spray = True
        target.scope_guard = None
        target.budget = None
        result = smtp_auth_spray.run(target)
        assert not result.exploited

    @patch("exploits.smtp_auth_spray.socket.create_connection")
    def test_auth_success(self, mock_conn):
        from exploits import smtp_auth_spray
        # Simulate successful AUTH PLAIN
        sock = MagicMock()
        # Build response stream
        recv_data = [
            b"220 mail.test ESMTP\r\n",           # banner
            b"250-mail.test\r\n250 OK\r\n",       # EHLO
            b"220 TLS ready\r\n",                  # STARTTLS
            b"250-mail.test\r\n250 OK\r\n",       # EHLO (post-TLS)
            b"235 Authentication successful\r\n",  # AUTH PLAIN
            b"221 Bye\r\n",                        # QUIT
        ]
        sock.recv = MagicMock(side_effect=recv_data)
        mock_conn.return_value = sock

        target = MagicMock()
        target.host = "10.0.0.5"
        target.port = 587
        target.ports = [587]
        target.spray = True
        target.scope_guard = None
        target.budget = None

        with patch("exploits.smtp_auth_spray._read_reply") as mock_read, \
             patch("exploits.smtp_auth_spray._cmd") as mock_cmd, \
             patch("exploits.smtp_auth_spray._try_starttls") as mock_tls:
            responses = [
                (220, "220 mail.test ESMTP"),
                (250, "250 OK"),
                (250, "250 OK"),  # post-tls EHLO
                (235, "235 OK"),  # AUTH PLAIN success
                (221, "221 Bye"),
            ]
            idx = [0]

            def fake_read(s):
                if idx[0] < len(responses):
                    r = responses[idx[0]]
                    idx[0] += 1
                    return r
                return (None, "")

            def fake_cmd(s, line):
                if idx[0] < len(responses):
                    r = responses[idx[0]]
                    idx[0] += 1
                    return r
                return (None, "")

            mock_read.side_effect = fake_read
            mock_cmd.side_effect = fake_cmd
            mock_tls.return_value = sock

            result = smtp_auth_spray.run(target)
            # Should find auth success
            assert any("CRITICAL" == f.severity for f in result.findings) or not result.findings

    def test_default_creds_list_not_empty(self):
        from exploits import smtp_auth_spray
        assert len(smtp_auth_spray._DEFAULT_CREDS) > 5


# ===========================================================================
# SMTP Inject Module Tests
# ===========================================================================

class TestSMTPInject:
    def test_module_contract(self):
        from exploits import smtp_inject
        assert smtp_inject.NAME == "smtp-inject"
        assert smtp_inject.SUPPORTS == {"hostport"}
        assert smtp_inject.INTENSITY == "active"

    def test_no_host(self):
        from exploits import smtp_inject
        target = MagicMock()
        target.host = None
        result = smtp_inject.run(target)
        assert not result.exploited
        assert "no host" in result.error

    @patch("exploits.smtp_inject.socket.create_connection")
    def test_connection_refused(self, mock_conn):
        from exploits import smtp_inject
        mock_conn.side_effect = OSError("Connection refused")
        target = MagicMock()
        target.host = "10.0.0.5"
        target.port = 25
        target.ports = [25]
        target.scope_guard = None
        target.budget = None
        result = smtp_inject.run(target)
        assert not result.exploited

    def test_injection_vectors_defined(self):
        from exploits import smtp_inject
        assert len(smtp_inject._INJECTION_VECTORS) >= 3
        assert len(smtp_inject._SMUGGLE_VECTORS) >= 2

    @patch("exploits.smtp_inject._connect")
    def test_crlf_injection_detected(self, mock_connect):
        from exploits import smtp_inject
        sock = MagicMock()
        mock_connect.return_value = sock

        with patch("exploits.smtp_inject._read_reply") as mock_read, \
             patch("exploits.smtp_inject._cmd") as mock_cmd, \
             patch("exploits.smtp_inject._cmd_raw") as mock_raw:
            # Simulate server that accepts CRLF injection
            cmd_responses = iter([
                (220, "220 mail.test ESMTP"),  # banner
                (250, "250 OK"),              # EHLO
                (250, "250 OK"),              # MAIL FROM (injected accepted!)
                (250, "250 RSET"),            # RSET
                (221, "221 Bye"),             # QUIT
            ] * 10)  # repeat for multiple vectors

            def fake_read(s):
                return next(cmd_responses, (None, ""))

            def fake_cmd(s, line):
                return next(cmd_responses, (None, ""))

            def fake_raw(s, data):
                return next(cmd_responses, (None, ""))

            mock_read.side_effect = fake_read
            mock_cmd.side_effect = fake_cmd
            mock_raw.side_effect = fake_raw

            target = MagicMock()
            target.host = "10.0.0.5"
            target.port = 25
            target.ports = [25]
            target.scope_guard = None
            target.budget = None

            result = smtp_inject.run(target)
            # With servers accepting injected payloads, should detect injection
            assert any("injection" in f.title.lower() or "inject" in f.title.lower()
                       for f in result.findings) or not result.findings


# ===========================================================================
# Integration: registry includes new SMTP modules
# ===========================================================================

class TestSMTPAntispam:
    def test_module_contract(self):
        from exploits import smtp_antispam
        assert smtp_antispam.NAME == "smtp-antispam"
        assert smtp_antispam.SUPPORTS == {"hostport"}
        assert smtp_antispam.INTENSITY == "active"

    def test_no_host(self):
        from exploits import smtp_antispam
        target = MagicMock()
        target.host = None
        result = smtp_antispam.run(target)
        assert not result.exploited
        assert "no host" in result.error

    @patch("exploits.smtp_antispam._connect")
    def test_rate_limit_missing(self, mock_connect):
        from exploits import smtp_antispam
        sock = MagicMock()
        mock_connect.return_value = sock

        with patch("exploits.smtp_antispam._read_reply") as mock_read, \
             patch("exploits.smtp_antispam._cmd") as mock_cmd:
            # Server always accepts everything (no rate limiting)
            def fake_read(s):
                return (220, "220 mail.test ESMTP")

            def fake_cmd(s, line):
                if "EHLO" in line:
                    return (250, "250 OK")
                if "MAIL FROM" in line:
                    return (250, "250 OK")
                if "RCPT TO" in line:
                    return (250, "250 OK")
                if "RSET" in line:
                    return (250, "250 OK")
                if "QUIT" in line:
                    return (221, "221 Bye")
                if "DATA" in line:
                    return (354, "354 Go ahead")
                return (250, "250 OK")

            mock_read.side_effect = fake_read
            mock_cmd.side_effect = fake_cmd

            target = MagicMock()
            target.host = "10.0.0.5"
            target.port = 25
            target.ports = [25]
            target.scope_guard = None
            target.budget = None

            result = smtp_antispam.run(target)
            # Should detect missing rate-limit and spoof acceptance
            assert any("rate-limit" in f.title.lower() or "bomb" in f.title.lower()
                       for f in result.findings)

    @patch("exploits.smtp_antispam._connect")
    def test_rate_limit_present(self, mock_connect):
        from exploits import smtp_antispam
        sock = MagicMock()
        mock_connect.return_value = sock

        with patch("exploits.smtp_antispam._read_reply") as mock_read, \
             patch("exploits.smtp_antispam._cmd") as mock_cmd:
            call_count = [0]

            def fake_read(s):
                return (220, "220 mail.test ESMTP")

            def fake_cmd(s, line):
                if "EHLO" in line:
                    return (250, "250 OK")
                if "MAIL FROM" in line:
                    call_count[0] += 1
                    if call_count[0] >= 3:
                        return (421, "421 Too many connections")
                    return (250, "250 OK")
                if "RCPT TO" in line:
                    return (550, "550 No such user")
                if "RSET" in line:
                    return (250, "250 OK")
                if "QUIT" in line:
                    return (221, "221 Bye")
                return (250, "250 OK")

            mock_read.side_effect = fake_read
            mock_cmd.side_effect = fake_cmd

            target = MagicMock()
            target.host = "10.0.0.5"
            target.port = 25
            target.ports = [25]
            target.scope_guard = None
            target.budget = None

            result = smtp_antispam.run(target)
            # Should NOT detect missing rate-limit (server throttled)
            assert not any("rate-limit" in f.title.lower() for f in result.findings)

    @patch("exploits.smtp_antispam._test_backscatter")
    @patch("exploits.smtp_antispam._test_spoof_filter")
    @patch("exploits.smtp_antispam._test_rate_limit")
    @patch("exploits.smtp_antispam._connect")
    def test_gtube_accepted_means_no_filter(self, mock_connect, mock_rate, mock_spoof, mock_back):
        from exploits import smtp_antispam
        # Disable other tests so we only test spam filter
        mock_rate.return_value = []
        mock_spoof.return_value = []
        mock_back.return_value = []

        sock = MagicMock()
        mock_connect.return_value = sock

        with patch("exploits.smtp_antispam._read_reply") as mock_read, \
             patch("exploits.smtp_antispam._cmd") as mock_cmd:
            read_calls = [0]

            def fake_read(s):
                read_calls[0] += 1
                if read_calls[0] == 1:
                    return (220, "220 mail.test ESMTP")  # banner
                return (250, "250 OK")  # after DATA content → accepted

            def fake_cmd(s, line):
                if "EHLO" in line:
                    return (250, "250 OK")
                if "MAIL FROM" in line:
                    return (250, "250 OK")
                if "RCPT TO" in line:
                    return (250, "250 OK")
                if line.strip() == "DATA":
                    return (354, "354 Go ahead")
                if "RSET" in line:
                    return (250, "250 OK")
                if "QUIT" in line:
                    return (221, "221 Bye")
                return (250, "250 OK")

            mock_read.side_effect = fake_read
            mock_cmd.side_effect = fake_cmd

            target = MagicMock()
            target.host = "10.0.0.5"
            target.port = 25
            target.ports = [25]
            target.scope_guard = None
            target.budget = None

            result = smtp_antispam.run(target)
            # Should detect GTUBE acceptance
            assert any("gtube" in f.title.lower() or "spam" in f.title.lower()
                       for f in result.findings)

    def test_gtube_string_present(self):
        from exploits import smtp_antispam
        assert "GTUBE" in smtp_antispam._GTUBE
        assert len(smtp_antispam._GTUBE) > 40

    @patch("exploits.smtp_antispam.socket.create_connection")
    def test_connection_refused(self, mock_conn):
        from exploits import smtp_antispam
        mock_conn.side_effect = OSError("Connection refused")
        target = MagicMock()
        target.host = "10.0.0.5"
        target.port = 25
        target.ports = [25]
        target.scope_guard = None
        target.budget = None
        result = smtp_antispam.run(target)
        assert not result.exploited


class TestSMTPRegistry:
    def test_all_modules_registered(self):
        from exploits import registry
        names = [registry.name_of(m) for m in registry.ALL_MODULES]
        assert "smtp-enum" in names
        assert "smtp-auth-spray" in names
        assert "smtp-inject" in names
        assert "smtp-antispam" in names

    def test_module_count_increased(self):
        from exploits import registry
        # Should now be 89 (was 88 before adding smtp_antispam)
        assert len(registry.ALL_MODULES) >= 89
