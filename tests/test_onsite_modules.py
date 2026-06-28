"""Tests for on-site physical-audit modules (v8): wifi_probe, router_probe,
android_probe, ios_probe, bluetooth_probe, device_posture.

All tests are offline — no real network or hardware required. Internal helpers
are monkeypatched; no subprocess is actually executed.
"""
from __future__ import annotations

import socket
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from exploits import (
    android_probe,
    bluetooth_probe,
    device_posture,
    ios_probe,
    router_probe,
    wifi_probe,
)


# ---------------------------------------------------------------------------
# Shared target stubs
# ---------------------------------------------------------------------------

class _Local:
    kind = "local"
    local = True
    is_propagated = False
    raw = "local"
    host = "127.0.0.1"
    port = None
    ports = []
    pivot_targets: list = []
    scope_guard = None


class _Remote:
    kind = "hostport"
    local = False
    is_propagated = False
    raw = "10.0.0.1:80"
    host = "10.0.0.1"
    port = 80
    ports = [80]
    pivot_targets: list = []
    scope_guard = None


class _Propagated:
    kind = "hostport"
    local = False
    is_propagated = True
    raw = "10.0.0.2"
    host = "10.0.0.2"
    port = None
    ports = []
    pivot_targets: list = []
    scope_guard = None


def _make_hostport(host="10.0.0.1", port=80):
    return SimpleNamespace(
        kind="hostport", host=host, port=port, ports=[port],
        local=False, is_propagated=False, raw=f"{host}:{port}",
        pivot_targets=[], scope_guard=None,
    )


def _open_port():
    """Start a listening TCP server on a random localhost port. Returns (srv, port)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    return srv, srv.getsockname()[1]


# ===========================================================================
# wifi_probe
# ===========================================================================

class TestWifiProbe:
    def test_skipped_for_remote_non_propagated(self):
        res = wifi_probe.run(_Remote())
        assert res.tool_available is False
        assert res.exploited is False

    def test_propagated_allowed(self, monkeypatch):
        # Patch the internal discovery so it returns an empty list (no WiFi visible)
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: ([], True))
        res = wifi_probe.run(_Propagated())
        assert not any("not running on a local" in (f.detail or "") for f in res.findings)

    def test_no_networks_visible(self, monkeypatch):
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: ([], True))
        res = wifi_probe.run(_Local())
        assert res.exploited is False

    def test_open_network_high_finding(self, monkeypatch):
        networks = [{"ssid": "FreeWifi", "bssid": "AA:BB:CC:DD:EE:FF",
                     "channel": "6", "signal": "-60", "security": "open", "wps": False}]
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: (networks, True))
        res = wifi_probe.run(_Local())
        assert any(f.severity == "HIGH" for f in res.findings)
        assert res.exploited is True

    def test_wep_network_high_finding(self, monkeypatch):
        networks = [{"ssid": "OldNet", "bssid": "11:22:33:44:55:66",
                     "channel": "11", "signal": "-70", "security": "WEP", "wps": False}]
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: (networks, True))
        res = wifi_probe.run(_Local())
        assert any(f.severity == "HIGH" and "wep" in f.title.lower() for f in res.findings)
        assert res.exploited is True

    def test_wps_network_medium_finding(self, monkeypatch):
        networks = [{"ssid": "HomeNet", "bssid": "DE:AD:BE:EF:00:01",
                     "channel": "1", "signal": "-55", "security": "WPA2", "wps": True}]
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: (networks, True))
        res = wifi_probe.run(_Local())
        assert any(f.severity == "MEDIUM" for f in res.findings)

    def test_wpa2_only_is_info(self, monkeypatch):
        networks = [{"ssid": "SecureNet", "bssid": "DE:AD:BE:EF:00:02",
                     "channel": "6", "signal": "-50", "security": "WPA2", "wps": False}]
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: (networks, True))
        res = wifi_probe.run(_Local())
        assert not any(f.severity in ("HIGH", "CRITICAL") for f in res.findings)
        assert res.exploited is False

    def test_no_tools_returns_no_exploit(self, monkeypatch):
        monkeypatch.setattr(wifi_probe, "_discover_networks",
                            lambda: (None, False))
        res = wifi_probe.run(_Local())
        assert res.exploited is False


# ===========================================================================
# router_probe
# ===========================================================================

class TestRouterProbe:
    # _probe_host returns (List[Finding], List[Tuple]) — mock must match this shape.

    def test_no_response_no_exploit(self, monkeypatch):
        monkeypatch.setattr(router_probe, "_probe_host",
                            lambda host, skip_port=None: ([], []))
        res = router_probe.run(_make_hostport("192.168.1.1", 80))
        assert res.exploited is False

    def test_openwrt_detection_medium_finding(self, monkeypatch):
        from exploits.base import Finding
        fake_finding = Finding(
            title="Router admin interface exposed: openwrt",
            severity="MEDIUM", location="192.168.1.1:80",
            detail="OpenWrt detected.", evidence="<title>OpenWrt</title>",
        )
        monkeypatch.setattr(router_probe, "_probe_host",
                            lambda host, skip_port=None: ([fake_finding], [("openwrt", 80, "<title>OpenWrt</title>")]))
        res = router_probe.run(_make_hostport("192.168.1.1", 80))
        assert any(f.severity == "MEDIUM" for f in res.findings)

    def test_telnet_high_finding(self, monkeypatch):
        from exploits.base import Finding
        telnet_finding = Finding(
            title="Telnet enabled on 192.168.1.1:23 — cleartext management protocol",
            severity="HIGH", location="192.168.1.1:23",
            detail="Telnet transmits credentials in plaintext.", evidence="TCP connect OK",
            cwe="CWE-319",
        )
        monkeypatch.setattr(router_probe, "_probe_host",
                            lambda host, skip_port=None: ([telnet_finding], []))
        res = router_probe.run(_make_hostport("192.168.1.1", 80))
        assert any(f.severity == "HIGH" and "telnet" in f.title.lower() for f in res.findings)
        assert res.exploited is True

    def test_tr069_high_finding(self, monkeypatch):
        from exploits.base import Finding
        tr_finding = Finding(
            title="TR-069/CWMP management interface exposed to LAN — ISP protocol should never be LAN-accessible",
            severity="HIGH", location="192.168.1.1:7547",
            detail="ISP protocol should never be LAN-accessible.",
            cwe="CWE-16",
        )
        monkeypatch.setattr(router_probe, "_probe_host",
                            lambda host, skip_port=None: ([tr_finding], []))
        res = router_probe.run(_make_hostport("192.168.1.1", 7547))
        assert any(f.severity == "HIGH" for f in res.findings)


# ===========================================================================
# android_probe
# ===========================================================================

class TestAndroidProbe:
    def test_port_closed_no_exploit(self, monkeypatch):
        monkeypatch.setattr(android_probe, "_port_open", lambda *a, **k: False)
        monkeypatch.setattr(android_probe, "_tcp_probe_adb", lambda *a, **k: None)
        res = android_probe.run(_make_hostport("10.0.0.100", 5555))
        assert res.exploited is False

    def test_cnxn_response_high(self, monkeypatch):
        monkeypatch.setattr(android_probe, "_port_open", lambda *a, **k: True)
        monkeypatch.setattr(android_probe, "_tcp_probe_adb",
                            lambda *a, **k: b"CNXN\x00\x00\x00\x01" + b"\x00" * 16)
        monkeypatch.setattr(android_probe.toolrunner, "available", lambda b: False)
        res = android_probe.run(_make_hostport("10.0.0.100", 5555))
        assert any(f.severity in ("HIGH", "CRITICAL") for f in res.findings)
        assert res.exploited is True

    def test_auth_response_high(self, monkeypatch):
        monkeypatch.setattr(android_probe, "_port_open", lambda *a, **k: True)
        monkeypatch.setattr(android_probe, "_tcp_probe_adb",
                            lambda *a, **k: b"AUTH\x00\x00\x00\x01" + b"\x00" * 16)
        monkeypatch.setattr(android_probe.toolrunner, "available", lambda b: False)
        res = android_probe.run(_make_hostport("10.0.0.100", 5555))
        assert any(f.severity in ("HIGH", "CRITICAL") for f in res.findings)

    def test_pivot_target_added_when_shell_confirmed(self, monkeypatch):
        # Pivot is added only when adb shell is confirmed (not just TCP handshake).
        monkeypatch.setattr(android_probe, "_port_open", lambda *a, **k: True)
        monkeypatch.setattr(android_probe, "_tcp_probe_adb",
                            lambda *a, **k: b"CNXN\x00\x00\x00\x01" + b"\x00" * 16)
        # Mock toolrunner.available + run_tool to simulate successful shell
        monkeypatch.setattr(android_probe.toolrunner, "available", lambda b: True)
        connect_result = MagicMock()
        connect_result.ok = True
        connect_result.stdout = "connected to 10.0.0.100:5555"
        id_result = MagicMock()
        id_result.ok = True
        id_result.stdout = "uid=0(root) gid=0(root)"
        monkeypatch.setattr(android_probe.toolrunner, "run_tool",
                            lambda cmd, **k: connect_result if "connect" in cmd else id_result)
        target = _make_hostport("10.0.0.100", 5555)
        target.pivot_targets = []
        android_probe.run(target)
        assert any(p.get("via") == "android-adb" for p in target.pivot_targets)

    def test_netrange_sweep_finds_adb_hosts(self, monkeypatch):
        """For netrange targets, android_probe sweeps all hosts for port 5555."""
        # Mock _sweep_hosts to return two live hosts
        monkeypatch.setattr(android_probe, "_sweep_hosts",
                            lambda hosts, port: ["10.0.0.5", "10.0.0.22"])
        # CNXN response for both hosts
        monkeypatch.setattr(android_probe, "_tcp_probe_adb",
                            lambda *a, **k: b"CNXN\x00\x00\x00\x01" + b"\x00" * 16)
        monkeypatch.setattr(android_probe, "_port_open", lambda *a, **k: True)
        monkeypatch.setattr(android_probe.toolrunner, "available", lambda b: False)
        target = SimpleNamespace(
            kind="netrange", host="10.0.0.0", port=5555, ports=[5555],
            hosts=["10.0.0.%d" % i for i in range(1, 25)],
            local=False, is_propagated=False, raw="10.0.0.0/24",
            pivot_targets=[], scope_guard=None,
        )
        res = android_probe.run(target)
        high_findings = [f for f in res.findings if f.severity == "HIGH"]
        assert len(high_findings) >= 2, f"Expected 2+ HIGH findings, got {len(high_findings)}"
        assert res.exploited is True

    def test_netrange_no_adb_hosts_info(self, monkeypatch):
        """Netrange with no live hosts returns INFO finding."""
        monkeypatch.setattr(android_probe, "_sweep_hosts", lambda hosts, port: [])
        monkeypatch.setattr(android_probe.toolrunner, "available", lambda b: False)
        target = SimpleNamespace(
            kind="netrange", host="10.0.0.0", port=5555, ports=[5555],
            hosts=["10.0.0.%d" % i for i in range(1, 25)],
            local=False, is_propagated=False, raw="10.0.0.0/24",
            pivot_targets=[], scope_guard=None,
        )
        res = android_probe.run(target)
        assert res.exploited is False
        assert any("not detected" in f.title.lower() or f.severity == "INFO" for f in res.findings)

    def test_port_open_no_adb_is_info(self, monkeypatch):
        monkeypatch.setattr(android_probe, "_port_open", lambda *a, **k: True)
        # No ADB response — unknown service
        monkeypatch.setattr(android_probe, "_tcp_probe_adb", lambda *a, **k: b"\x00" * 4)
        monkeypatch.setattr(android_probe.toolrunner, "available", lambda b: False)
        res = android_probe.run(_make_hostport("10.0.0.100", 5555))
        # Should not be critical — just INFO or MEDIUM
        assert not any(f.severity == "CRITICAL" for f in res.findings)


# ===========================================================================
# ios_probe
# ===========================================================================

class TestIosProbe:
    def test_port_closed_no_exploit(self, monkeypatch):
        monkeypatch.setattr(ios_probe, "_tcp_open", lambda *a, **k: False)
        monkeypatch.setattr(ios_probe, "_tcp_banner", lambda *a, **k: None)
        res = ios_probe.run(_make_hostport("10.0.0.50", 62078))
        assert res.exploited is False

    def test_itunes_sync_port_medium(self, monkeypatch):
        def fake_tcp_open(host, port, **k):
            return port == 62078
        monkeypatch.setattr(ios_probe, "_tcp_open", fake_tcp_open)
        monkeypatch.setattr(ios_probe, "_tcp_banner", lambda *a, **k: None)
        res = ios_probe.run(_make_hostport("10.0.0.50", 62078))
        assert any(f.severity == "MEDIUM" for f in res.findings)

    def test_jailbroken_ssh_plus_itunes_medium(self, monkeypatch):
        def fake_tcp_open(host, port, **k):
            return port in (62078, 22)
        def fake_tcp_banner(host, port, **k):
            if port == 22:
                return "SSH-2.0-OpenSSH_8.9 Debian-3\r\n"
            return None
        monkeypatch.setattr(ios_probe, "_tcp_open", fake_tcp_open)
        monkeypatch.setattr(ios_probe, "_tcp_banner", fake_tcp_banner)
        res = ios_probe.run(_make_hostport("10.0.0.50", 62078))
        jailbreak = any(
            ("jailbreak" in f.title.lower() or ("ssh" in f.title.lower() and f.severity == "MEDIUM"))
            for f in res.findings
        )
        assert jailbreak, f"Jailbreak finding expected. Findings: {[f.title for f in res.findings]}"

    def test_exploited_always_false(self, monkeypatch):
        def fake_tcp_open(host, port, **k):
            return True
        monkeypatch.setattr(ios_probe, "_tcp_open", fake_tcp_open)
        monkeypatch.setattr(ios_probe, "_tcp_banner",
                            lambda *a, **k: "SSH-2.0-OpenSSH_7.0\r\n")
        res = ios_probe.run(_make_hostport("10.0.0.50", 62078))
        assert res.exploited is False

    def test_xcode_proxy_port_info(self, monkeypatch):
        def fake_tcp_open(host, port, **k):
            return port == 27015
        monkeypatch.setattr(ios_probe, "_tcp_open", fake_tcp_open)
        monkeypatch.setattr(ios_probe, "_tcp_banner", lambda *a, **k: None)
        res = ios_probe.run(_make_hostport("10.0.0.50", 27015))
        assert any("27015" in f.title or "xcode" in f.title.lower() for f in res.findings)


# ===========================================================================
# bluetooth_probe
# ===========================================================================

class TestBluetoothProbe:
    def test_skipped_for_remote_non_propagated(self):
        res = bluetooth_probe.run(_Remote())
        assert res.tool_available is False
        assert res.exploited is False

    def test_no_adapter_info_finding(self, monkeypatch):
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: False)
        res = bluetooth_probe.run(_Local())
        assert res.exploited is False
        assert any("adapter" in f.title.lower() or "bluetooth" in f.title.lower()
                   for f in res.findings)

    def test_adapter_no_devices_info(self, monkeypatch):
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: True)
        monkeypatch.setattr(bluetooth_probe, "_scan_bluetoothctl",
                            lambda: (True, []))
        monkeypatch.setattr(bluetooth_probe, "_scan_hcitool",
                            lambda: (False, []))
        res = bluetooth_probe.run(_Local())
        assert res.exploited is False
        assert any("no" in f.title.lower() or "no discoverable" in f.title.lower()
                   or "0" in f.title or "range" in f.title.lower()
                   for f in res.findings)

    def test_discoverable_device_is_info(self, monkeypatch):
        devices = [
            {"addr": "AA:BB:CC:DD:EE:FF", "name": "SomePhone", "source": "bluetoothctl"},
        ]
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: True)
        monkeypatch.setattr(bluetooth_probe, "_scan_bluetoothctl",
                            lambda: (True, devices))
        monkeypatch.setattr(bluetooth_probe, "_device_info",
                            lambda addr: {})
        monkeypatch.setattr(bluetooth_probe, "_scan_hcitool", lambda: (False, []))
        res = bluetooth_probe.run(_Local())
        assert any("discoverable" in f.title.lower() or "somephon" in f.title.lower()
                   for f in res.findings)
        assert res.exploited is False

    def test_propagated_host_allowed(self, monkeypatch):
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: False)
        res = bluetooth_probe.run(_Propagated())
        # Propagated → gate passes; no adapter → INFO, not a "not local" skip
        assert not any("not running on a local" in (f.detail or "") for f in res.findings)


# ===========================================================================
# device_posture
# ===========================================================================

class TestDevicePosture:
    def test_skipped_for_remote_non_propagated(self):
        res = device_posture.run(_Remote())
        assert res.tool_available is False
        assert res.exploited is False

    def test_root_uid_high(self, monkeypatch):
        monkeypatch.setattr(device_posture, "_check_privilege",
                            lambda: [device_posture.Finding(
                                title="Running as root (uid=0)",
                                severity="HIGH", location="local",
                                detail="Full device privileges.", cwe="CWE-250",
                            )])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
        monkeypatch.setattr(device_posture, "_local_service_scan", lambda: [])
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])
        res = device_posture.run(_Local())
        assert any(f.severity == "HIGH" and "root" in f.title.lower() for f in res.findings)
        assert res.exploited is True

    def test_cap_sys_admin_high(self, monkeypatch):
        monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities",
                            lambda: [device_posture.Finding(
                                title="CAP_SYS_ADMIN effective — container escape likely possible",
                                severity="HIGH", location="local",
                                detail="CAP_SYS_ADMIN allows mounting, eBPF, etc.",
                                cwe="CWE-269",
                            )])
        monkeypatch.setattr(device_posture, "_local_service_scan", lambda: [])
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])
        res = device_posture.run(_Local())
        assert any("cap_sys_admin" in f.title.lower() or "sys_admin" in f.title.lower()
                   for f in res.findings if f.severity == "HIGH")
        assert res.exploited is True

    def test_localhost_port_added_to_pivot(self, monkeypatch):
        srv, open_port = _open_port()
        try:
            # Patch all sub-checks except the local service scan
            monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
            monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
            monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
            monkeypatch.setattr(device_posture, "_check_container", lambda: [])
            monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
            monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
            monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
            monkeypatch.setattr(device_posture, "_check_python", lambda: [])
            # Inject only our dynamic port into the scan list
            original = list(device_posture._LOCAL_PORTS)
            device_posture._LOCAL_PORTS = [open_port]
            target = _Local()
            target.pivot_targets = []
            try:
                res = device_posture.run(target)
            finally:
                device_posture._LOCAL_PORTS = original
        finally:
            srv.close()

        pivot_ports = [p.get("port") for p in target.pivot_targets]
        finding_text = " ".join((f.title or "") + (f.detail or "") for f in res.findings)
        assert open_port in pivot_ports or str(open_port) in finding_text

    def test_propagated_target_allowed(self, monkeypatch):
        for fn in ("_check_privilege", "_check_restricted_shell", "_os_fingerprint",
                   "_check_container", "_check_capabilities", "_local_service_scan",
                   "_check_wifi", "_check_bt_adapter", "_check_python"):
            monkeypatch.setattr(device_posture, fn, lambda: [])
        res = device_posture.run(_Propagated())
        assert not any("not running on a local" in (f.detail or "") for f in res.findings)


# ===========================================================================
# Intensity inheritance (question 1 — already correct; this confirms it)
# ===========================================================================

class TestIntensityInheritance:
    def test_active_includes_detective(self):
        from sandbox import scope_guard
        assert scope_guard.allows("active", "detective")
        assert scope_guard.allows("active", "active")
        assert not scope_guard.allows("active", "intrusive")

    def test_intrusive_includes_active_and_detective(self):
        from sandbox import scope_guard
        assert scope_guard.allows("intrusive", "detective")
        assert scope_guard.allows("intrusive", "active")
        assert scope_guard.allows("intrusive", "intrusive")

    def test_proof_peak_includes_base_ladder(self):
        from sandbox import scope_guard
        assert scope_guard.allows("proof", "detective")
        assert scope_guard.allows("proof", "active")
        assert scope_guard.allows("proof", "intrusive")
        assert scope_guard.allows("proof", "proof")
        assert not scope_guard.allows("proof", "fuzz")

    def test_fuzz_peak_includes_base_ladder_and_proof(self):
        from sandbox import scope_guard
        assert scope_guard.allows("fuzz", "detective")
        assert scope_guard.allows("fuzz", "active")
        assert scope_guard.allows("fuzz", "intrusive")
        assert scope_guard.allows("fuzz", "proof")   # fuzz ⊇ proof
        assert scope_guard.allows("fuzz", "fuzz")

    def test_proof_does_not_include_fuzz(self):
        from sandbox import scope_guard
        # proof is a distinct peak — it does not unlock fuzz modules
        assert not scope_guard.allows("proof", "fuzz")

    def test_detective_excludes_higher_tiers(self):
        from sandbox import scope_guard
        assert scope_guard.allows("detective", "detective")
        assert not scope_guard.allows("detective", "active")
        assert not scope_guard.allows("detective", "intrusive")
        assert not scope_guard.allows("detective", "proof")
        assert not scope_guard.allows("detective", "fuzz")


# ===========================================================================
# privesc_exploit module tests
# ===========================================================================

class TestPrivescExploit:
    def test_module_contract(self):
        from exploits import privesc_exploit
        assert privesc_exploit.NAME == "privesc-exploit"
        assert "local" in privesc_exploit.SUPPORTS
        assert privesc_exploit.INTENSITY == "intrusive"

    def test_skipped_for_remote_non_propagated(self):
        from exploits import privesc_exploit
        from unittest.mock import MagicMock
        target = MagicMock()
        target.kind = "hostport"
        target.local = False
        target.is_propagated = False
        result = privesc_exploit.run(target)
        assert not result.exploited
        assert not result.tool_available

    def test_skips_when_already_root(self, monkeypatch):
        from exploits import privesc_exploit
        from unittest.mock import MagicMock
        monkeypatch.setattr(privesc_exploit, "_current_uid", lambda: 0)
        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        result = privesc_exploit.run(target)
        assert not result.exploited
        assert any("already running as root" in f.title.lower() for f in result.findings)

    def test_suid_escalation_success(self, monkeypatch):
        from exploits import privesc_exploit
        from unittest.mock import MagicMock
        import shutil

        monkeypatch.setattr(privesc_exploit, "_current_uid", lambda: 1000)
        # Pretend python3 is SUID
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name == "python3" else None)
        monkeypatch.setattr(privesc_exploit, "_is_suid", lambda path: "python3" in path)

        def fake_run(argv, timeout=10):
            if "python3" in argv[0]:
                return "uid=0(root) gid=0(root) groups=0(root)"
            return None
        monkeypatch.setattr(privesc_exploit, "_run", fake_run)

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        result = privesc_exploit.run(target)
        assert result.exploited
        assert any("CRITICAL" == f.severity for f in result.findings)
        assert any("suid" in f.title.lower() for f in result.findings)
        # Root shell relay added for propagation
        assert len(target.pivot_targets) >= 1
        assert target.pivot_targets[0]["relay"]["type"] == "shell-exec"

    def test_no_vectors_returns_info(self, monkeypatch):
        from exploits import privesc_exploit
        from unittest.mock import MagicMock
        import shutil

        monkeypatch.setattr(privesc_exploit, "_current_uid", lambda: 1000)
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(privesc_exploit, "_is_suid", lambda path: False)
        monkeypatch.setattr(privesc_exploit, "_run", lambda argv, timeout=10: None)
        # Suppress filesystem-based checks that may find real writable paths on the host
        monkeypatch.setattr(privesc_exploit, "_check_writable_path", lambda: [])
        monkeypatch.setattr(privesc_exploit, "_check_writable_cron", lambda: [])

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        result = privesc_exploit.run(target)
        assert not result.exploited
        assert any("no exploitable" in f.title.lower() for f in result.findings)

    def test_sudo_nopasswd_escalation(self, monkeypatch):
        from exploits import privesc_exploit
        from unittest.mock import MagicMock
        import shutil

        monkeypatch.setattr(privesc_exploit, "_current_uid", lambda: 1000)
        # No SUID binaries
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}" if name in ("sudo", "find") else None)
        monkeypatch.setattr(privesc_exploit, "_is_suid", lambda path: False)

        sudo_l_output = "(ALL) NOPASSWD: /usr/bin/find"

        def fake_run(argv, timeout=10):
            if argv == ["sudo", "-n", "-l"]:
                return sudo_l_output
            if "sudo" in argv and "find" in argv:
                return "uid=0(root) gid=0(root)"
            return None
        monkeypatch.setattr(privesc_exploit, "_run", fake_run)

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        result = privesc_exploit.run(target)
        assert result.exploited
        assert any("sudo" in f.title.lower() for f in result.findings)


# ===========================================================================
# router_auth module tests
# ===========================================================================

class TestRouterAuth:
    def test_module_contract(self):
        from exploits import router_auth
        assert router_auth.NAME == "router-auth"
        assert "hostport" in router_auth.SUPPORTS
        assert "netrange" in router_auth.SUPPORTS
        assert router_auth.INTENSITY == "intrusive"

    def test_no_host_returns_info(self):
        from exploits import router_auth
        from unittest.mock import MagicMock
        target = MagicMock()
        target.kind = "hostport"
        target.host = ""
        target.ip = ""
        result = router_auth.run(target)
        assert not result.exploited

    def test_no_panel_returns_info(self, monkeypatch):
        from exploits import router_auth
        from unittest.mock import MagicMock
        # fingerprint returns "" — no router detected
        monkeypatch.setattr(router_auth, "_fingerprint", lambda host, port, scheme: "")
        target = MagicMock()
        target.kind = "hostport"
        target.host = "192.168.1.1"
        target.scope_guard = None
        result = router_auth.run(target)
        assert not result.exploited
        assert any("no router admin panel" in f.title.lower() for f in result.findings)

    def test_default_creds_accepted_basic_auth(self, monkeypatch):
        from exploits import router_auth
        from unittest.mock import MagicMock
        import time as _time

        monkeypatch.setattr(router_auth, "_fingerprint",
                            lambda host, port, scheme: "openwrt")
        monkeypatch.setattr(router_auth, "_try_basic_auth",
                            lambda host, port, scheme, user, pw: (True, 200) if pw == "" else (False, 401))
        monkeypatch.setattr(_time, "sleep", lambda s: None)

        target = MagicMock()
        target.kind = "hostport"
        target.host = "192.168.1.1"
        target.scope_guard = None
        target.pivot_targets = []
        result = router_auth.run(target)
        assert result.exploited
        assert any("CRITICAL" == f.severity for f in result.findings)
        assert "openwrt" in result.findings[0].title.lower()
        # Relay for propagation added
        assert len(target.pivot_targets) >= 1
        assert target.pivot_targets[0]["relay"]["type"] == "http-upload"

    def test_no_creds_accepted_returns_info(self, monkeypatch):
        from exploits import router_auth
        from unittest.mock import MagicMock
        import time as _time

        monkeypatch.setattr(router_auth, "_fingerprint",
                            lambda host, port, scheme: "mikrotik")
        monkeypatch.setattr(router_auth, "_try_basic_auth",
                            lambda host, port, scheme, user, pw: (False, 401))
        monkeypatch.setattr(router_auth, "_try_form_login",
                            lambda host, port, scheme, fw, user, pw: (False, 401))
        monkeypatch.setattr(_time, "sleep", lambda s: None)

        target = MagicMock()
        target.kind = "hostport"
        target.host = "192.168.88.1"
        target.scope_guard = None
        target.pivot_targets = []
        result = router_auth.run(target)
        assert not result.exploited
        assert any("no default credentials accepted" in f.title.lower() for f in result.findings)

    def test_netrange_tests_each_host(self, monkeypatch):
        from exploits import router_auth
        from unittest.mock import MagicMock
        import time as _time

        call_log = []
        monkeypatch.setattr(router_auth, "_fingerprint",
                            lambda host, port, scheme: "tplink")
        def fake_basic(host, port, scheme, user, pw):
            call_log.append(host)
            return (True, 200) if host == "10.0.0.2" and pw == "admin" else (False, 401)
        monkeypatch.setattr(router_auth, "_try_basic_auth", fake_basic)
        monkeypatch.setattr(router_auth, "_try_form_login",
                            lambda *a: (False, 0))
        monkeypatch.setattr(_time, "sleep", lambda s: None)

        target = MagicMock()
        target.kind = "netrange"
        target.host = ""
        target.hosts = ["10.0.0.1", "10.0.0.2"]
        target.scope_guard = None
        target.pivot_targets = []
        result = router_auth.run(target)
        assert result.exploited
        assert "10.0.0.2" in call_log


# ===========================================================================
# container_escape pivot_targets tests (docker socket → relay)
# ===========================================================================

class TestContainerEscapeDockerPivot:
    def test_docker_socket_adds_pivot_target(self, monkeypatch, tmp_path):
        from exploits import container_escape
        from unittest.mock import MagicMock
        import os

        # Create a fake docker socket file
        fake_sock = str(tmp_path / "docker.sock")
        open(fake_sock, "w").close()

        monkeypatch.setattr(container_escape, "_in_container",
                            lambda: (True, "/.dockerenv present"))
        monkeypatch.setattr(container_escape, "_cap_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_socket_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_mount_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_privileged_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_runc_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_local_prove_findings", lambda prove: [])

        # Patch the socket path check in _run_local to use our fake socket
        _real_exists = os.path.exists
        _real_access = os.access
        monkeypatch.setattr(os.path, "exists",
                            lambda p: p == fake_sock or _real_exists(p))
        monkeypatch.setattr(os, "access",
                            lambda p, m: p == fake_sock or _real_access(p, m))
        # Also patch the constant list in container_escape
        monkeypatch.setattr(container_escape, "_DOCKER_SOCKS" if hasattr(container_escape, "_DOCKER_SOCKS") else "__file__",
                            [fake_sock], raising=False)

        target = MagicMock()
        target.kind = "local"
        target.prove_access = False
        target.pivot_targets = []

        container_escape._run_local(target)
        # Pivot should be added
        relay_types = [pt.get("relay", {}).get("type") for pt in target.pivot_targets]
        assert "docker" in relay_types

    def test_no_socket_no_pivot(self, monkeypatch):
        from exploits import container_escape
        from unittest.mock import MagicMock
        import os

        monkeypatch.setattr(container_escape, "_in_container",
                            lambda: (True, "/.dockerenv present"))
        monkeypatch.setattr(container_escape, "_cap_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_socket_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_mount_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_privileged_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_runc_findings", lambda: [])
        monkeypatch.setattr(container_escape, "_local_prove_findings", lambda prove: [])
        # Ensure no socket paths exist
        monkeypatch.setattr(os.path, "exists", lambda p: False)

        target = MagicMock()
        target.kind = "local"
        target.prove_access = False
        target.pivot_targets = []

        container_escape._run_local(target)
        relay_types = [pt.get("relay", {}).get("type") for pt in target.pivot_targets]
        assert "docker" not in relay_types


# ===========================================================================
# device_posture extended pivot_targets (wifi / bt / docker)
# ===========================================================================

class TestDevicePostureExtendedPivots:
    def test_wifi_adapter_adds_pivot(self, monkeypatch):
        from exploits import device_posture
        from exploits.base import Finding
        from unittest.mock import MagicMock
        import os

        wifi_finding = Finding(
            title="WiFi adapter present: wlan0", severity="INFO",
            location="local", detail="", evidence="", category="posture",
            tags=["wifi-adapter"],
        )
        monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
        monkeypatch.setattr(device_posture, "_local_service_scan", lambda: ([], []))
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [wifi_finding])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])
        monkeypatch.setattr(os.path, "exists", lambda p: False)

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        device_posture.run(target)

        vias = [pt.get("via", "") for pt in target.pivot_targets]
        assert any("wifi-adapter" in v for v in vias)

    def test_bt_adapter_adds_pivot(self, monkeypatch):
        from exploits import device_posture
        from exploits.base import Finding
        from unittest.mock import MagicMock
        import os

        bt_finding = Finding(
            title="Bluetooth adapter present: hci0", severity="INFO",
            location="local", detail="", evidence="", category="posture",
            tags=["bt-adapter"],
        )
        monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
        monkeypatch.setattr(device_posture, "_local_service_scan", lambda: ([], []))
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [bt_finding])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])
        monkeypatch.setattr(os.path, "exists", lambda p: False)

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        device_posture.run(target)

        vias = [pt.get("via", "") for pt in target.pivot_targets]
        assert any("bt-adapter" in v for v in vias)

    def test_docker_socket_adds_pivot(self, monkeypatch, tmp_path):
        from exploits import device_posture
        from unittest.mock import MagicMock
        import os

        fake_sock = str(tmp_path / "docker.sock")
        open(fake_sock, "w").close()

        monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
        monkeypatch.setattr(device_posture, "_local_service_scan", lambda: ([], []))
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])

        _real_exists = os.path.exists
        _real_access = os.access
        monkeypatch.setattr(os.path, "exists",
                            lambda p: p == fake_sock or _real_exists(p))
        monkeypatch.setattr(os, "access",
                            lambda p, m: p == fake_sock or _real_access(p, m))

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []

        # Patch device_posture's docker socket list to include our fake socket
        import exploits.device_posture as dp_mod
        original_code = dp_mod.run.__code__
        # Use monkeypatch to replace the socket path list in the run() code at runtime
        # by patching os.path.exists to return True for our sock path
        # (already done above) — the run() function will find our sock
        # but we need the sock to be in the _docker_socks list; patch via the module
        # We can't easily patch inline lists, so instead we test via the os.path.exists mock

        # The device_posture.run() uses hardcoded paths "/var/run/docker.sock" etc.
        # Patch exists to True for ANY path ending in "docker.sock"
        monkeypatch.setattr(os.path, "exists",
                            lambda p: "docker.sock" in p or _real_exists(p))
        monkeypatch.setattr(os, "access",
                            lambda p, m: "docker.sock" in p or _real_access(p, m))

        device_posture.run(target)

        relay_types = [pt.get("relay", {}).get("type") for pt in target.pivot_targets]
        assert "docker" in relay_types


# ===========================================================================
# privesc_exploit — password spray, kernel CVE, proof-of-access (Request 2)
# ===========================================================================

class TestPrivescPasswordSpray:
    def test_spray_succeeds_with_correct_password(self, monkeypatch):
        from exploits import privesc_exploit

        monkeypatch.setattr(privesc_exploit, "_current_uid", lambda: 1000)
        import shutil
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.setattr(privesc_exploit, "_is_suid", lambda path: False)
        monkeypatch.setattr(privesc_exploit, "_run", lambda argv, timeout=10: None)
        monkeypatch.setattr(privesc_exploit, "_check_writable_path", lambda: [])
        monkeypatch.setattr(privesc_exploit, "_check_writable_cron", lambda: [])
        monkeypatch.setattr(privesc_exploit, "_check_sudo_baron_samedit", lambda: [])
        monkeypatch.setattr(privesc_exploit, "_check_pkexec_pwnkit", lambda: [])
        monkeypatch.setattr(privesc_exploit, "_check_kernel_cves", lambda: [])

        def fake_spray():
            return ([privesc_exploit.Finding(
                title="Default password accepted by sudo: user=root pw=toor",
                severity="CRITICAL",
                location="local",
                detail="sudo accepted the password 'toor' for root via -S",
                evidence="uid=0(root)",
                cwe="CWE-521",
                category="credential",
                tags=["sudo", "default-password", "privesc"],
            )], True)
        monkeypatch.setattr(privesc_exploit, "_spray_sudo_passwords", fake_spray)

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        result = privesc_exploit.run(target)
        assert result.exploited
        assert any("default password" in f.title.lower() for f in result.findings)

    def test_spray_capped_at_max(self, monkeypatch):
        from exploits import privesc_exploit
        import subprocess

        call_count = []

        def fake_run_subprocess(argv, **kwargs):
            call_count.append(1)
            m = MagicMock()
            m.returncode = 1
            m.stdout = ""
            return m

        monkeypatch.setattr(subprocess, "run", fake_run_subprocess)
        findings, _ok = privesc_exploit._spray_sudo_passwords()
        assert len(call_count) <= privesc_exploit._SPRAY_MAX

    def test_spray_no_success_returns_empty(self, monkeypatch):
        from exploits import privesc_exploit
        import subprocess

        def fake_run_subprocess(argv, **kwargs):
            m = MagicMock()
            m.returncode = 1
            m.stdout = ""
            return m

        monkeypatch.setattr(subprocess, "run", fake_run_subprocess)
        findings, ok = privesc_exploit._spray_sudo_passwords()
        assert ok is False
        # May return an INFO summary finding but no CRITICAL escalation finding
        assert not any(f.severity == "CRITICAL" for f in findings)


class TestKernelCveDetection:
    def test_dirtypipe_detected(self, monkeypatch):
        from exploits import privesc_exploit

        # DirtyPipe: 5.8.0 – 5.16.11
        monkeypatch.setattr(privesc_exploit, "_run", lambda argv, timeout=10: "5.10.0-generic")
        monkeypatch.setattr(privesc_exploit, "_parse_kernel_version",
                            lambda _uname_r: (5, 10, 0))
        findings = privesc_exploit._check_kernel_cves()
        titles = [f.title for f in findings]
        assert any("CVE-2022-0847" in t or "dirtypipe" in t.lower() for t in titles)

    def test_dirtycow_detected(self, monkeypatch):
        from exploits import privesc_exploit

        # DirtyCow: 2.6.22 – 4.8.3
        monkeypatch.setattr(privesc_exploit, "_run", lambda argv, timeout=10: "4.4.0-generic")
        monkeypatch.setattr(privesc_exploit, "_parse_kernel_version",
                            lambda _uname_r: (4, 4, 0))
        findings = privesc_exploit._check_kernel_cves()
        titles = [f.title for f in findings]
        assert any("CVE-2016-5195" in t or "dirtycow" in t.lower() for t in titles)

    def test_safe_kernel_no_cve(self, monkeypatch):
        from exploits import privesc_exploit

        # Modern kernel beyond all ranges
        monkeypatch.setattr(privesc_exploit, "_run", lambda argv, timeout=10: "6.5.0-generic")
        monkeypatch.setattr(privesc_exploit, "_parse_kernel_version",
                            lambda _uname_r: (6, 5, 0))
        findings = privesc_exploit._check_kernel_cves()
        assert findings == []

    def test_baron_samedit_detected(self, monkeypatch):
        from exploits import privesc_exploit

        # sudo 1.9.4 is < 1.9.5p2 → vulnerable
        def fake_run(argv, timeout=10):
            if "sudo" in argv and "--version" in argv:
                return "Sudo version 1.9.4\nSudoers policy plugin version 1.9.4"
            return None
        monkeypatch.setattr(privesc_exploit, "_run", fake_run)

        findings = privesc_exploit._check_sudo_baron_samedit()
        titles = [f.title for f in findings]
        assert any("cve-2021-3156" in t.lower() or "baron samedit" in t.lower() for t in titles)

    def test_pwnkit_detected_when_suid_pkexec(self, monkeypatch):
        from exploits import privesc_exploit
        import shutil

        monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/pkexec" if b == "pkexec" else None)
        monkeypatch.setattr(privesc_exploit, "_is_suid", lambda p: p == "/usr/bin/pkexec")

        findings = privesc_exploit._check_pkexec_pwnkit()
        titles = [f.title for f in findings]
        assert any("cve-2021-4034" in t.lower() or "pwnkit" in t.lower() for t in titles)


class TestPrivescProofOfAccess:
    def test_proof_file_written_on_success(self, monkeypatch, tmp_path):
        from exploits import privesc_exploit
        import shutil
        import os

        monkeypatch.setattr(privesc_exploit, "_current_uid", lambda: 1000)
        monkeypatch.setattr(shutil, "which",
                            lambda name: f"/usr/bin/{name}" if name == "python3" else None)
        monkeypatch.setattr(privesc_exploit, "_is_suid",
                            lambda path: "python3" in path)

        written_paths = []

        def fake_write_proof():
            path = str(tmp_path / "SECTEST_PRIVESC_PROOF_test.txt")
            written_paths.append(path)
            with open(path, "w") as fh:
                fh.write("proof")

        monkeypatch.setattr(privesc_exploit, "_write_privesc_proof", fake_write_proof)

        def fake_run(argv, timeout=10):
            if "python3" in argv[0]:
                return "uid=0(root) gid=0(root)"
            return None
        monkeypatch.setattr(privesc_exploit, "_run", fake_run)

        target = MagicMock()
        target.kind = "local"
        target.local = True
        target.is_propagated = False
        target.pivot_targets = []
        result = privesc_exploit.run(target)

        assert result.exploited
        assert len(written_paths) >= 1
        assert os.path.exists(written_paths[0])


# ===========================================================================
# device_posture — ss port enum + ARP peer discovery (Request 2)
# ===========================================================================

class TestSsPortEnum:
    def test_ss_ports_union_with_tcp_connect(self, monkeypatch):
        from exploits import device_posture
        import os
        import socket as _socket

        monkeypatch.setattr(device_posture, "_ss_port_enum", lambda: [9200, 5432])
        monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        monkeypatch.setattr(os, "access", lambda p, m: False)
        # Patch create_connection to raise OSError (connection refused) on all ports
        monkeypatch.setattr(_socket, "create_connection",
                            lambda addr, timeout=None: (_ for _ in ()).throw(OSError("refused")))

        target = _Local()
        target.pivot_targets = []
        res = device_posture.run(target)

        pivot_ports = {p.get("port") for p in target.pivot_targets}
        finding_text = " ".join((f.title or "") + " " + (f.detail or "") for f in res.findings)
        assert 9200 in pivot_ports or "9200" in finding_text
        assert 5432 in pivot_ports or "5432" in finding_text

    def test_ss_port_enum_parses_ss_output(self, monkeypatch):
        from exploits import device_posture

        fake_ss_output = (
            "Netid State Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*\n"
            "tcp   LISTEN 0      128    0.0.0.0:8080        0.0.0.0:*\n"
            "tcp   LISTEN 0      50     0.0.0.0:9200        0.0.0.0:*\n"
        )

        def fake_run_tool(cmd, timeout=None):
            r = MagicMock()
            if "ss" in cmd:
                r.available = True
                r.stdout = fake_ss_output
            else:
                r.available = False
                r.stdout = ""
            return r

        monkeypatch.setattr(device_posture.toolrunner, "run_tool", fake_run_tool)
        monkeypatch.setattr(device_posture.toolrunner, "available", lambda b: b == "ss")

        ports = device_posture._ss_port_enum()
        assert 22 in ports
        assert 8080 in ports
        assert 9200 in ports


class TestArpPeerDiscovery:
    def test_arp_peers_added_to_pivot_targets(self, monkeypatch):
        from exploits import device_posture
        import os

        mock_arp_finding = device_posture.Finding(
            title="ARP peers discovered: 2 hosts visible in ARP table",
            severity="INFO",
            location="local",
            detail="Peers: 192.168.1.1, 192.168.1.100",
            evidence="arp -a output",
            category="discovery",
            tags=["arp", "lateral"],
        )
        monkeypatch.setattr(device_posture, "_arp_peer_scan",
                            lambda: ([mock_arp_finding], ["192.168.1.1", "192.168.1.100"]))
        monkeypatch.setattr(device_posture, "_check_privilege", lambda: [])
        monkeypatch.setattr(device_posture, "_check_restricted_shell", lambda: [])
        monkeypatch.setattr(device_posture, "_os_fingerprint", lambda: [])
        monkeypatch.setattr(device_posture, "_check_container", lambda: [])
        monkeypatch.setattr(device_posture, "_check_capabilities", lambda: [])
        monkeypatch.setattr(device_posture, "_local_service_scan", lambda: ([], []))
        monkeypatch.setattr(device_posture, "_check_wifi", lambda: [])
        monkeypatch.setattr(device_posture, "_check_bt_adapter", lambda: [])
        monkeypatch.setattr(device_posture, "_check_python", lambda: [])
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        monkeypatch.setattr(os, "access", lambda p, m: False)

        target = _Local()
        target.pivot_targets = []
        device_posture.run(target)

        peer_hosts = {p.get("host") for p in target.pivot_targets}
        assert "192.168.1.1" in peer_hosts
        assert "192.168.1.100" in peer_hosts

    def test_arp_peer_scan_parses_proc_arp(self, monkeypatch):
        from exploits import device_posture

        proc_arp_data = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n"
            "192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0\n"
            "0.0.0.0          0x0         0x0         00:00:00:00:00:00     *        eth0\n"
        )

        monkeypatch.setattr(device_posture.toolrunner, "available", lambda b: False)

        import builtins
        real_open = builtins.open

        def fake_open(path, *a, **k):
            if path == "/proc/net/arp":
                import io
                return io.StringIO(proc_arp_data)
            return real_open(path, *a, **k)

        monkeypatch.setattr(builtins, "open", fake_open)

        findings, peers = device_posture._arp_peer_scan()
        assert "192.168.1.1" in peers
        assert "192.168.1.50" in peers
        assert "0.0.0.0" not in peers


# ===========================================================================
# wifi_probe — gateway + subnet pivot (Request 2)
# ===========================================================================

class TestWifiGatewayPivot:
    def test_gateway_added_to_pivot_when_vulnerable_network(self, monkeypatch):
        networks = [{"ssid": "OpenNet", "bssid": "AA:BB:CC:DD:EE:FF",
                     "channel": "6", "signal": "-60", "security": "open", "wps": False}]
        monkeypatch.setattr(wifi_probe, "_discover_networks", lambda: (networks, True))
        monkeypatch.setattr(wifi_probe, "_get_default_gateway", lambda: "192.168.0.1")
        monkeypatch.setattr(wifi_probe, "_get_local_cidr", lambda: "192.168.0.0/24")

        target = _Local()
        target.pivot_targets = []
        res = wifi_probe.run(target)

        assert res.exploited is True
        pivot_hosts = [p.get("host") for p in target.pivot_targets]
        assert "192.168.0.1" in pivot_hosts

    def test_local_subnet_added_to_pivot_when_vulnerable_network(self, monkeypatch):
        networks = [{"ssid": "OpenNet", "bssid": "AA:BB:CC:DD:EE:FF",
                     "channel": "6", "signal": "-60", "security": "open", "wps": False}]
        monkeypatch.setattr(wifi_probe, "_discover_networks", lambda: (networks, True))
        monkeypatch.setattr(wifi_probe, "_get_default_gateway", lambda: "192.168.0.1")
        monkeypatch.setattr(wifi_probe, "_get_local_cidr", lambda: "192.168.0.0/24")

        target = _Local()
        target.pivot_targets = []
        wifi_probe.run(target)

        netrange_entries = [p for p in target.pivot_targets if p.get("kind") == "netrange"]
        assert any("192.168.0.0/24" in p.get("cidr", "") for p in netrange_entries)

    def test_no_pivot_when_no_vulnerable_network(self, monkeypatch):
        networks = [{"ssid": "SafeNet", "bssid": "DE:AD:BE:EF:00:01",
                     "channel": "6", "signal": "-50", "security": "WPA2", "wps": False}]
        monkeypatch.setattr(wifi_probe, "_discover_networks", lambda: (networks, True))
        monkeypatch.setattr(wifi_probe, "_get_default_gateway", lambda: "10.0.0.1")
        monkeypatch.setattr(wifi_probe, "_get_local_cidr", lambda: "10.0.0.0/24")

        target = _Local()
        target.pivot_targets = []
        res = wifi_probe.run(target)

        assert res.exploited is False
        assert len(target.pivot_targets) == 0


# ===========================================================================
# bluetooth_probe — GATT discovery + pivot targets (Request 2)
# ===========================================================================

class TestBluetoothGattAndPivot:
    def test_rfcomm_service_adds_pivot_target(self, monkeypatch):
        devices = [{"addr": "AA:BB:CC:DD:EE:FF", "name": "EmbeddedDevice", "source": "bluetoothctl"}]
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: True)
        monkeypatch.setattr(bluetooth_probe, "_scan_bluetoothctl", lambda: (True, devices))
        monkeypatch.setattr(bluetooth_probe, "_scan_hcitool", lambda: (False, []))
        monkeypatch.setattr(bluetooth_probe, "_device_info", lambda addr: {})
        monkeypatch.setattr(bluetooth_probe, "_sdp_browse",
                            lambda addr: [{"name": "Serial Port", "proto": "RFCOMM", "channel": "1"}])
        monkeypatch.setattr(bluetooth_probe, "_gatt_discover", lambda addr: [])

        target = _Local()
        target.pivot_targets = []
        bluetooth_probe.run(target)

        relay_types = [p.get("relay", {}).get("type") for p in target.pivot_targets]
        assert "bt-rfcomm" in relay_types

    def test_ble_uart_service_adds_pivot_target_high_severity(self, monkeypatch):
        devices = [{"addr": "11:22:33:44:55:66", "name": "BLESensor", "source": "bluetoothctl"}]
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: True)
        monkeypatch.setattr(bluetooth_probe, "_scan_bluetoothctl", lambda: (True, devices))
        monkeypatch.setattr(bluetooth_probe, "_scan_hcitool", lambda: (False, []))
        monkeypatch.setattr(bluetooth_probe, "_device_info", lambda addr: {})
        monkeypatch.setattr(bluetooth_probe, "_sdp_browse", lambda addr: [])
        monkeypatch.setattr(bluetooth_probe, "_gatt_discover",
                            lambda addr: [{"uuid": "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
                                           "handle": "0x0001", "name": "Nordic UART Service"}])

        target = _Local()
        target.pivot_targets = []
        res = bluetooth_probe.run(target)

        relay_types = [p.get("relay", {}).get("type") for p in target.pivot_targets]
        assert "ble-uart" in relay_types
        assert any(f.severity == "HIGH" for f in res.findings)

    def test_gatt_only_info_service_no_pivot(self, monkeypatch):
        devices = [{"addr": "AA:BB:CC:DD:EE:01", "name": "Fitband", "source": "bluetoothctl"}]
        monkeypatch.setattr(bluetooth_probe, "_adapter_present", lambda: True)
        monkeypatch.setattr(bluetooth_probe, "_scan_bluetoothctl", lambda: (True, devices))
        monkeypatch.setattr(bluetooth_probe, "_scan_hcitool", lambda: (False, []))
        monkeypatch.setattr(bluetooth_probe, "_device_info", lambda addr: {})
        monkeypatch.setattr(bluetooth_probe, "_sdp_browse", lambda addr: [])
        monkeypatch.setattr(bluetooth_probe, "_gatt_discover",
                            lambda addr: [
                                {"uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                                 "handle": "0x0001", "name": "Battery Service"},
                                {"uuid": "0000180a-0000-1000-8000-00805f9b34fb",
                                 "handle": "0x0010", "name": "Device Information"},
                            ])

        target = _Local()
        target.pivot_targets = []
        res = bluetooth_probe.run(target)

        relay_types = [p.get("relay", {}).get("type") for p in target.pivot_targets]
        assert "ble-uart" not in relay_types
        assert "bt-rfcomm" not in relay_types
        assert any("gatt" in f.title.lower() or "ble" in f.title.lower() for f in res.findings)
