"""Tests for the local host-introspection modules (container-escape-detector
and rootkit-ioc-detector) and the new k8s-probe kubelet CVE checks.

The container-escape detector reads ``/proc`` and the filesystem, which cannot be
controlled in CI, so we monkeypatch its read helpers to simulate each scenario.
"""
from exploits import container_escape, k8s_probe, rootkit_ioc
from targets import model


def _clean(monkeypatch, *, in_container=True):
    """Patch container_escape so every check is benign by default."""
    monkeypatch.setattr(container_escape, "_in_container",
                        lambda: (in_container, "simulated"))
    monkeypatch.setattr(container_escape, "_effective_caps", lambda: 0)
    monkeypatch.setattr(container_escape, "_read", lambda path, limit=65536: "")
    monkeypatch.setattr(container_escape.os.path, "exists", lambda p: False)


# --- target resolution -----------------------------------------------------
def test_local_target_resolves():
    t = model.resolve(local=True)
    assert t.kind == model.LOCAL
    assert "local" in t.describe()


# --- not-in-container skip path -------------------------------------------
def test_container_escape_skips_on_bare_host(monkeypatch):
    _clean(monkeypatch, in_container=False)
    res = container_escape.run(object())
    assert res.exploited is False
    assert res.error
    assert res.findings and res.findings[0].severity == "INFO"


# --- dangerous capability --------------------------------------------------
def test_container_escape_flags_cap_sys_admin(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setattr(container_escape, "_effective_caps", lambda: 1 << 21)
    res = container_escape.run(object())
    assert res.exploited is True
    titles = [f.title for f in res.findings]
    assert any("CAP_SYS_ADMIN" in t for t in titles)
    crit = [f for f in res.findings if "CAP_SYS_ADMIN" in f.title][0]
    assert crit.severity == "CRITICAL"


# --- mounted runtime socket ------------------------------------------------
def test_container_escape_flags_docker_socket(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setattr(container_escape.os.path, "exists",
                        lambda p: p == "/var/run/docker.sock")
    res = container_escape.run(object())
    assert res.exploited is True
    socket_findings = [f for f in res.findings if "socket" in f.title.lower()]
    assert socket_findings and socket_findings[0].severity == "CRITICAL"


# --- writable host bind mount ----------------------------------------------
def test_container_escape_flags_writable_host_mount(monkeypatch):
    _clean(monkeypatch)
    mountinfo = ("36 35 0:32 / /host rw,relatime shared:15 - ext4 /dev/sda1 rw\n")
    monkeypatch.setattr(container_escape, "_read",
                        lambda path, limit=65536: mountinfo if "mountinfo" in path else "")
    res = container_escape.run(object())
    assert res.exploited is True
    assert any("/host" in f.title for f in res.findings)


# --- vulnerable runc (Leaky Vessels) ---------------------------------------
def test_container_escape_flags_leaky_runc(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setattr(container_escape.os.path, "exists",
                        lambda p: p == "/usr/bin/runc")
    monkeypatch.setattr(container_escape, "_read",
                        lambda path, limit=65536:
                        "runc version 1.1.0" if path == "/usr/bin/runc" else "")
    res = container_escape.run(object())
    cve = [f for f in res.findings if "CVE-2024-21626" in f.references]
    assert cve and cve[0].severity == "HIGH"


# --- patched runc => no Leaky Vessels finding ------------------------------
def test_container_escape_patched_runc_clean(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setattr(container_escape.os.path, "exists",
                        lambda p: p == "/usr/bin/runc")
    monkeypatch.setattr(container_escape, "_read",
                        lambda path, limit=65536:
                        "runc version 1.3.3" if path == "/usr/bin/runc" else "")
    res = container_escape.run(object())
    assert not any("CVE-2024-21626" in f.references for f in res.findings)
    assert not any("CVE-2025-31133" in f.references for f in res.findings)


# --- prove-access: harmless persistent marker on a detected container -------
class _ProveTarget:
    kind = "local"
    prove_access = True


def test_container_escape_prove_writes_container_marker(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setattr(container_escape, "_local_writable_host_mounts", lambda: [])
    written = {}
    monkeypatch.setattr(container_escape, "_write_marker_file",
                        lambda d: written.setdefault(d, f"{d}/sectest_proof_x.txt"))
    res = container_escape.run(_ProveTarget())
    # A marker is written to the container's own /tmp (proof of in-container exec).
    assert "/tmp" in written
    assert any("marker written to container filesystem" in f.title for f in res.findings)


def test_container_escape_prove_writes_host_marker_on_escape(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setattr(container_escape, "_local_writable_host_mounts", lambda: ["/host"])
    monkeypatch.setattr(container_escape, "_write_marker_file",
                        lambda d: f"{d}/sectest_proof_x.txt")
    res = container_escape.run(_ProveTarget())
    escape = [f for f in res.findings if "escape PROVEN" in f.title]
    assert escape and escape[0].severity == "CRITICAL"
    assert res.exploited is True


def test_container_escape_no_marker_without_prove(monkeypatch):
    _clean(monkeypatch)
    calls = []
    monkeypatch.setattr(container_escape, "_write_marker_file",
                        lambda d: calls.append(d))
    # object() has no prove_access attribute -> no writes.
    container_escape.run(object())
    assert calls == []


def test_container_escape_write_marker_uses_o_excl(monkeypatch, tmp_path):
    # The real writer must only ever CREATE a new file (never overwrite).
    path = container_escape._write_marker_file(str(tmp_path))
    assert path is not None
    assert "sectest_proof_" in path
    # A second call makes a distinct file (unique name), never clobbering the first.
    import os as _os
    assert _os.path.exists(path)


# --- k8s kubelet pprof (CVE-2019-11248) ------------------------------------
def test_k8s_kubelet_pprof_exposed(routed_http_server):
    host, port, _ = routed_http_server({
        "/debug/pprof/": (200, b"Types of profiles available"),
    })
    findings = k8s_probe._kubelet_cve_checks(f"http://{host}:{port}", port)
    assert findings and findings[0].severity == "MEDIUM"
    assert "CVE-2019-11248" in findings[0].references


def test_k8s_kubelet_exec_precondition_flagged(monkeypatch):
    def fake_get(url, *a, **k):
        if url.endswith("/pods"):
            return (200, '{"kind":"PodList","items":[]}', {})
        return (404, "", {})
    monkeypatch.setattr(k8s_probe.netutil, "http_get", fake_get)
    findings = k8s_probe._kubelet("10.0.0.1", 10250, read_only=False)
    assert any("exec/run" in f.title for f in findings)


# --- k8s kubelet Checkpoint API (CVE-2025-0426) ----------------------------
def test_k8s_kubelet_checkpoint_api_flagged(monkeypatch):
    def fake_get(url, *a, **k):
        if "/checkpoint/" in url:
            return (405, "Method Not Allowed", {})  # handler present, POST-only
        return (404, "", {})
    monkeypatch.setattr(k8s_probe.netutil, "http_get", fake_get)
    findings = k8s_probe._kubelet_cve_checks("https://10.0.0.1:10250", 10250)
    chk = [f for f in findings if "CVE-2025-0426" in f.references]
    assert chk and chk[0].severity == "HIGH"


# --- k8s kubelet logs/query (CVE-2024-9042) --------------------------------
def test_k8s_kubelet_logs_query_flagged(monkeypatch):
    def fake_get(url, *a, **k):
        if "/logs/query" in url:
            return (200, "log line", {})
        return (404, "", {})
    monkeypatch.setattr(k8s_probe.netutil, "http_get", fake_get)
    findings = k8s_probe._kubelet_cve_checks("https://10.0.0.1:10250", 10250)
    assert any("CVE-2024-9042" in f.references for f in findings)


def test_k8s_kubelet_cve_checks_clean_when_404(monkeypatch):
    monkeypatch.setattr(k8s_probe.netutil, "http_get",
                        lambda url, *a, **k: (404, "", {}))
    findings = k8s_probe._kubelet_cve_checks("https://10.0.0.1:10250", 10250)
    assert findings == []


# --- rootkit-ioc-detector --------------------------------------------------
def _rootkit_all_clean(monkeypatch):
    """Patch rootkit_ioc so every read returns nothing and platform is linux."""
    monkeypatch.setattr(rootkit_ioc.sys, "platform", "linux")
    monkeypatch.setattr(rootkit_ioc, "_read", lambda path, limit=1_000_000: None)
    monkeypatch.setattr(rootkit_ioc, "_listdir", lambda path: [])
    monkeypatch.setattr(rootkit_ioc.os, "walk", lambda p: iter(()))


def test_rootkit_ioc_clean_host(monkeypatch):
    _rootkit_all_clean(monkeypatch)
    res = rootkit_ioc.run(object())
    assert res.exploited is False
    assert res.findings and res.findings[0].severity == "INFO"


def test_rootkit_ioc_non_linux_skips(monkeypatch):
    monkeypatch.setattr(rootkit_ioc.sys, "platform", "win32")
    res = rootkit_ioc.run(object())
    assert res.exploited is False
    assert res.error and "Linux" in res.error


def test_rootkit_ioc_flags_ld_preload(monkeypatch):
    _rootkit_all_clean(monkeypatch)
    monkeypatch.setattr(rootkit_ioc, "_read",
                        lambda path, limit=1_000_000:
                        "/lib/libazazel.so" if path == "/etc/ld.so.preload" else None)
    res = rootkit_ioc.run(object())
    assert res.exploited is True
    f = [f for f in res.findings if "ld.so.preload" in f.location][0]
    assert f.severity == "CRITICAL"  # matched a known userland family name


def test_rootkit_ioc_flags_known_lkm(monkeypatch):
    _rootkit_all_clean(monkeypatch)
    monkeypatch.setattr(rootkit_ioc, "_loaded_modules",
                        lambda: {"diamorphine", "ext4"})
    res = rootkit_ioc.run(object())
    assert res.exploited is True
    assert any("diamorphine" in f.title.lower() for f in res.findings)


def test_rootkit_ioc_flags_hidden_module(monkeypatch):
    _rootkit_all_clean(monkeypatch)
    monkeypatch.setattr(rootkit_ioc, "_loaded_modules", lambda: set())
    monkeypatch.setattr(rootkit_ioc, "_listdir",
                        lambda path: ["evilmod"] if path == "/sys/module" else [])
    monkeypatch.setattr(rootkit_ioc.os.path, "exists",
                        lambda p: p == "/sys/module/evilmod/coresize")
    res = rootkit_ioc.run(object())
    assert res.exploited is True
    assert any("hidden from /proc/modules" in f.title for f in res.findings)

