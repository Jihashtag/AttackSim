"""Tests for "use the accessible device to broaden the audit".

When access to a device is PROVEN, the toolkit derives the device's subnet, sweeps it for
live hosts and re-runs the host:port modules against each in-scope peer. A pre-scan
confirmation prompt also gates the very first scan. All offline (no network).

Covers:
* ``access_prover._publish_subnet_pivot`` — queues the foothold's subnet, skips
  hostnames / loopback / link-local, and de-duplicates a /24.
* ``main._expand_subnet_spec`` — scope-filters candidates, runs a (monkeypatched) liveness
  sweep, and returns one host:port spec per live peer.
* ``main._fanout_pivots`` — a published subnet pivot is expanded and the peers probed.
* ``main._confirm_scan`` — interactive accept/decline, ``--yes`` skip, non-interactive
  proceed, and static targets never prompt.
"""
from __future__ import annotations

import time
import types

import main as cli
import targets as targetmod
from exploits import access_prover, host_sweep
from sandbox import scope_guard


def _stub_target(**kw):
    t = types.SimpleNamespace(pivot_targets=[])
    for k, v in kw.items():
        setattr(t, k, v)
    return t


def _args(**kw):
    base = {"assume_yes": False, "only": None}
    base.update(kw)
    return types.SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# access_prover._publish_subnet_pivot
# ---------------------------------------------------------------------------
def test_publish_subnet_pivot_queues_cidr():
    t = _stub_target()
    cidr = access_prover._publish_subnet_pivot(t, "10.0.0.5", 2375)
    assert cidr == "10.0.0.0/24"
    assert len(t.pivot_targets) == 1
    spec = t.pivot_targets[0]
    assert spec["kind"] == "netrange"
    assert spec["cidr"] == "10.0.0.0/24"
    assert spec["via"] == "proof:10.0.0.5:2375"
    assert spec["ports"], "the subnet pivot must carry probe ports"


def test_publish_subnet_pivot_skips_non_routable():
    t = _stub_target()
    assert access_prover._publish_subnet_pivot(t, "example.com") is None     # hostname
    assert access_prover._publish_subnet_pivot(t, "127.0.0.1") is None        # loopback
    assert access_prover._publish_subnet_pivot(t, "169.254.10.1") is None     # link-local
    assert access_prover._publish_subnet_pivot(t, "") is None
    assert t.pivot_targets == []


def test_publish_subnet_pivot_dedups_same_subnet():
    t = _stub_target()
    assert access_prover._publish_subnet_pivot(t, "10.0.0.5") == "10.0.0.0/24"
    # A second proof on a different host of the SAME /24 must not queue it twice.
    assert access_prover._publish_subnet_pivot(t, "10.0.0.9") == "10.0.0.0/24"
    assert len(t.pivot_targets) == 1


# ---------------------------------------------------------------------------
# main._expand_subnet_spec
# ---------------------------------------------------------------------------
def test_expand_subnet_spec_sweeps_in_scope_live_hosts(monkeypatch):
    seen = {}

    def fake_sweep(hosts, ports=None, *, timeout=None, deadline=None):
        seen["hosts"] = list(hosts)
        seen["ports"] = ports
        # Pretend the first two candidates are alive.
        return [(hosts[0], 80), (hosts[1], 443)]

    monkeypatch.setattr(host_sweep, "discover_live_hosts", fake_sweep)
    guard = scope_guard.ScopeGuard.from_specs(["10.0.0.0/24"], intensity="intrusive")
    spec = {"kind": "netrange", "cidr": "10.0.0.0/24", "ports": [80, 443],
            "via": "proof:10.0.0.5"}
    out = cli._expand_subnet_spec(spec, guard, deadline=time.monotonic() + 60)
    assert len(out) == 2
    assert all(c["kind"] == "hostport" for c in out)
    assert all(c["via"] == "proof:10.0.0.5" for c in out)
    # The sweep only ever saw in-scope hosts.
    assert all(h.startswith("10.0.0.") for h in seen["hosts"])


def test_expand_subnet_spec_drops_out_of_scope_without_sweeping(monkeypatch):
    called = {"n": 0}

    def fake_sweep(hosts, ports=None, *, timeout=None, deadline=None):
        called["n"] += 1
        return [(hosts[0], 80)]

    monkeypatch.setattr(host_sweep, "discover_live_hosts", fake_sweep)
    # Scope authorises a DIFFERENT subnet, so every 10.0.0.x candidate is out of scope.
    guard = scope_guard.ScopeGuard.from_specs(["192.168.0.0/24"], intensity="intrusive")
    spec = {"kind": "netrange", "cidr": "10.0.0.0/24", "ports": [80], "via": "proof:10.0.0.5"}
    out = cli._expand_subnet_spec(spec, guard, deadline=time.monotonic() + 60)
    assert out == []
    assert called["n"] == 0, "an out-of-scope subnet must never be swept"


# ---------------------------------------------------------------------------
# main._fanout_pivots — end-to-end subnet broadening
# ---------------------------------------------------------------------------
def test_fanout_pivots_expands_proven_subnet(monkeypatch):
    # One live peer in the foothold's subnet.
    monkeypatch.setattr(host_sweep, "discover_live_hosts",
                        lambda hosts, ports=None, *, timeout=None, deadline=None: [("10.0.0.20", 80)])
    probed = []

    def fake_run_modules(mods, target, jobs=1, resume=None):
        probed.append(target.host)
        return []

    monkeypatch.setattr(cli, "_run_modules", fake_run_modules)
    # A scope that authorises the whole subnet at intrusive intensity.
    guard = scope_guard.ScopeGuard.from_specs(["10.0.0.0/24"], intensity="intrusive")
    target = _stub_target(
        kind=targetmod.HOSTPORT, host="10.0.0.5", port=2375, ports=[2375],
        scope_guard=guard, intensity="proof", pivot_depth=0,
        pivot_targets=[{"kind": "netrange", "cidr": "10.0.0.0/24",
                        "ports": [80, 443], "via": "proof:10.0.0.5"}])
    out = cli._fanout_pivots(target, _args(), jobs=1)
    assert "10.0.0.20" in probed, "the live subnet peer must be probed"
    assert isinstance(out, list)


# ---------------------------------------------------------------------------
# main._confirm_scan — the pre-scan safety gate
# ---------------------------------------------------------------------------
def _live_target():
    t = _stub_target(kind=targetmod.HOSTPORT)
    t.describe = lambda: "hostport:10.0.0.5:2375"
    return t


def test_confirm_scan_interactive_accept():
    ok = cli._confirm_scan([_live_target()], _args(), None, "proof",
                          isatty=True, input_fn=lambda _p: "yes")
    assert ok is True


def test_confirm_scan_interactive_decline():
    ok = cli._confirm_scan([_live_target()], _args(), None, "proof",
                          isatty=True, input_fn=lambda _p: "n")
    assert ok is False


def test_confirm_scan_yes_flag_skips_prompt():
    def _no_prompt(_p):
        raise AssertionError("must not prompt when --yes is given")

    ok = cli._confirm_scan([_live_target()], _args(assume_yes=True), None, "proof",
                          isatty=True, input_fn=_no_prompt)
    assert ok is True


def test_confirm_scan_non_interactive_refuses_without_yes():
    # Fail-closed: a non-interactive shell must pass --yes to scan a live target.
    ok = cli._confirm_scan([_live_target()], _args(), None, "active", isatty=False)
    assert ok is False


def test_confirm_scan_non_interactive_proceeds_with_yes():
    ok = cli._confirm_scan([_live_target()], _args(assume_yes=True), None, "active",
                          isatty=False)
    assert ok is True


def test_confirm_scan_static_target_never_prompts():
    t = _stub_target(kind=targetmod.REPO)
    t.describe = lambda: "repo:/tmp/x"

    def _no_prompt(_p):
        raise AssertionError("a repo target must not be prompted")

    ok = cli._confirm_scan([t], _args(), None, "active", isatty=True, input_fn=_no_prompt)
    assert ok is True
