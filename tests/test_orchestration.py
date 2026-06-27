"""Tests for run orchestration: parallel module execution, resume state, scan profiles."""
from __future__ import annotations

import os
import tempfile
import types

import config
import main
from exploits.base import ExploitResult
from report import state


def _mod(name, value=None):
    def run(target):
        return ExploitResult(name=name, description="", exploited=False,
                             attacker_value=value or name)
    return types.SimpleNamespace(NAME=name, __name__=name, run=run)


def _target(label="t1"):
    return types.SimpleNamespace(describe=lambda: label, kind="hostport")


def test_run_modules_preserves_order_when_parallel():
    mods = [_mod("a"), _mod("b"), _mod("c"), _mod("d")]
    results = main._run_modules(mods, _target(), jobs=4)
    assert [r.name for r in results] == ["a", "b", "c", "d"]


def test_run_modules_sequential_matches_parallel():
    mods = [_mod("x"), _mod("y"), _mod("z")]
    seq = main._run_modules(mods, _target(), jobs=1)
    par = main._run_modules(mods, _target(), jobs=3)
    assert [r.name for r in seq] == [r.name for r in par] == ["x", "y", "z"]


def test_resume_skips_completed_modules():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "resume.json")
        rs = state.ResumeState.load(path)
        mods = [_mod("a"), _mod("b")]
        first = main._run_modules(mods, _target("host1"), jobs=2, resume=rs)
        assert {r.name for r in first} == {"a", "b"}
        assert rs.count == 2
        # A second run with the same state skips everything already done.
        second = main._run_modules(mods, _target("host1"), jobs=2, resume=rs)
        assert second == []
        # A different target label is independent.
        third = main._run_modules(mods, _target("host2"), jobs=2, resume=rs)
        assert {r.name for r in third} == {"a", "b"}


def test_resume_state_persists_to_disk():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.json")
        rs = state.ResumeState.load(path)
        rs.mark("targetA", "modX")
        assert os.path.exists(path)
        reloaded = state.ResumeState.load(path)
        assert reloaded.is_done("targetA", "modX")
        assert not reloaded.is_done("targetA", "modY")


def test_scan_profiles_defined():
    profiles = getattr(config, "SCAN_PROFILES", {})
    assert set(profiles) == {"quick", "standard", "deep", "stealth"}
    for preset in profiles.values():
        assert "intensity" in preset and "jobs" in preset


def test_module_crash_is_isolated_in_run_modules():
    def boom(target):
        raise RuntimeError("kaboom")
    bad = types.SimpleNamespace(NAME="bad", __name__="bad", run=boom)
    results = main._run_modules([_mod("ok"), bad], _target(), jobs=2)
    names = {r.name for r in results}
    assert "ok" in names and "bad" in names
    assert any(r.error and "kaboom" in r.error for r in results if r.name == "bad")
