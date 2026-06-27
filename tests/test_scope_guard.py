"""Tests for the intensity-tier + scope-allow-list governor (sandbox/scope_guard.py)."""
from __future__ import annotations

import pytest

from sandbox import scope_guard as sg
from exploits import registry


# --------------------------------------------------------------------- intensity ladder
def test_rank_and_normalise():
    assert sg.rank("detective") < sg.rank("active") < sg.rank("intrusive")
    assert sg.normalise("INTRUSIVE") == "intrusive"
    assert sg.normalise("bogus") == "detective"


def test_allows_linear_tiers():
    # an intrusive run includes detective+active+intrusive modules
    assert sg.allows("intrusive", "detective")
    assert sg.allows("intrusive", "active")
    assert sg.allows("intrusive", "intrusive")
    # an active run does NOT include intrusive modules
    assert not sg.allows("active", "intrusive")
    # a detective run includes only detective
    assert sg.allows("detective", "detective")
    assert not sg.allows("detective", "active")


def test_allows_peaks_are_opt_in():
    # proof modules run only under a proof run; fuzz only under fuzz
    assert sg.allows("proof", "proof")
    assert not sg.allows("intrusive", "proof")
    assert sg.allows("fuzz", "fuzz")
    assert not sg.allows("intrusive", "fuzz")
    assert not sg.allows("proof", "fuzz")
    # a peak run still includes the base reconnaissance ladder up to intrusive
    assert sg.allows("proof", "detective")
    assert sg.allows("proof", "active")
    assert sg.allows("proof", "intrusive")
    assert sg.allows("fuzz", "intrusive")


# --------------------------------------------------------------------- scope matching
def test_from_specs_classifies_tokens():
    g = sg.ScopeGuard.from_specs(["10.0.0.0/24", ".example.com", "192.168.1.5"],
                                 intensity="intrusive")
    assert g.in_scope("10.0.0.7")
    assert g.in_scope("https://api.example.com/path")
    assert g.in_scope("192.168.1.5:8443")
    assert not g.in_scope("172.16.0.1")
    assert not g.in_scope("evil.test")


def test_bare_hostname_matches_exact_and_subdomain():
    g = sg.ScopeGuard.from_specs(["example.com"], intensity="intrusive")
    assert g.in_scope("example.com")
    assert g.in_scope("api.example.com")
    assert not g.in_scope("notexample.com")


def test_empty_scope_allows_everything_for_low_intensity():
    g = sg.ScopeGuard.from_specs([], intensity="active")
    assert g.in_scope("anything.test")
    ok, _ = g.authorize("anything.test")
    assert ok  # active is below the scope-enforcement threshold


def test_requires_scope_and_authorize_allows_target_derived():
    """Under the new v2 scope model, empty scope at intrusive+ is allowed (target-derived)."""
    g = sg.ScopeGuard.from_specs([], intensity="intrusive")
    assert g.requires_scope  # signals confirmation needed
    assert g.empty
    ok, reason = g.authorize("10.0.0.1")
    assert ok
    assert "target-derived" in reason.lower()


def test_authorize_in_and_out_of_scope():
    g = sg.ScopeGuard.from_specs(["10.0.0.0/30"], intensity="intrusive")
    ok, _ = g.authorize("10.0.0.1")
    assert ok
    ok, reason = g.authorize("10.0.0.99")
    assert not ok
    assert "not in the scope" in reason


def test_host_extraction_from_url_and_hostport():
    g = sg.ScopeGuard.from_specs(["10.0.0.5"], intensity="intrusive")
    assert g.in_scope("http://user:pw@10.0.0.5:8080/x")
    assert g.in_scope("10.0.0.5:443")


# --------------------------------------------------------------------- registry filter
def test_registry_intensity_filter_hides_proof_by_default():
    active = {registry.name_of(m) for m in registry.modules_for("hostport", "active")}
    assert "access-prover" not in active     # proof tier, hidden at active
    proof = {registry.name_of(m) for m in registry.modules_for("hostport", "proof")}
    assert "access-prover" in proof


def test_registry_no_intensity_arg_is_unfiltered():
    # backward-compatible: omitting intensity returns all supporting modules
    names = {registry.name_of(m) for m in registry.modules_for("hostport")}
    assert "access-prover" in names


def test_catalogue_has_intensity():
    for row in registry.catalogue():
        assert row.get("intensity")
