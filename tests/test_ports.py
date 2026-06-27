"""Tests for port-spec parsing and the safety cap."""
import pytest

from targets import model


def test_single_port():
    assert model.parse_ports("22") == [22]


def test_range_expands_inclusive():
    assert model.parse_ports("80-83") == [80, 81, 82, 83]


def test_reversed_range_is_normalised():
    assert model.parse_ports("83-80") == [80, 81, 82, 83]


def test_comma_list_dedupes_and_sorts():
    assert model.parse_ports("443,80,443,22") == [22, 80, 443]


def test_mixed_list_and_range():
    assert model.parse_ports("22,8000-8002") == [22, 8000, 8001, 8002]


def test_invalid_spec_raises():
    with pytest.raises(model.TargetError):
        model.parse_ports("not-ports")


def test_out_of_range_filtered_then_empty_raises():
    with pytest.raises(model.TargetError):
        model.parse_ports("70000")


def test_cap_enforced():
    with pytest.raises(model.TargetError):
        model.parse_ports(f"1-{model.MAX_PORTS + 100}")
