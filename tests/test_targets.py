"""Tests for target resolution precedence and auth-header construction."""
import os

import pytest

from targets import model


def test_repo_path(tmp_path):
    t = model.resolve(repo=str(tmp_path))
    assert t.kind == model.REPO
    assert t.root == os.path.abspath(str(tmp_path))


def test_basic_creds_take_precedence_over_url():
    t = model.resolve(username="admin", password="pw", url="https://app.example")
    assert t.kind == model.CREDS
    assert t.cred_kind == "basic"
    assert t.url == "https://app.example"


def test_url_is_url_target():
    t = model.resolve(url="https://api.example")
    assert t.kind == model.URL


def test_token_without_url_is_creds():
    t = model.resolve(jwt="eyJ.a.b")
    assert t.kind == model.CREDS
    assert t.cred_kind == "bearer"


def test_host_port_with_ports_flag():
    t = model.resolve(host_port="10.0.0.1", ports="22,80")
    assert t.kind == model.HOSTPORT
    assert t.host == "10.0.0.1"
    assert t.ports == [22, 80]


def test_positional_hostports_range():
    t = model.resolve(positional="10.0.0.1:1-3")
    assert t.kind == model.HOSTPORT
    assert t.ports == [1, 2, 3]


def test_positional_dir_is_repo(tmp_path):
    t = model.resolve(positional=str(tmp_path))
    assert t.kind == model.REPO


def test_unintelligible_target_raises():
    with pytest.raises(model.TargetError):
        model.resolve(positional="!!!not-a-target!!!")


def test_default_repo_fallback(tmp_path):
    t = model.resolve(default_repo=str(tmp_path))
    assert t.kind == model.REPO


def test_jwt_header_default_scheme():
    t = model.resolve(url="https://x", jwt="TKN")
    assert t.jwt_header() == ("Authorization", "Bearer TKN")


def test_jwt_header_custom_name_and_scheme():
    t = model.resolve(url="https://x", jwt="TKN", auth_header="X-Auth", auth_scheme="")
    assert t.jwt_header() == ("X-Auth", "TKN")


def test_api_key_header_default():
    t = model.resolve(url="https://x", api_key="KEY")
    assert t.api_key_header() == ("X-API-Key", "KEY")


def test_auth_headers_combined():
    t = model.resolve(url="https://x", jwt="A", api_key="B", auth_header=None)
    headers = t.auth_headers()
    assert headers["Authorization"] == "Bearer A"
    assert headers["X-API-Key"] == "B"
