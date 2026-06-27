"""Tests for the new active modules: path-probe and jwt-attacker."""
from exploits import jwt_attacker, path_probe


# --- path-probe ------------------------------------------------------------
def test_path_probe_finds_sensitive_paths(app_server, fake_target):
    t = fake_target(kind="url", url=app_server, raw=app_server)
    res = path_probe.run(t)
    assert res.exploited is True
    titles = " ".join(f.title for f in res.findings)
    assert "heap dump" in titles or "/env" in titles
    assert any("git/config" in f.location or ".git" in f.title for f in res.findings)


def test_path_probe_unreachable_is_skip(fake_target):
    t = fake_target(kind="url", url="http://127.0.0.1:1", raw="x")
    res = path_probe.run(t)
    assert res.exploited is False
    assert res.error


# --- jwt-attacker ----------------------------------------------------------
def test_jwt_attacker_algnone_bypass(app_server, fake_target):
    t = fake_target(kind="url", url=app_server, raw=app_server)
    res = jwt_attacker.run(t)
    assert res.exploited is True
    assert any("bypass accepted" in f.title for f in res.findings)


def test_jwt_attacker_unreachable_is_skip(fake_target):
    t = fake_target(kind="url", url="http://127.0.0.1:1", raw="x")
    res = jwt_attacker.run(t)
    assert res.exploited is False
    assert res.error


def test_crack_recovers_weak_secret():
    claims = {"sub": "u", "role": "USER"}
    token = jwt_attacker._encode({"alg": "HS256", "typ": "JWT"}, claims, secret="secret")
    assert jwt_attacker._crack_hs256(token, jwt_attacker._SECRET_WORDS) == "secret"


def test_crack_returns_none_for_strong_secret():
    claims = {"sub": "u"}
    token = jwt_attacker._encode(
        {"alg": "HS256", "typ": "JWT"}, claims,
        secret="a-very-long-and-unguessable-random-secret-value-9f3b",
    )
    assert jwt_attacker._crack_hs256(token, jwt_attacker._SECRET_WORDS) is None


def test_jwt_attacker_cracks_weak_supplied_token(app_server, fake_target):
    token = jwt_attacker._encode({"alg": "HS256", "typ": "JWT"}, {"sub": "u"}, secret="secret")
    t = fake_target(kind="url", url=app_server, jwt=token, raw=app_server)
    res = jwt_attacker.run(t)
    assert res.exploited is True
    assert any("secret recovered" in f.title for f in res.findings)


def test_algnone_encoding_is_unsigned():
    token = jwt_attacker._encode({"alg": "none", "typ": "JWT"}, {"sub": "x"}, secret=None)
    assert token.endswith(".")
    assert token.count(".") == 2
