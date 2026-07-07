"""Tests for the login layer: PBKDF2, HKDF directional keys, replay, lockout, timestamps."""

from __future__ import annotations

import time

import pytest
from Crypto.Hash import SHA256

from conftest import FakeSocket, make_user
from siftprotocols.siftlogin import LoginGuard, SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftmtp import SiFT_MTP


def _login(mtp=None):
    return SiFT_LOGIN(mtp or SiFT_MTP(FakeSocket(), role="server"))


def test_check_password_accepts_correct_and_rejects_wrong():
    lp = _login()
    user = make_user("alice", "correct-horse")
    assert lp.check_password("correct-horse", user) is True
    assert lp.check_password("wrong", user) is False


def test_directional_keys_deterministic_and_distinct():
    cr, sr = b"c" * 16, b"s" * 16
    req_hash = SHA256.new(b"req").digest()
    k1 = SiFT_LOGIN._derive_keys(cr, sr, req_hash)
    k2 = SiFT_LOGIN._derive_keys(cr, sr, req_hash)
    assert k1 == k2                      # deterministic from the same inputs
    assert k1[0] != k1[1]                # c2s and s2c differ
    # Different transcript -> different keys.
    k3 = SiFT_LOGIN._derive_keys(cr, sr, SHA256.new(b"other").digest())
    assert k3 != k1


def test_timestamp_window():
    lp = _login()
    lp.validate_timestamp(str(time.time_ns()))  # now: OK
    with pytest.raises(SiFT_LOGIN_Error, match="Timestamp"):
        lp.validate_timestamp(str(time.time_ns() - 10 * 10**9))  # 10s old
    with pytest.raises(SiFT_LOGIN_Error, match="Malformed"):
        lp.validate_timestamp("not-a-number")


def test_login_req_res_serialisation_roundtrip():
    lp = _login()
    req = {"timestamp": "123", "username": "alice", "password": "pw", "client_random": "ab" * 16}
    assert lp.parse_login_req(lp.build_login_req(req)) == req
    res_hash = SHA256.new(b"x").digest()
    res = {"request_hash": res_hash, "server_random": b"r" * 16}
    parsed = lp.parse_login_res(lp.build_login_res(res))
    assert parsed["request_hash"] == res_hash and parsed["server_random"] == b"r" * 16


def test_replay_cache_rejects_duplicate():
    guard = LoginGuard(replay_window_s=5)
    h = SHA256.new(b"same request").digest()
    guard.check_not_replay(h)  # first time: fine
    with pytest.raises(SiFT_LOGIN_Error, match="replay"):
        guard.check_not_replay(h)


def test_brute_force_lockout():
    guard = LoginGuard(max_failures=3, lockout_s=60)
    for _ in range(3):
        guard.assert_not_locked("mallory")   # not locked yet
        guard.record_failure("mallory")
    with pytest.raises(SiFT_LOGIN_Error, match="locked"):
        guard.assert_not_locked("mallory")   # now locked
    # A successful login clears the state.
    guard.record_success("mallory")
    guard.assert_not_locked("mallory")


def test_full_login_over_loopback(loopback):
    session = loopback()
    session.login("alice", "aaa")
    assert session.logged_in_user == "alice"


def test_bad_password_is_rejected(loopback):
    session = loopback()
    with pytest.raises(Exception):
        session.login("alice", "WRONG")
    # give the server thread a moment to record the failure event
    time.sleep(0.2)
    events = [e["event"] for e in session.monitor.events()]
    assert "login_failure" in events
