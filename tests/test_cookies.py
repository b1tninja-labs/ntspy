"""RFC 8915 sec. 6 suggested cookie format."""

from __future__ import annotations

import pytest

from ntspy.auth import Negotiated
from ntspy.cookies import CookieError, ServerState, mint, validate

KEYS = Negotiated(15, bytes(range(32)), bytes(range(32, 64)))


def test_mint_then_validate_recovers_the_negotiated_keys():
    state = ServerState.new()
    got = validate(mint(state, KEYS), state)
    assert got == KEYS
    assert got.s2c_key == KEYS.s2c_key
    assert got.c2s_key == KEYS.c2s_key


def test_cookie_layout_is_id_nonce_ciphertext():
    state = ServerState.new(key_id=b"IDID")
    cookie = mint(state, KEYS, nonce=b"N" * 16)
    assert cookie[:4] == b"IDID"
    assert cookie[4:20] == b"N" * 16
    assert len(cookie) == 4 + 16 + 16 + 2 + 64


def test_cookies_are_unlinkable_by_default():
    state = ServerState.new()
    assert mint(state, KEYS) != mint(state, KEYS)


def test_unknown_or_erased_key_is_refused():
    state = ServerState.new()
    cookie = mint(state, KEYS)
    with pytest.raises(CookieError):
        validate(cookie, ServerState.new())
    state.rotate()
    state.erase(cookie[:4])
    with pytest.raises(CookieError):
        validate(cookie, state)


def test_old_cookie_still_validates_after_rotation_until_erased():
    state = ServerState.new()
    old = mint(state, KEYS)
    state.rotate()
    assert validate(old, state) == KEYS
    assert validate(mint(state, KEYS), state) == KEYS


@pytest.mark.parametrize("at", [0, 5, 25, 60])
def test_tampered_cookie_is_refused(at):
    state = ServerState.new()
    cookie = bytearray(mint(state, KEYS))
    cookie[at] ^= 0x80
    with pytest.raises(CookieError):
        validate(bytes(cookie), state)


@pytest.mark.parametrize("size", [0, 4, 20, 35])
def test_truncated_cookie_is_refused(size):
    state = ServerState.new()
    with pytest.raises(CookieError):
        validate(mint(state, KEYS)[:size], state)


def test_cannot_erase_the_current_key():
    state = ServerState.new()
    with pytest.raises(ValueError, match="current"):
        state.erase(state.current)
