"""AES-SIV via cryptography against RFC 5297 A.2, and HKDF against RFC 5869 A.1."""

from __future__ import annotations

import pytest

from ntspy.auth import (
    AuthenticationError,
    Negotiated,
    exporter_context,
    hkdf_sha256,
    siv_open,
    siv_seal,
)


def h(text):
    return bytes.fromhex(text.replace(" ", ""))


KEY = h("7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f")
AD1 = h("00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100")
AD2 = h("10203040 50607080 90a0")
NONCE = h("09f91102 9d74e35b d84156c5 635688c0")
PLAIN = h(
    "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e"
    " 63727970 74207573 696e6720 5349562d 414553"
)
EXPECTED = h(
    "7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17"
    " dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d"
)


def test_rfc5297_a2_nonce_based_vector_through_cryptography():
    """The vector [AD1, AD2, nonce] reproduces the RFC output: the nonce is the last component."""
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    assert AESSIV(KEY).encrypt(PLAIN, [AD1, AD2, NONCE]) == EXPECTED


def test_siv_seal_marshals_aad_then_nonce():
    sealed = siv_seal(KEY, NONCE, PLAIN, AD1 + AD2)
    assert siv_open(KEY, NONCE, sealed, AD1 + AD2) == PLAIN
    assert sealed != EXPECTED  # one combined AD is not the two-component vector


def test_siv_open_rejects_tampering_and_wrong_key():
    sealed = siv_seal(KEY, NONCE, PLAIN, b"hdr")
    with pytest.raises(AuthenticationError):
        siv_open(KEY, NONCE, sealed[:-1] + bytes([sealed[-1] ^ 1]), b"hdr")
    with pytest.raises(AuthenticationError):
        siv_open(KEY, NONCE, sealed, b"other")
    with pytest.raises(AuthenticationError):
        siv_open(bytes(32), NONCE, sealed, b"hdr")


def test_siv_wrong_key_length_refused():
    with pytest.raises(AuthenticationError):
        siv_seal(b"short", NONCE, b"x")


def test_hkdf_rfc5869_a1():
    okm = hkdf_sha256(h("0b" * 22), h("000102030405060708090a0b0c"), h("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm == h(
        "3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf 34007208d5b887185865"
    )


def test_exporter_context_is_five_octets_rfc8915_5_1():
    assert exporter_context(15, s2c=False) == bytes([0, 0, 0, 15, 0])
    assert exporter_context(15, s2c=True) == bytes([0, 0, 0, 15, 1])


def test_negotiated_checks_key_lengths_and_hides_keys():
    n = Negotiated(15, bytes(32), bytes(32))
    assert "c2s_key" not in repr(n)
    with pytest.raises(AuthenticationError):
        Negotiated(15, bytes(16), bytes(32))
    with pytest.raises(AuthenticationError):
        Negotiated(99, bytes(32), bytes(32))
