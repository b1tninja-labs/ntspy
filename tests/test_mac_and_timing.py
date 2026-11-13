"""AES-CMAC packet MAC (RFC 8573 with RFC 4493) and the on-wire arithmetic (RFC 5905 sec. 8).

Provenance: the AES-CMAC vectors are RFC 4493 sec. 4 (read through rfclib), which RFC 8573 sec. 5
names as its test vectors. The packet-level MAC is checked against ``cryptography``'s CMAC computed
independently over the encoded header, so it shares no code with the module. The timing numbers
are chosen so every value is an exact binary fraction (multiples of 1/8 second) and the answers
are exact: a server 0.5 s ahead, 0.125 s each way, 0.125 s of server processing.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from ntspy.auth import AuthenticationError, aes_cmac, sign_mac, verify_mac
from ntspy.packet import ExtensionField, Mac, NtpPacket, NtpTimestamp, decode_packet, encode_packet
from ntspy.timing import ResponseCheck, check_response, offset_and_delay

RFC4493_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
RFC4493_M = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
RFC4493_VECTORS = [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
]
Z = NtpTimestamp()


def test_aes_cmac_rfc4493_vectors():
    for length, expected in RFC4493_VECTORS:
        assert aes_cmac(RFC4493_KEY, RFC4493_M[:length]).hex() == expected
    for bad in (b"", b"k" * 15, b"k" * 24, b"k" * 32):  # RFC 8573 sec. 3: AES-128 only
        with pytest.raises(AuthenticationError, match="16 octets"):
            aes_cmac(bad, b"x")


def client_packet(*extensions):
    return NtpPacket(
        0, 4, 3, 0, 6, -18, 0, 0, b"\0" * 4, Z, Z, Z, NtpTimestamp(3_900_000_000, 7), extensions
    )


def test_aes_cmac_mac():
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms

    key = RFC4493_KEY
    for extensions in ((), (ExtensionField(0x1234, b"\x01" * 12),)):
        signed = sign_mac(client_packet(*extensions), 42, key)
        assert signed.mac is not None
        assert signed.mac.key_id == 42
        assert len(signed.mac.digest) == 16  # RFC 8573 sec. 3: at least 128 bits
        raw = encode_packet(signed)
        assert len(raw) == 48 + sum(e.length for e in extensions) + 4 + 16
        # independent check: CMAC over every header and extension octet, key id excluded
        oracle = cmac.CMAC(algorithms.AES(key))
        oracle.update(raw[:-20])
        assert signed.mac.digest == oracle.finalize()
        received = decode_packet(raw)
        assert verify_mac(received, {42: key})
        # anything that changes the covered octets, the key id or the key breaks it
        assert not verify_mac(received, {42: b"\x00" * 16})
        assert not verify_mac(received, {43: key})
        assert not verify_mac(received, {})
        tampered = bytearray(raw)
        tampered[5] ^= 1  # a header octet
        assert not verify_mac(decode_packet(bytes(tampered)), {42: key})
        tampered = bytearray(raw)
        tampered[-1] ^= 1  # the tag
        assert not verify_mac(decode_packet(bytes(tampered)), {42: key})
    assert not verify_mac(client_packet(), {42: key})  # no MAC at all
    # a 20-octet digest is MD5/SHA-1 shaped and never accepted as an AES-CMAC tag
    sha_like = replace(client_packet(), mac=Mac(42, b"d" * 20))
    assert not verify_mac(sha_like, {42: key})
    with pytest.raises(ValueError, match="already"):
        sign_mac(signed, 1, key)
    with pytest.raises(ValueError, match="32 bits"):
        sign_mac(client_packet(), 2**32, key)


def ts(seconds: float, era_seconds: int = 3_900_000_000) -> NtpTimestamp:
    whole = int(seconds)
    return NtpTimestamp(era_seconds + whole, int((seconds - whole) * (1 << 32)))


def test_offset_and_delay():
    # server 0.5 s ahead; 0.125 s each way; 0.125 s of processing (exact binary fractions)
    t1, t2, t3, t4 = ts(100.0), ts(100.625), ts(100.75), ts(100.375)
    result = offset_and_delay(t1, t2, t3, t4)
    assert result.offset == 0.5
    assert result.delay == 0.25
    # a client ahead of the server has a negative offset
    behind = offset_and_delay(ts(100.0), ts(99.625), ts(99.75), ts(100.375))
    assert behind.offset == -0.5
    assert behind.delay == 0.25
    # differences are taken modulo 2**64, so a reply across the 2036 era boundary is right.
    # T1 = 2**32 - 1 s, T2 = 1.5 s past the wrap, T3 = T2, T4 = 0.25 s into the second second:
    # T2 - T1 = 2.5 s, T3 - T4 = 1.5 - 0.25 + ... computed below from exact fractions
    t1 = NtpTimestamp(0xFFFFFFFF, 0)
    t2 = NtpTimestamp(1, 1 << 31)  # 1.5 s after the wrap, so 2.5 s after t1
    t3 = NtpTimestamp(1, 1 << 31)
    t4 = NtpTimestamp(0, 1 << 30)  # 0.25 s after the wrap, so 1.25 s after t1
    wrapped = offset_and_delay(t1, t2, t3, t4)
    assert wrapped.offset == (2.5 + (1.5 - 0.25)) / 2
    assert wrapped.delay == max(1.25 - 0.0, 0.0)
    # a negative apparent delay is clamped to the precision (sec. 8 para 15), zero by default
    skewed = offset_and_delay(ts(0.0), ts(0.0), ts(2.0), ts(1.0))
    assert skewed.delay == 0.0
    assert offset_and_delay(ts(0.0), ts(0.0), ts(2.0), ts(1.0), precision=2**-18).delay == 2**-18


def reply(**over):
    fields = {
        "leap": 0, "version": 4, "mode": 4, "stratum": 2, "poll": 6, "precision": -18,
        "root_delay": 0, "root_dispersion": 0, "reference_id": b"\x7f\x00\x00\x01",
        "reference": ts(1.0), "origin": ts(100.0), "receive": ts(100.625), "transmit": ts(100.75),
    }  # fmt: skip
    fields.update(over)
    return NtpPacket(**fields)


def test_response_sanity_checks():
    sent = ts(100.0)
    assert check_response(reply(), sent_transmit=sent) is ResponseCheck.OK
    assert check_response(reply(mode=3), sent_transmit=sent) is ResponseCheck.NOT_A_SERVER_REPLY
    # the "bogus" test: the origin timestamp must be what the client sent (sec. 8 para 8)
    assert check_response(reply(origin=ts(99.0)), sent_transmit=sent) is ResponseCheck.BOGUS
    # a repeated transmit timestamp is a duplicate or replay
    repeat = check_response(reply(), sent_transmit=sent, last_transmit=ts(100.75))
    assert repeat is ResponseCheck.DUPLICATE
    assert check_response(reply(), sent_transmit=sent, last_transmit=ts(99.0)) is ResponseCheck.OK
    # stratum 0 is a KoD whose timestamps are undefined: reported before any are trusted
    kiss = check_response(reply(stratum=0, origin=ts(0.0)), sent_transmit=sent)
    assert kiss is ResponseCheck.KISS_OF_DEATH
    assert check_response(reply(leap=3), sent_transmit=sent) is ResponseCheck.UNSYNCHRONIZED
    assert check_response(reply(stratum=16), sent_transmit=sent) is ResponseCheck.UNSYNCHRONIZED
    assert check_response(reply(transmit=Z), sent_transmit=sent) is ResponseCheck.UNSYNCHRONIZED
