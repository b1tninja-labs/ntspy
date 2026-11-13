"""RFC 8915 sec. 5 extension fields and the authenticator."""

from __future__ import annotations

from dataclasses import replace

import pytest

from ntspy.auth import AuthenticationError, Negotiated
from ntspy.extension import (
    COOKIE,
    NTS_AUTHENTICATOR,
    UNIQUE_IDENTIFIER,
    authenticate,
    cookie_field,
    open_authenticator,
    placeholder_field,
    unique_identifier_field,
    verify,
)
from ntspy.packet import (
    ExtensionField,
    NtpPacket,
    NtpTimestamp,
    PacketError,
    decode_packet,
    encode_packet,
)

KEYS = Negotiated(15, bytes(range(32)), bytes(range(32, 64)))
Z = NtpTimestamp()


def request(mode=3, ext=()):
    return NtpPacket(0, 4, mode, 0, 0, 0, 0, 0, b"\0" * 4, Z, Z, Z, NtpTimestamp(1, 2), tuple(ext))


def nts_request():
    return request(ext=[unique_identifier_field(), cookie_field(b"c" * 100)])


def wire(packet):
    return decode_packet(encode_packet(packet))


def test_unique_identifier_is_at_least_32_random_octets():
    a, b = unique_identifier_field(), unique_identifier_field()
    assert a.field_type == UNIQUE_IDENTIFIER
    assert len(a.value) == 32
    assert a != b
    with pytest.raises(PacketError):
        unique_identifier_field(b"short")


def test_placeholder_has_the_same_body_length_as_the_cookie():
    assert len(placeholder_field(100).value) == len(cookie_field(b"c" * 100).value)
    assert placeholder_field(100).value == bytes(100)


def test_authenticate_then_verify_round_trip_through_the_wire():
    packet = wire(authenticate(nts_request(), KEYS))
    assert verify(packet, KEYS)
    assert packet.extensions[-1].field_type == NTS_AUTHENTICATOR


def test_encrypted_extension_fields_come_back_decrypted():
    inner = ExtensionField(COOKIE, b"n" * 100)
    server = request(mode=4, ext=[unique_identifier_field()])
    packet = wire(authenticate(server, KEYS, encrypted=[inner]))
    assert open_authenticator(packet, KEYS) == (inner,)
    assert b"n" * 100 not in packet.raw


def test_client_uses_c2s_key_and_server_uses_s2c_key():
    swapped = Negotiated(15, KEYS.s2c_key, KEYS.c2s_key)
    assert not verify(wire(authenticate(nts_request(), KEYS)), swapped)


@pytest.mark.parametrize("at", [0, 40, 52, 60])
def test_tampering_with_header_or_authenticated_field_fails(at):
    raw = bytearray(encode_packet(authenticate(nts_request(), KEYS)))
    raw[at] ^= 0x01
    try:
        packet = decode_packet(bytes(raw))
    except PacketError:
        return
    assert not verify(packet, KEYS)


def test_missing_authenticator_and_duplicate_authenticator_fail():
    assert not verify(nts_request(), KEYS)
    once = authenticate(nts_request(), KEYS)
    twice = replace(once, extensions=(*once.extensions, once.extensions[-1]), raw=b"")
    assert not verify(twice, KEYS)


def test_authenticator_refused_outside_modes_3_and_4():
    with pytest.raises(AuthenticationError):
        authenticate(request(mode=1), KEYS)


def test_short_nonce_in_a_client_packet_needs_additional_padding():
    """RFC 8915 sec. 5.6: N_REQ is 16, so a 4 octet nonce needs at least 12 octets of padding."""
    short = authenticate(nts_request(), KEYS, nonce=b"abcd")
    assert not verify(wire(short), KEYS)


def test_nonce_of_16_octets_needs_no_additional_padding():
    assert verify(authenticate(nts_request(), KEYS, nonce=bytes(16)), KEYS)


def test_authenticator_length_lies_are_refused():
    good = authenticate(nts_request(), KEYS)
    field = good.extensions[-1]
    forged = ExtensionField(NTS_AUTHENTICATOR, b"\xff\xff\xff\xff" + field.value[4:])
    bad = replace(good, extensions=(*good.extensions[:-1], forged), raw=b"")
    assert not verify(bad, KEYS)
