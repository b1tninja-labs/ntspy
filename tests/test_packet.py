"""RFC 5905 sec. 7.3 header and RFC 7822 sec. 3 extension fields and MAC tail."""

from __future__ import annotations

import contextlib
import random
import struct

import pytest

from ntspy.packet import (
    ExtensionField,
    Mac,
    NtpPacket,
    NtpTimestamp,
    PacketError,
    decode_packet,
    encode_packet,
    ntp_short_to_seconds,
)


def header(first=0x24, stratum=2, poll=6, precision=-18, refid=b"\x7f\x00\x00\x01"):
    """Hand-built 48 octets: LI 0, VN 4, mode 4 by default."""
    return struct.pack(
        ">BBbbII4s", first, stratum, poll, precision, 0x00010000, 0x00008000, refid
    ) + struct.pack(
        ">QQQQ", 0xE000000000000001, 0xE000000100000002, 0xE000000200000003, 0xE000000300000004
    )


def ef(kind, size):
    return struct.pack(">HH", kind, size) + b"\xaa" * (size - 4)


def test_decode_server_response_vector():
    p = decode_packet(header())
    assert (p.leap, p.version, p.mode, p.stratum, p.poll, p.precision) == (0, 4, 4, 2, 6, -18)
    assert p.root_delay == 0x10000
    assert ntp_short_to_seconds(p.root_delay) == 1.0
    assert p.root_dispersion == 0x8000
    assert p.reference_id == b"\x7f\x00\x00\x01"
    assert p.reference == NtpTimestamp(0xE0000000, 1)
    assert p.origin == NtpTimestamp(0xE0000001, 2)
    assert p.receive == NtpTimestamp(0xE0000002, 3)
    assert p.transmit == NtpTimestamp(0xE0000003, 4)
    assert p.extensions == ()
    assert p.mac is None


@pytest.mark.parametrize(
    "tail",
    [
        b"",
        ef(0x1234, 28),
        b"\x00\x00\x00\x07" + b"\x11" * 16,
        b"\x00\x00\x00\x07" + b"\x11" * 20,
        ef(0x1234, 28) + b"\x00\x00\x00\x09" + b"\x22" * 16,
        ef(0x1, 16) + ef(0x2, 32),
    ],
)
def test_round_trip_is_byte_identical(tail):
    raw = header() + tail
    p = decode_packet(raw)
    assert encode_packet(p) == raw
    assert p.raw == raw


def test_mac_after_extension_field_is_split_correctly():
    p = decode_packet(header() + ef(0x1234, 28) + b"\x00\x00\x00\x09" + b"\x22" * 16)
    assert len(p.extensions) == 1
    assert p.mac == Mac(9, b"\x22" * 16)


def test_mac_only_20_and_24_octets():
    mac = decode_packet(header() + b"\0\0\0\1" + b"x" * 20).mac
    assert mac is not None
    assert mac.digest == b"x" * 20
    with pytest.raises(PacketError):
        decode_packet(header() + b"\0\0\0\1" + b"x" * 12)


@pytest.mark.parametrize("size", [0, 1, 47])
def test_short_packet_refused(size):
    with pytest.raises(PacketError):
        decode_packet(bytes(size))


def test_header_with_trailing_3_bytes_refused():
    with pytest.raises(PacketError):
        decode_packet(header() + b"abc")


def test_extension_length_less_than_16_refused():
    with pytest.raises(PacketError):
        decode_packet(header() + ef(1, 12) + ef(2, 28))


def test_extension_length_not_multiple_of_4_refused():
    bad = struct.pack(">HH", 1, 30) + b"\0" * 28
    with pytest.raises(PacketError):
        decode_packet(header() + bad)


def test_extension_length_beyond_packet_refused():
    with pytest.raises(PacketError):
        decode_packet(header() + struct.pack(">HH", 1, 64) + b"\0" * 24)


def test_extension_length_65535_refused():
    with pytest.raises(PacketError):
        decode_packet(header() + struct.pack(">HH", 1, 65535) + b"\0" * 24)


def test_single_extension_without_mac_shorter_than_28_refused():
    """RFC 7822 sec. 3 (7.5.1.4): a lone field is at least 28 octets."""
    with pytest.raises(PacketError):
        decode_packet(header() + ef(1, 16))
    z = NtpTimestamp()
    short = NtpPacket(
        0, 4, 3, 0, 0, 0, 0, 0, b"\0" * 4, z, z, z, z, (ExtensionField(1, bytes(20)),)
    )
    with pytest.raises(PacketError):
        encode_packet(short)


def test_two_extensions_without_mac_last_28_other_16_accepted():
    p = decode_packet(header() + ef(1, 16) + ef(2, 28))
    assert [e.length for e in p.extensions] == [16, 28]


def test_unknown_extension_type_is_preserved_not_dropped():
    p = decode_packet(header() + ef(0xBEEF, 28))
    assert p.extensions[0].field_type == 0xBEEF
    assert len(p.extensions[0].value) == 24


def test_leap_indicator_3_decodes():
    assert decode_packet(header(first=0xE4)).leap == 3


def test_stratum_0_reference_id_is_kiss_code_ascii():
    p = decode_packet(header(stratum=0, refid=b"RATE"))
    assert p.kiss_code == "RATE"
    assert decode_packet(header()).kiss_code is None


def test_negative_poll_and_precision_are_signed():
    p = decode_packet(header(poll=-3, precision=-18))
    assert (p.poll, p.precision) == (-3, -18)
    assert header(precision=-18)[3] == 0xEE


def test_decode_keeps_original_bytes():
    buf = bytearray(header())
    p = decode_packet(bytes(buf))
    buf[0] = 0
    assert p.raw == header()


def test_fuzz_random_buffers_never_raise_anything_but_packet_error():
    rng = random.Random(5905)
    for _ in range(1000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        with contextlib.suppress(PacketError):
            decode_packet(data)


def test_fuzz_mutated_valid_packets():
    rng = random.Random(7822)
    base = header() + ef(0x0104, 36) + ef(0x0404, 40)
    for _ in range(1000):
        data = bytearray(base)
        data[rng.randrange(48, len(data))] = rng.randrange(256)
        with contextlib.suppress(PacketError):
            decode_packet(bytes(data))


@pytest.mark.parametrize(
    "bad",
    [{"stratum": 256}, {"version": 8}, {"poll": 128}, {"reference_id": b"abc"}, {"leap": 4}],
)
def test_encode_refuses_out_of_range_fields(bad):
    good = decode_packet(header())
    fields = {**good.__dict__, **bad}
    with pytest.raises(PacketError):
        encode_packet(NtpPacket(**fields))


def test_timestamp_unix_conversion_uses_the_1900_epoch():
    assert NtpTimestamp.from_unix(0).seconds == 2208988800
    assert NtpTimestamp(2208988800, 1 << 31).to_unix() == 0.5
    assert NtpTimestamp().is_zero
    with pytest.raises(PacketError):
        NtpTimestamp.from_unix(-3e9)


def test_a_24_octet_tail_is_a_mac_not_a_short_field():
    """The documented rule: under 28 octets remaining, a 20 or 24 octet tail is a MAC."""
    p = decode_packet(header() + ef(1, 24))
    assert p.mac is not None
    assert p.extensions == ()
