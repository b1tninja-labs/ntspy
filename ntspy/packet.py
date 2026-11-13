"""NTPv4 header, extension fields and timestamps (RFC 5905 sec. 7.3, RFC 7822 sec. 3).

``decode_packet`` reads the 48-octet header, the extension fields and an optional MAC, and
keeps the received bytes in ``NtpPacket.raw`` so a verifier signs over what arrived.

How the tail is split. RFC 7822 sec. 3 says extension fields come before the MAC "if a MAC is
present", a MAC without extension fields is at most 24 octets (7.5.1.3), and extension fields
without a MAC must be at least 28 octets for the last one and 16 for any other (7.5.1.4).
So while 28 or more octets remain, the next item is an extension field; when fewer than 28
remain, the rest is a MAC and must be 20 octets (4-octet key id and a 16-octet digest, as for
MD5 or AES-CMAC) or 24 (key id and a 20-octet digest). Nothing remaining means no MAC, and then
the last extension field must itself be at least 28 octets.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

__all__ = [
    "EXTENSION_HEADER_LENGTH",
    "HEADER_LENGTH",
    "NTP_UNIX_OFFSET",
    "ExtensionField",
    "Mac",
    "NtpPacket",
    "NtpTimestamp",
    "PacketError",
    "decode_packet",
    "encode_packet",
    "ntp_short_to_seconds",
    "parse_extension_fields",
]

HEADER_LENGTH = 48  # 12 words (RFC 5905 sec. 7.3)
EXTENSION_HEADER_LENGTH = 4
# Seconds from 1 Jan 1900 to 1 Jan 1970 (RFC 5905 sec. 6, Figure 4 and A.4).
NTP_UNIX_OFFSET = 2_208_988_800
_MIN_EF = 16  # RFC 7822 sec. 3 (7.5)
_MIN_LAST_EF_WITHOUT_MAC = 28  # RFC 7822 sec. 3 (7.5.1.4)
_MAX_EF = 65532  # RFC 7822 sec. 3 (7.5)
_MAC_LENGTHS = (20, 24)  # key id + 16 or 20 octet digest
_HEADER = struct.Struct(">BBbbII4sQQQQ")


class PacketError(ValueError):
    """A packet that cannot be decoded or encoded."""


@dataclass(frozen=True)
class NtpTimestamp:
    """64-bit NTP timestamp: seconds since 1900 (era 0) and a 32-bit binary fraction."""

    seconds: int = 0
    fraction: int = 0

    @property
    def is_zero(self) -> bool:
        return self.seconds == 0 and self.fraction == 0

    @classmethod
    def from_unix(cls, unix_seconds: float) -> NtpTimestamp:
        """Convert Unix time to era 0; values outside 1900 to 2036 are refused."""
        whole = int(unix_seconds // 1)
        seconds = whole + NTP_UNIX_OFFSET
        if not 0 <= seconds <= 0xFFFFFFFF:
            raise PacketError("time is outside NTP era 0")
        return cls(seconds, int((unix_seconds - whole) * (1 << 32)) & 0xFFFFFFFF)

    def to_unix(self) -> float:
        """Unix time assuming era 0; the era is not carried on the wire."""
        return self.seconds - NTP_UNIX_OFFSET + self.fraction / (1 << 32)

    def to_int(self) -> int:
        return (self.seconds << 32) | self.fraction

    @classmethod
    def from_int(cls, value: int) -> NtpTimestamp:
        return cls(value >> 32, value & 0xFFFFFFFF)


def ntp_short_to_seconds(value: int) -> float:
    """NTP short format (16.16 unsigned fixed point) to seconds."""
    return value / 65536


@dataclass(frozen=True)
class ExtensionField:
    """A top-level extension field; ``value`` is everything after the 4-octet field header.

    The padding the sender added is part of ``value`` (the Length field covers it, RFC 7822
    sec. 3), so ``4 + len(value)`` is the Length and the field re-encodes byte for byte.
    """

    field_type: int
    value: bytes

    @property
    def length(self) -> int:
        return EXTENSION_HEADER_LENGTH + len(self.value)

    def encode(self) -> bytes:
        if not 0 <= self.field_type <= 0xFFFF:
            raise PacketError("field type does not fit 16 bits")
        if self.length % 4 or self.length > _MAX_EF:
            raise PacketError(f"extension field length {self.length} is not a legal multiple of 4")
        return struct.pack(">HH", self.field_type, self.length) + self.value


@dataclass(frozen=True)
class Mac:
    """Key identifier and message digest (RFC 5905 sec. 7.3); the digest is not validated."""

    key_id: int
    digest: bytes


@dataclass(frozen=True)
class NtpPacket:
    leap: int
    version: int
    mode: int
    stratum: int
    poll: int
    precision: int
    root_delay: int
    root_dispersion: int
    reference_id: bytes
    reference: NtpTimestamp
    origin: NtpTimestamp
    receive: NtpTimestamp
    transmit: NtpTimestamp
    extensions: tuple[ExtensionField, ...] = ()
    mac: Mac | None = None
    raw: bytes = field(default=b"", compare=False, repr=False)

    @property
    def kiss_code(self) -> str | None:
        """The four-character kiss code when stratum is 0 (RFC 5905 sec. 7.3), else None."""
        if self.stratum != 0:
            return None
        return self.reference_id.decode("ascii", errors="replace")


def parse_extension_fields(data: bytes, *, min_length: int = EXTENSION_HEADER_LENGTH):
    """Split ``data`` into extension fields with no MAC and no minimum-length policy.

    Used for the plaintext inside an NTS authenticator, where RFC 8915 sec. 5.6 lets fields be
    arbitrarily short but still a multiple of 4 octets.
    """
    fields: list[ExtensionField] = []
    at = 0
    while at < len(data):
        if len(data) - at < EXTENSION_HEADER_LENGTH:
            raise PacketError("truncated extension field header")
        field_type, length = struct.unpack_from(">HH", data, at)
        if length % 4 or length < min_length or at + length > len(data):
            raise PacketError(f"bad extension field length {length}")
        fields.append(ExtensionField(field_type, data[at + 4 : at + length]))
        at += length
    return tuple(fields)


def decode_packet(raw: bytes) -> NtpPacket:
    """Decode an NTP packet (RFC 5905 sec. 7.3, sec. 7.5; RFC 7822 sec. 3).

    Raises ``PacketError`` for anything malformed. Unknown extension field types are kept,
    not dropped (RFC 7822 sec. 3 lets a receiver ignore them, which is the caller's policy).
    """
    raw = bytes(raw)
    if len(raw) < HEADER_LENGTH:
        raise PacketError(f"packet is {len(raw)} octets, the header needs {HEADER_LENGTH}")
    if len(raw) % 4:
        raise PacketError("packet length is not a multiple of 4 octets")
    first, stratum, poll, precision, rdelay, rdisp, refid, ref, org, rec, xmt = _HEADER.unpack_from(
        raw
    )
    leap, version, mode = first >> 6, (first >> 3) & 7, first & 7
    at = HEADER_LENGTH
    extensions: list[ExtensionField] = []
    mac: Mac | None = None
    while at < len(raw):
        remaining = len(raw) - at
        if remaining < _MIN_LAST_EF_WITHOUT_MAC:
            if remaining not in _MAC_LENGTHS:
                raise PacketError(f"{remaining} trailing octets are neither a MAC nor a field")
            mac = Mac(int.from_bytes(raw[at : at + 4], "big"), raw[at + 4 :])
            at = len(raw)
            break
        field_type, length = struct.unpack_from(">HH", raw, at)
        if length % 4 or length < _MIN_EF or length > _MAX_EF or at + length > len(raw):
            raise PacketError(f"bad extension field length {length}")
        extensions.append(ExtensionField(field_type, raw[at + 4 : at + length]))
        at += length
    if extensions and mac is None and extensions[-1].length < _MIN_LAST_EF_WITHOUT_MAC:
        raise PacketError("the last extension field without a MAC must be 28 octets or more")
    return NtpPacket(
        leap,
        version,
        mode,
        stratum,
        poll,
        precision,
        rdelay,
        rdisp,
        refid,
        NtpTimestamp.from_int(ref),
        NtpTimestamp.from_int(org),
        NtpTimestamp.from_int(rec),
        NtpTimestamp.from_int(xmt),
        tuple(extensions),
        mac,
        raw,
    )


def encode_packet(packet: NtpPacket) -> bytes:
    """Encode an NTP packet (RFC 5905 sec. 7.3, sec. 7.5; RFC 7822 sec. 3), refusing bad fields."""
    if not 0 <= packet.leap <= 3 or not 0 <= packet.version <= 7 or not 0 <= packet.mode <= 7:
        raise PacketError("leap, version or mode out of range")
    if not 0 <= packet.stratum <= 255:
        raise PacketError("stratum out of range")
    for name in ("poll", "precision"):
        if not -128 <= getattr(packet, name) <= 127:
            raise PacketError(f"{name} out of range")
    for name in ("root_delay", "root_dispersion"):
        if not 0 <= getattr(packet, name) <= 0xFFFFFFFF:
            raise PacketError(f"{name} out of range")
    if len(packet.reference_id) != 4:
        raise PacketError("reference id is 4 octets")
    head = _HEADER.pack(
        (packet.leap << 6) | (packet.version << 3) | packet.mode,
        packet.stratum,
        packet.poll,
        packet.precision,
        packet.root_delay,
        packet.root_dispersion,
        packet.reference_id,
        packet.reference.to_int(),
        packet.origin.to_int(),
        packet.receive.to_int(),
        packet.transmit.to_int(),
    )
    body = b""
    for ext in packet.extensions:
        if ext.length < _MIN_EF:
            raise PacketError("extension fields are at least 16 octets (RFC 7822 sec. 3)")
        body += ext.encode()
    if packet.mac is not None:
        if len(packet.mac.digest) not in (16, 20):
            raise PacketError(
                "a MAC without agreement is at most 24 octets: 16 or 20 digest octets"
            )
        body += packet.mac.key_id.to_bytes(4, "big") + packet.mac.digest
    elif packet.extensions and packet.extensions[-1].length < _MIN_LAST_EF_WITHOUT_MAC:
        raise PacketError("the last extension field without a MAC must be 28 octets or more")
    return head + body
