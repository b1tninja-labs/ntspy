"""NTS key establishment: the record codec, request and response rules, ALPN and retry (RFC 8915 sec. 3, 4).

This is the plain TLV layer of NTS-KE. ``encode_record``, ``decode_records``, ``build_request`` and
``parse_response`` read and write the bytes a client and server exchange inside the TLS channel
and enforce what sec. 4.1 says about each record. The TLS session itself, and the key extraction
after it (the exporter of sec. 5.1 and 4.3), are not here: Python's ``ssl`` has no keying-material
exporter, so ``establish`` stays a placeholder and ROADMAP.md records the exporter as ``[no]``.
``tls_context`` gives the TLS 1.3 + ALPN ``ntske/1`` context a caller would connect with.
"""

from __future__ import annotations

import enum
import ipaddress
import ssl
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Negotiated = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "AEAD_AES_SIV_CMAC_256",
    "ALPN_NTSKE",
    "KE_PORT",
    "MAX_REQUEST_OCTETS",
    "NEXT_PROTOCOL_NTPV4",
    "KeBackoff",
    "KeError",
    "KeRecord",
    "KeResponse",
    "RecordType",
    "build_request",
    "decode_records",
    "encode_record",
    "establish",
    "parse_response",
    "retry_interval",
    "tls_context",
]

KE_PORT = 4460  # sec. 4: "The NTS key establishment protocol is conducted via TCP port 4460"
ALPN_NTSKE = "ntske/1"  # sec. 4: the ALPN identifier, REQUIRED for interoperability (sec. 3)
NEXT_PROTOCOL_NTPV4 = 0  # sec. 4.1.2 and the IANA "Network Time Security Next Protocols" registry
AEAD_AES_SIV_CMAC_256 = 15  # sec. 4.1.5: servers MUST support it
MAX_RECORD_BODY = 0xFFFF
MAX_REQUEST_OCTETS = 1024
"""Servers MUST accept requests of at least this many octets (sec. 4 para 3). A floor, not a limit."""
MAX_RESPONSE_OCTETS = 65536
"""Clients SHOULD accept responses of at least this many octets (sec. 4 para 3); the default bound here."""
_CODE_LENGTH = 2
_WARNING_NONE = "no warning codes are defined (sec. 4.1.4)"


class KeError(ValueError):
    """An NTS-KE message that breaks sec. 4 or that carries an Error or Warning record."""


class RecordType(enum.IntEnum):
    """Record types 0 to 7 (RFC 8915 sec. 4.1.1 to 4.1.8)."""

    END_OF_MESSAGE = 0
    NEXT_PROTOCOL = 1
    ERROR = 2
    WARNING = 3
    AEAD_ALGORITHM = 4
    NEW_COOKIE = 5
    SERVER = 6
    PORT = 7


@dataclass(frozen=True, slots=True)
class KeRecord:
    """One NTS-KE record: the critical bit, the 15-bit type and the body (sec. 4, Figure 2)."""

    record_type: int
    body: bytes = b""
    critical: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.record_type <= 0x7FFF:
            raise KeError(f"record type {self.record_type} does not fit 15 bits")
        if len(self.body) > MAX_RECORD_BODY:
            raise KeError(f"record body of {len(self.body)} octets does not fit 16 bits")


def encode_record(record: KeRecord) -> bytes:
    """Encode one record (RFC 8915 sec. 4.1, Figure 2 of sec. 4): C and the 15-bit type, the 16-bit body length, the body.

    The critical bit is the most significant bit of the first octet (sec. 4 para 7). The length is
    the length of the body only, unlike an NTP extension field (para 8).
    """
    first = (0x8000 if record.critical else 0) | record.record_type
    return struct.pack(">HH", first, len(record.body)) + record.body


def decode_records(data: bytes, *, max_octets: int = MAX_RESPONSE_OCTETS) -> tuple[KeRecord, ...]:
    """Decode one NTS-KE message: records up to and including the End of Message record.

    Every message ends with exactly one End of Message record, which MUST have the critical bit
    set and an empty body (sec. 4.1.1); that is what makes a message self-delimiting, so
    decoding stops there and octets after it are an error. A truncated record, a missing End of
    Message and a message over ``max_octets`` are errors.

    Raises:
        KeError: the bytes are not one complete NTS-KE message.
    """
    if len(data) > max_octets:
        raise KeError(f"message of {len(data)} octets exceeds the {max_octets} octet limit")
    records: list[KeRecord] = []
    at = 0
    while True:
        if len(data) - at < 4:
            raise KeError("message ends before an End of Message record")
        first, length = struct.unpack_from(">HH", data, at)
        at += 4
        if len(data) - at < length:
            raise KeError("a record body is truncated")
        record = KeRecord(first & 0x7FFF, bytes(data[at : at + length]), bool(first & 0x8000))
        at += length
        records.append(record)
        if record.record_type == RecordType.END_OF_MESSAGE:
            if not record.critical or record.body:
                raise KeError("End of Message must be critical and empty (sec. 4.1.1)")
            if at != len(data):
                raise KeError(f"{len(data) - at} octets follow the End of Message record")
            return tuple(records)


def _u16s(body: bytes, what: str) -> tuple[int, ...]:
    if len(body) % 2:
        raise KeError(f"{what} is not a list of 16-bit integers")
    return struct.unpack(f">{len(body) // 2}H", body)


def _ids(ids: tuple[int, ...]) -> bytes:
    if any(not 0 <= i <= 0xFFFF for i in ids):
        raise KeError("an identifier does not fit 16 bits")
    return struct.pack(f">{len(ids)}H", *ids)


def build_request(
    *,
    aead: tuple[int, ...] = (AEAD_AES_SIV_CMAC_256,),
    protocols: tuple[int, ...] = (NEXT_PROTOCOL_NTPV4,),
    server: str | None = None,
    port: int | None = None,
) -> bytes:
    """The client's NTS-KE request (sec. 4, Figure 3): protocol and AEAD negotiation, optional server and port.

    The Next Protocol record lists at least one protocol and is critical (sec. 4.1.2); the AEAD
    record lists at least one algorithm in decreasing preference and is required when protocol 0
    is offered (sec. 4.1.5). The client never sends Error, Warning or New Cookie records
    (sec. 4.1.3, 4.1.4, 4.1.6), at most one server record (sec. 4.1.7), and does not set the
    critical bit on the optional server and port records (SHOULD NOT, sec. 4.1.7 and 4.1.8).
    """
    if not protocols:
        raise KeError("the request must list at least one next protocol (sec. 4.1.2)")
    if NEXT_PROTOCOL_NTPV4 in protocols and not aead:
        raise KeError("protocol 0 needs an AEAD algorithm record (sec. 4.1.5)")
    records = [KeRecord(RecordType.NEXT_PROTOCOL, _ids(protocols), critical=True)]
    if aead:
        records.append(KeRecord(RecordType.AEAD_ALGORITHM, _ids(aead)))
    if server is not None:
        records.append(KeRecord(RecordType.SERVER, _server_body(server)))
    if port is not None:
        if not 0 < port <= 0xFFFF:
            raise KeError("port does not fit 16 bits")
        records.append(KeRecord(RecordType.PORT, struct.pack(">H", port)))
    records.append(KeRecord(RecordType.END_OF_MESSAGE, critical=True))
    return b"".join(encode_record(r) for r in records)


def _server_body(name: str) -> bytes:
    """An ASCII IPv4 or IPv6 address (no zone) or FQDN (sec. 4.1.7); non-ASCII must be an A-label."""
    try:
        raw = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise KeError(
            "a server name is ASCII; use the A-label of an internationalized name"
        ) from error
    if not raw:
        raise KeError("a server name is not empty")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return raw  # an FQDN; the recipient makes it fully qualified (sec. 4.1.7)
    if address.version == 6 and "%" in name:  # pragma: no cover - ip_address refuses a zone here
        raise KeError("an IPv6 address must not carry a zone identifier")
    return raw


@dataclass(frozen=True, slots=True)
class KeResponse:
    """What a validated server response negotiated (sec. 4.1)."""

    protocols: tuple[int, ...]
    aead: int | None
    cookies: tuple[bytes, ...]
    server: str | None = None
    port: int | None = None
    ignored: tuple[int, ...] = field(default=())
    """Types of unrecognized non-critical records, which sec. 4 says to ignore."""


def parse_response(
    data: bytes,
    *,
    offered_protocols: tuple[int, ...] = (NEXT_PROTOCOL_NTPV4,),
    offered_aead: tuple[int, ...] = (AEAD_AES_SIV_CMAC_256,),
    max_octets: int = MAX_RESPONSE_OCTETS,
) -> KeResponse:
    """Validate a server's NTS-KE response against sec. 4.1 and return what it negotiated.

    Errors a client must act on: an Error record (the client MUST discard key material and not
    proceed, sec. 4.1.3), a Warning record (MAY abort; unrecognized codes MUST be errors, and
    none are defined, sec. 4.1.4), an unrecognized record with the critical bit set (sec. 4),
    a missing or repeated Next Protocol record, protocols or an algorithm the client did not
    offer (sec. 4.1.2, 4.1.5), a repeated AEAD or server record, and, when NTPv4 is accepted with
    a non-empty algorithm, no cookie (the server MUST send at least one, sec. 4.1.6). A response
    that accepts nothing, or NTPv4 with an empty AEAD record, parses as ``aead=None`` or no
    protocols: the client cannot proceed and the caller decides.

    Raises:
        KeError: the response is malformed, carries an Error or Warning, or breaks a MUST.
    """
    records = decode_records(data, max_octets=max_octets)
    protocols: tuple[int, ...] | None = None
    aead: tuple[int, ...] | None = None
    cookies: list[bytes] = []
    server: str | None = None
    port: int | None = None
    ignored: list[int] = []
    for record in records[:-1]:
        kind = record.record_type
        if kind == RecordType.ERROR:
            if len(record.body) != _CODE_LENGTH:
                raise KeError("an Error record body is exactly two octets (sec. 4.1.3)")
            code = struct.unpack(">H", record.body)[0]
            names = {
                0: "unrecognized critical record",
                1: "bad request",
                2: "internal server error",
            }
            raise KeError(f"the server answered Error {code} ({names.get(code, 'unknown code')})")
        if kind == RecordType.WARNING:
            raise KeError(f"the server answered a Warning record; {_WARNING_NONE}")
        if kind == RecordType.NEXT_PROTOCOL:
            if protocols is not None:
                raise KeError("two Next Protocol records (sec. 4.1.2)")
            if not record.critical:
                raise KeError("the Next Protocol record must be critical (sec. 4.1.2)")
            protocols = _u16s(record.body, "Next Protocol")
        elif kind == RecordType.AEAD_ALGORITHM:
            if aead is not None:
                raise KeError("two AEAD Algorithm records (sec. 4.1.5)")
            aead = _u16s(record.body, "AEAD Algorithm")
        elif kind == RecordType.NEW_COOKIE:
            cookies.append(record.body)
        elif kind == RecordType.SERVER:
            if server is not None:
                raise KeError("two NTPv4 Server records (sec. 4.1.7)")
            server = _read_server(record.body)
        elif kind == RecordType.PORT:
            if len(record.body) != _CODE_LENGTH:
                raise KeError("a Port record body is exactly two octets (sec. 4.1.8)")
            port = struct.unpack(">H", record.body)[0]
        elif record.critical:
            raise KeError(f"unrecognized critical record type {kind} (sec. 4)")
        else:
            ignored.append(kind)
    if protocols is None:
        raise KeError("no Next Protocol record (sec. 4.1.2: exactly one)")
    if not set(protocols) <= set(offered_protocols):
        raise KeError("the response lists a protocol the client did not offer (sec. 4.1.2)")
    chosen: int | None = None
    if aead is not None:
        if len(aead) > 1:
            raise KeError("the response names more than one AEAD algorithm (sec. 4.1.5)")
        if aead and aead[0] not in offered_aead:
            raise KeError("the response chose an AEAD algorithm the client did not offer")
        chosen = aead[0] if aead else None
    if NEXT_PROTOCOL_NTPV4 in protocols:
        if aead is None:
            raise KeError("NTPv4 accepted with no AEAD Algorithm record (sec. 4.1.5)")
        if chosen is not None and not cookies:
            raise KeError("NTPv4 negotiated but no New Cookie record (sec. 4.1.6)")
    return KeResponse(protocols, chosen, tuple(cookies), server, port, tuple(ignored))


def _read_server(body: bytes) -> str:
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as error:
        raise KeError("a Server record is ASCII (sec. 4.1.7)") from error
    if not text or "%" in text:
        raise KeError("a Server record is an address without a zone, or an FQDN (sec. 4.1.7)")
    return text


def tls_context(*, cafile: str | None = None) -> ssl.SSLContext:
    """A client TLS context for NTS-KE: TLS 1.3 only, server verified, ALPN ``ntske/1`` (sec. 3, 4).

    "Implementations MUST NOT negotiate TLS versions earlier than 1.3" (sec. 3), and ALPN is
    "integral to NTS" (sec. 3). The server name check is the stdlib's (RFC 6125 DNS-ID); sec. 8.5's
    advice on verifying a server whose clock is not yet set is not handled here.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    if cafile is None:
        context.load_default_certs()
    else:
        context.load_verify_locations(cafile=cafile)
    context.set_alpn_protocols([ALPN_NTSKE])
    return context


def retry_interval(attempt: int) -> float:
    """Seconds before the ``attempt``-th retry: ``min(10 * 1.5**(n-1), 432000)`` (sec. 4.2).

    The RFC calls it a suggestion ("Clients SHOULD use exponential backoff"): an initial and
    minimum of 10 seconds, a base of 1.5 and a maximum of five days.
    """
    if attempt < 1:
        raise ValueError("attempts count from 1")
    return min(10.0 * 1.5 ** (attempt - 1), 432000.0)


class KeBackoff:
    """Retry state for NTS-KE (sec. 4.2): the interval is not reset by a mere handshake.

    "Clients MUST NOT reset the retry interval until they have performed a successful key
    establishment ... followed by a successful use of the negotiated Next Protocol with the keys
    and data established during that transaction." So ``ke_succeeded`` only records that half, and
    ``next_protocol_succeeded`` completes it and resets.
    """

    def __init__(self) -> None:
        self.attempts = 0
        self._ke_ok = False

    def failed(self) -> float:
        """Record a failed attempt and return the interval to wait before the next one."""
        self.attempts += 1
        self._ke_ok = False
        return retry_interval(self.attempts)

    def ke_succeeded(self) -> None:
        self._ke_ok = True

    def next_protocol_succeeded(self) -> None:
        if self._ke_ok:
            self.attempts = 0
            self._ke_ok = False


async def establish(server: str, port: int) -> Negotiated:
    """Pending behaviour defined by RFC 8915 sec. 4.

    Not implemented yet. See the ``ke.establish()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code. It cannot be finished on the
    standard library: the keys come from the TLS exporter (sec. 4.3 and 5.1), which ``ssl`` lacks.
    """
    raise NotImplementedError("establish() is not implemented: RFC 8915 sec. 4")
