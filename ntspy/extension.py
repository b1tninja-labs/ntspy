"""The NTS extension fields: unique identifier, cookie, placeholder, authenticator (RFC 8915 sec. 5).

``authenticate`` appends the NTS Authenticator and Encrypted Extension Fields field to a packet
(sec. 5.6); ``verify`` and ``open_authenticator`` check it. Both use the key for the packet's
direction: the C2S key for mode 3, the S2C key for mode 4. The packet passed to ``authenticate``
must hold, in ``extensions``, exactly the fields that are to be authenticated but not encrypted.
"""

from __future__ import annotations

import enum
import os
import struct
from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace

from .auth import AuthenticationError, Negotiated, siv_open, siv_seal
from .packet import (
    HEADER_LENGTH,
    ExtensionField,
    NtpPacket,
    PacketError,
    encode_packet,
    parse_extension_fields,
)

__all__ = [
    "COOKIE",
    "COOKIE_PLACEHOLDER",
    "NTS_AUTHENTICATOR",
    "UNIQUE_IDENTIFIER",
    "KodAction",
    "KodDiscardError",
    "KodResult",
    "NakAction",
    "NakTracker",
    "authenticate",
    "classify_kod",
    "cookie_field",
    "open_authenticator",
    "placeholder_field",
    "unique_identifier_field",
    "verify",
]

UNIQUE_IDENTIFIER = 0x0104  # sec. 5.3
COOKIE = 0x0204  # sec. 5.4
COOKIE_PLACEHOLDER = 0x0304  # sec. 5.5
NTS_AUTHENTICATOR = 0x0404  # sec. 5.6
_N_REQ = 16  # lesser of 16 and N_MAX, which is unlimited for AES-SIV (RFC 5297 sec. 6.1)


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def unique_identifier_field(identifier: bytes | None = None) -> ExtensionField:
    """A Unique Identifier field (sec. 5.3); with no argument, 32 random octets (the minimum)."""
    body = os.urandom(32) if identifier is None else identifier
    if len(body) < 32:
        raise PacketError("a unique identifier is at least 32 octets (RFC 8915 sec. 5.3)")
    return ExtensionField(UNIQUE_IDENTIFIER, _pad4(body))


def cookie_field(cookie: bytes) -> ExtensionField:
    """An NTS Cookie field (sec. 5.4); the cookie is opaque to the client."""
    return ExtensionField(COOKIE, _pad4(cookie))


def placeholder_field(cookie_length: int) -> ExtensionField:
    """A Cookie Placeholder of the same body length as the cookie, all zeros (sec. 5.5)."""
    return ExtensionField(COOKIE_PLACEHOLDER, b"\x00" * (cookie_length + (-cookie_length % 4)))


def _key_for(packet: NtpPacket, context: Negotiated) -> bytes:
    if packet.mode == 3:
        return context.c2s_key
    if packet.mode == 4:
        return context.s2c_key
    raise AuthenticationError("the authenticator is only for modes 3 and 4 (RFC 8915 sec. 5.6)")


def authenticate(
    packet: NtpPacket,
    context: Negotiated,
    *,
    encrypted: Sequence[ExtensionField] = (),
    nonce: bytes | None = None,
) -> NtpPacket:
    """Append the NTS Authenticator and Encrypted Extension Fields field (RFC 8915 sec. 5.6).

    The associated data is the header and every extension field already in ``packet``; the
    plaintext is ``encrypted`` concatenated. The nonce defaults to 16 random octets, which
    meets N_REQ, so no Additional Padding is ever needed here.
    """
    key = _key_for(packet, context)
    if packet.mac is not None:
        raise PacketError("an NTS packet carries no MAC")
    if any(e.field_type == NTS_AUTHENTICATOR for e in packet.extensions):
        raise PacketError("the packet already has an authenticator")
    nonce = os.urandom(_N_REQ) if nonce is None else nonce
    if not nonce:
        raise AuthenticationError("the nonce must not be empty")
    plaintext = b"".join(e.encode() for e in encrypted)
    aad = encode_packet(packet)
    sealed = siv_seal(key, nonce, plaintext, aad, aead_id=context.aead_id)
    body = struct.pack(">HH", len(nonce), len(sealed)) + _pad4(nonce) + _pad4(sealed)
    # The authenticator is the last field and there is no MAC, so RFC 7822 wants 28 octets.
    body += b"\x00" * max(0, 28 - 4 - len(body))
    field = ExtensionField(NTS_AUTHENTICATOR, body)
    out = replace(packet, extensions=(*packet.extensions, field), raw=b"")
    return replace(out, raw=encode_packet(out))


def _locate(packet: NtpPacket) -> tuple[int, ExtensionField]:
    hits = [i for i, e in enumerate(packet.extensions) if e.field_type == NTS_AUTHENTICATOR]
    if len(hits) != 1:
        raise AuthenticationError("exactly one NTS authenticator is required")
    return hits[0], packet.extensions[hits[0]]


def open_authenticator(packet: NtpPacket, context: Negotiated) -> tuple[ExtensionField, ...]:
    """Authenticate ``packet`` and return its decrypted extension fields (RFC 8915 sec. 5.6).

    Raises ``AuthenticationError`` on any failure: a missing or repeated authenticator, a
    malformed field, a mode 3 packet whose Additional Padding is too short (servers MUST
    discard those), or a failed tag.
    """
    index, auth = _locate(packet)
    key = _key_for(packet, context)
    body = auth.value
    if len(body) < 4:
        raise AuthenticationError("authenticator field is too short")
    nonce_len, ct_len = struct.unpack_from(">HH", body)
    nonce_padded = nonce_len + (-nonce_len % 4)
    ct_padded = ct_len + (-ct_len % 4)
    if 4 + nonce_padded + ct_padded > len(body) or nonce_len == 0:
        raise AuthenticationError("authenticator lengths exceed the field")
    extra = len(body) - 4 - nonce_padded - ct_padded
    if packet.mode == 3 and nonce_padded < _N_REQ and extra < _N_REQ - nonce_padded:
        raise AuthenticationError("Additional Padding is shorter than RFC 8915 sec. 5.6 requires")
    nonce = body[4 : 4 + nonce_len]
    sealed = body[4 + nonce_padded : 4 + nonce_padded + ct_len]
    prefix = packet.extensions[:index]
    signed = packet.raw if packet.raw else encode_packet(packet)
    aad = signed[: HEADER_LENGTH + sum(e.length for e in prefix)]
    plaintext = siv_open(key, nonce, sealed, aad, aead_id=context.aead_id)
    try:
        return parse_extension_fields(plaintext)
    except PacketError as error:
        raise AuthenticationError("decrypted extension fields are malformed") from error


def verify(packet: NtpPacket, context: Negotiated) -> bool:
    """True when the authenticator verifies under the packet's direction key (RFC 8915 sec. 5.6)."""
    try:
        open_authenticator(packet, context)
    except AuthenticationError:
        return False
    return True


# --- kiss-o'-death and NTS NAK (RFC 8915 sec. 5.7, RFC 5905 sec. 7.4) -----------------------


class KodAction(enum.Enum):
    """What a client does with a kiss-o'-death packet (RFC 5905 sec. 7.4, RFC 8915 sec. 5.7)."""

    DEMOBILIZE = enum.auto()  # DENY, RSTR: demobilize the association and stop sending
    SLOW_DOWN = enum.auto()  # RATE: increase the polling interval, and again on each RATE
    NTS_NAK = enum.auto()  # NTSN: the server could not validate the cookie
    IGNORE = enum.auto()  # anything else: no protocol significance, discarded after inspection


class KodDiscardError(ValueError):
    """A kiss-o'-death packet that MUST be discarded without further processing."""


@dataclass(frozen=True, slots=True)
class KodResult:
    """A kiss code and the action it calls for.

    ``uid_matched`` is true when the packet carried a Unique Identifier equal to an outstanding
    request's. The receive and transmit timestamps of a KoD are not exposed: RFC 5905 sec. 7.4
    para 8 says they "MUST be discarded".
    """

    code: str
    action: KodAction
    uid_matched: bool


def _unique_identifiers(packet: NtpPacket) -> list[bytes]:
    return [e.value for e in packet.extensions if e.field_type == UNIQUE_IDENTIFIER]


def classify_kod(
    packet: NtpPacket,
    *,
    outstanding: Collection[bytes],
    previously_authentic: bool,
) -> KodResult:
    """Classify a stratum 0 packet and decide what it asks of the client.

    The kiss code is the reference identifier as ASCII (RFC 5905 sec. 7.3 para 24). Actions are
    those of sec. 7.4: DENY and RSTR demobilize; RATE slows the client (verified erratum 3007
    corrects "reduce its polling interval" to "increase": the client must poll less often); codes
    beginning with "X" are ignored when unrecognized; other codes are discarded after inspection.
    ``NTSN`` is the NTS NAK of RFC 8915 sec. 5.7 para 13, which "MUST NOT include any NTS Cookie or
    NTS Authenticator and Encrypted Extension Fields", so one that does is discarded.

    Para 14: if the server "has previously responded with authentic NTS-protected NTP packets, the
    client MUST verify that any KoD packets ... contain the Unique Identifier extension field and
    that the Unique Identifier matches that of an outstanding request"; failing that, the packet is
    discarded. ``previously_authentic`` says which case this is. A KoD seen before any authentic
    reply need not carry one (a server that never replied cannot be told from a forger), and when
    it does carry one that matches, ``uid_matched`` records it. One that carries a UID matching
    nothing is discarded either way.

    Raises:
        KodDiscardError: not a KoD, or one the rules above say to discard.
    """
    if packet.stratum != 0 or packet.mode != 4:
        raise KodDiscardError("not a server kiss-o'-death packet (stratum 0, mode 4)")
    code = packet.reference_id.rstrip(b"\x00").decode("ascii", errors="replace")
    uids = _unique_identifiers(packet)
    matched = any(uid in outstanding for uid in uids)
    if uids and not matched:
        raise KodDiscardError("the Unique Identifier matches no outstanding request")
    if previously_authentic and not matched:
        raise KodDiscardError(
            "after authentic replies a KoD must carry a matching Unique Identifier"
        )
    if code == "NTSN":
        banned = {COOKIE, NTS_AUTHENTICATOR}
        if any(e.field_type in banned for e in packet.extensions):
            raise KodDiscardError(
                "an NTS NAK carries no Cookie or Authenticator field (sec. 5.7 para 13)"
            )
        action = KodAction.NTS_NAK
    elif code in {"DENY", "RSTR"}:
        action = KodAction.DEMOBILIZE
    elif code == "RATE":
        action = KodAction.SLOW_DOWN
    else:
        action = KodAction.IGNORE  # includes unrecognized "X..." codes, which MUST be ignored
    return KodResult(code, action, matched)


class NakAction(enum.Enum):
    """What to do after an NTS NAK, as polling continues (RFC 8915 sec. 5.7 para 16)."""

    WAIT = enum.auto()  # keep polling with the cookies and parameters held
    RERUN_KE = enum.auto()  # no valid NTS reply arrived: negotiate fresh cookies, keys, parameters
    NOTHING = enum.auto()  # no NAK outstanding


class NakTracker:
    """The client's state after an NTS NAK (sec. 5.7 para 16).

    "Upon reception of the NTS NAK kiss code, the client SHOULD wait until the next poll for a
    valid NTS-protected response, and if none is received, initiate a fresh NTS-KE handshake ...
    As long as the NTS-KE handshake has not succeeded, the client SHOULD continue polling the NTP
    server using the cookies and parameters it has." The rate limit on rerunning NTS-KE (para 15)
    is ``ke.KeBackoff``'s.
    """

    def __init__(self) -> None:
        self._pending = False
        self._polled_since_nak = False

    def on_nak(self) -> None:
        self._pending = True
        self._polled_since_nak = False

    def on_poll(self, *, valid_nts_response: bool) -> NakAction:
        """Record the outcome of a poll made after a NAK and say what the client does next."""
        if not self._pending:
            return NakAction.NOTHING
        if valid_nts_response:
            self._pending = False  # the NAK was a transient; the held cookies still work
            return NakAction.NOTHING
        if not self._polled_since_nak:
            self._polled_since_nak = True
            return NakAction.WAIT
        return NakAction.RERUN_KE

    def on_ke_succeeded(self) -> None:
        """A fresh handshake ends the episode; ``CookieJar.renew`` discards the old cookies."""
        self._pending = False
        self._polled_since_nak = False
