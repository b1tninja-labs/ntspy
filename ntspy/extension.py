"""The NTS extension fields: unique identifier, cookie, placeholder, authenticator (RFC 8915 sec. 5).

``authenticate`` appends the NTS Authenticator and Encrypted Extension Fields field to a packet
(sec. 5.6); ``verify`` and ``open_authenticator`` check it. Both use the key for the packet's
direction: the C2S key for mode 3, the S2C key for mode 4. The packet passed to ``authenticate``
must hold, in ``extensions``, exactly the fields that are to be authenticated but not encrypted.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Sequence
from dataclasses import replace

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
    "authenticate",
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
