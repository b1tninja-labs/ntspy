"""Issue and validate NTS cookies in the suggested format (RFC 8915 sec. 5.4 and 6).

Section 6 is non-normative: a cookie is the tuple (I, N, C). I is the identifier of the
server's master key K, N a random nonce, and C the AEAD encryption, under K with N and no
associated data, of the plaintext P (the AEAD algorithm id, the S2C key, the C2S key). This
module fixes one encoding of the tuple: I is 4 octets and N is 16 octets, so
``cookie = I || N || C``. Clients never parse cookies (sec. 5.4); only the issuing server does.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .auth import (
    AuthenticationError,
    Negotiated,
    hkdf_sha256,
    key_length,
    siv_open,
    siv_seal,
)

__all__ = [
    "CookieError",
    "ServerState",
    "mint",
    "ratchet",
    "validate",
]

_ID_LENGTH = 4
_NONCE_LENGTH = 16


class CookieError(ValueError):
    """A cookie that does not validate; the server answers with an NTS NAK (sec. 6)."""


@dataclass
class ServerState:
    """The server's master keys by identifier; ``current`` signs new cookies (sec. 6).

    Keys the server has not yet erased stay in ``keys`` so older cookies still validate.
    """

    current: bytes
    keys: dict[bytes, bytes] = field(default_factory=dict, repr=False)

    @classmethod
    def new(cls, *, key: bytes | None = None, key_id: bytes | None = None) -> ServerState:
        key_id = os.urandom(_ID_LENGTH) if key_id is None else key_id
        key = os.urandom(32) if key is None else key
        if len(key_id) != _ID_LENGTH:
            raise ValueError("key identifier is 4 octets")
        return cls(key_id, {key_id: key})

    def rotate(self, new_id: bytes | None = None) -> None:
        """Switch to a ratcheted key (sec. 6); the old key stays until ``erase`` is called."""
        new_id = os.urandom(_ID_LENGTH) if new_id is None else new_id
        self.keys[new_id] = ratchet(self.keys[self.current], new_id)
        self.current = new_id

    def erase(self, key_id: bytes) -> None:
        """Forget a key so its cookies stop validating (forward secrecy, sec. 6)."""
        if key_id == self.current:
            raise ValueError("cannot erase the current key")
        self.keys.pop(key_id, None)


def ratchet(previous_key: bytes, key_id: bytes) -> bytes:
    """A successor key: HKDF (RFC 5869) over the old key with the new key id as salt (sec. 6)."""
    return hkdf_sha256(previous_key, key_id, b"", len(previous_key))


def mint(state: ServerState, negotiated: Negotiated, *, nonce: bytes | None = None) -> bytes:
    """Form a cookie for ``negotiated`` under the current master key (RFC 8915 sec. 5.4, sec. 6)."""
    nonce = os.urandom(_NONCE_LENGTH) if nonce is None else nonce
    if len(nonce) != _NONCE_LENGTH:
        raise ValueError("cookie nonce is 16 octets")
    plaintext = negotiated.aead_id.to_bytes(2, "big") + negotiated.s2c_key + negotiated.c2s_key
    sealed = siv_seal(state.keys[state.current], nonce, plaintext, b"")
    return state.current + nonce + sealed


def validate(cookie: bytes, state: ServerState) -> Negotiated:
    """Recover the AEAD id and keys from a cookie, or raise ``CookieError`` (RFC 8915 sec. 5.4, sec. 6)."""
    if len(cookie) < _ID_LENGTH + _NONCE_LENGTH + 16:
        raise CookieError("cookie is too short")
    key_id = cookie[:_ID_LENGTH]
    nonce = cookie[_ID_LENGTH : _ID_LENGTH + _NONCE_LENGTH]
    sealed = cookie[_ID_LENGTH + _NONCE_LENGTH :]
    key = state.keys.get(key_id)
    if key is None:
        raise CookieError("unknown or erased master key")
    try:
        plaintext = siv_open(key, nonce, sealed, b"")
    except AuthenticationError as error:
        raise CookieError("cookie does not authenticate") from error
    if len(plaintext) < 2:
        raise CookieError("cookie plaintext is too short")
    aead_id = int.from_bytes(plaintext[:2], "big")
    try:
        length = key_length(aead_id)
    except AuthenticationError as error:
        raise CookieError("cookie names an unsupported AEAD algorithm") from error
    if len(plaintext) != 2 + 2 * length:
        raise CookieError("cookie plaintext has the wrong length")
    s2c = plaintext[2 : 2 + length]
    c2s = plaintext[2 + length :]
    return Negotiated(aead_id, c2s, s2c)
