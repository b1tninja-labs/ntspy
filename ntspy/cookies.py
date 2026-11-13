"""Issue and validate NTS cookies in the suggested format (RFC 8915 sec. 5.4 and 6).

Section 6 is non-normative: a cookie is the tuple (I, N, C). I is the identifier of the
server's master key K, N a random nonce, and C the AEAD encryption, under K with N and no
associated data, of the plaintext P (the AEAD algorithm id, the S2C key, the C2S key). This
module fixes one encoding of the tuple: I is 4 octets and N is 16 octets, so
``cookie = I || N || C``. Clients never parse cookies (sec. 5.4); only the issuing server does.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
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
    "MAX_PLACEHOLDERS",
    "TARGET_UNUSED",
    "CookieError",
    "CookieJar",
    "NeedKeyEstablishment",
    "RequestPlan",
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


# --- the client's cookie cache (RFC 8915 sec. 5.7) -------------------------------------------

TARGET_UNUSED = 8
"""Sec. 5.7 para 4: placeholders are sized so the client ends up holding eight unused cookies."""
MAX_PLACEHOLDERS = 7
"""Sec. 5.7 para 4: the client SHOULD NOT include more than seven placeholder fields."""


class NeedKeyEstablishment(CookieError):  # noqa: N818 - a state the caller acts on, not a failure
    """No unused cookie is left, so the client SHOULD rerun NTS-KE (sec. 5.7 para 3)."""


@dataclass(frozen=True, slots=True)
class RequestPlan:
    """What one NTS request carries: the cookie to send and how many placeholders to add."""

    cookie: bytes
    placeholders: int


class CookieJar:
    """The client's cookies for one NTP server, with the keys and parameters they belong to.

    A cookie is sent once and then dropped (sec. 5.7 para 3: "SHOULD avoid reusing a cookie"), unless
    the caller sets ``allow_reuse`` to favour resilience over unlinkability, in which case the last
    cookie is sent again when none is unused. Clients never parse cookies (sec. 5.4); to the jar a
    cookie is bytes.
    """

    def __init__(
        self,
        negotiated: Negotiated,
        cookies: Sequence[bytes],
        *,
        server: str | None = None,
        port: int = 123,
        allow_reuse: bool = False,
    ) -> None:
        self.negotiated = negotiated
        self.server = server
        self.port = port
        self.allow_reuse = allow_reuse
        self._unused: list[bytes] = [bytes(c) for c in cookies]
        self._last: bytes | None = None

    @property
    def unused(self) -> int:
        return len(self._unused)

    def needs_key_establishment(self) -> bool:
        """True when a request cannot be made without rerunning NTS-KE (sec. 5.7 para 3)."""
        return not self._unused and not (self.allow_reuse and self._last is not None)

    def plan_request(self, *, max_placeholders: int = MAX_PLACEHOLDERS) -> RequestPlan:
        """Take the next cookie and size the placeholders (sec. 5.7 para 3 to 5).

        With ``u`` unused cookies before the request, one is sent, ``N`` placeholders are added and
        the server returns ``N + 1``, so ``u - 1 + N + 1 = 8`` gives ``N = 8 - u``, capped at seven
        and at ``max_placeholders`` (sec. 5.7 para 5 allows fewer to avoid fragmentation).

        Raises:
            NeedKeyEstablishment: nothing unused is left and reuse is not allowed.
        """
        if not 0 <= max_placeholders <= MAX_PLACEHOLDERS:
            raise ValueError("max_placeholders is 0 to 7")
        if self._unused:
            placeholders = min(max(TARGET_UNUSED - len(self._unused), 0), max_placeholders)
            cookie = self._unused.pop(0)
            self._last = cookie
            return RequestPlan(cookie, placeholders)
        if self.allow_reuse and self._last is not None:
            return RequestPlan(self._last, 0)
        raise NeedKeyEstablishment("no unused cookie: rerun NTS-KE")

    def accept(self, cookies: Sequence[bytes], plan: RequestPlan) -> None:
        """Store the cookies of an authentic response to the request ``plan`` described.

        The server "MUST NOT exceed" one plus the number of placeholders it was sent (sec. 5.7
        para 9); more is a server error and is refused rather than stored.
        """
        if len(cookies) > plan.placeholders + 1:
            raise CookieError("the server returned more cookies than placeholders plus one")
        self._unused.extend(bytes(c) for c in cookies)

    def renew(self, negotiated: Negotiated, cookies: Sequence[bytes], **parameters: object) -> None:
        """Replace everything after a successful NTS-KE: the keys, parameters and cookies.

        Sec. 5.7 para 16: "If the NTS-KE handshake succeeds, the client MUST discard all old
        cookies and parameters and use the new ones instead." Until then, keep polling with what
        is held; this method is only called on success.
        """
        self.negotiated = negotiated
        self._unused = [bytes(c) for c in cookies]
        self._last = None
        for name, value in parameters.items():
            if name not in {"server", "port"}:
                raise TypeError(f"unknown parameter {name!r}")
            setattr(self, name, value)

    def snapshot(self) -> dict[str, object]:
        """A plain dict for persistent storage (sec. 5.7 para 17): keys, AEAD, server, unused cookies.

        It holds secrets; protecting the file is the caller's. Refuses to save a jar with no
        unused cookie, because that is what sec. 5.7 para 17 exists to avoid.
        """
        if not self._unused:
            raise NeedKeyEstablishment("nothing unused to keep for a later session restart")
        return {
            "aead_id": self.negotiated.aead_id,
            "c2s_key": self.negotiated.c2s_key.hex(),
            "s2c_key": self.negotiated.s2c_key.hex(),
            "server": self.server,
            "port": self.port,
            "cookies": [c.hex() for c in self._unused],
        }

    @classmethod
    def restore(cls, data: dict[str, object], *, allow_reuse: bool = False) -> CookieJar:
        """Rebuild a jar from ``snapshot`` output; anything malformed raises ``CookieError``."""
        try:
            negotiated = Negotiated(
                int(data["aead_id"]),  # type: ignore[call-overload]
                bytes.fromhex(str(data["c2s_key"])),
                bytes.fromhex(str(data["s2c_key"])),
            )
            cookies = [bytes.fromhex(str(c)) for c in data["cookies"]]  # type: ignore[attr-defined]
            server = data.get("server")
            return cls(
                negotiated,
                cookies,
                server=None if server is None else str(server),
                port=int(data.get("port", 123)),  # type: ignore[call-overload]
                allow_reuse=allow_reuse,
            )
        except (KeyError, ValueError, TypeError) as error:
            raise CookieError(f"the saved cookie state is malformed: {error}") from error
