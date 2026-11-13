"""AEAD sealing for NTS, the negotiated key set and key derivation helpers (RFC 8915, RFC 5297).

AES-SIV-CMAC comes from the ``cryptography`` package (``AESSIV``, documented at
https://cryptography.io/en/latest/hazmat/primitives/aead/, added in cryptography 37.0.0); the
standard library has no AES. The package is imported on first use, so the packet codec works
without it. The TLS exporter that NTS-KE needs (RFC 8915 sec. 5.1) is not available from
Python's ``ssl`` and is not provided here; ``exporter_context`` builds only its context value.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

__all__ = [
    "AEAD_AES_SIV_CMAC_256",
    "AEAD_AES_SIV_CMAC_384",
    "AEAD_AES_SIV_CMAC_512",
    "EXPORTER_LABEL",
    "AuthenticationError",
    "Negotiated",
    "exporter_context",
    "hkdf_sha256",
    "key_length",
    "siv_open",
    "siv_seal",
]

# AEAD registry numbers (RFC 5297 sec. 6, RFC 8915 sec. 4.1.5).
AEAD_AES_SIV_CMAC_256 = 15
AEAD_AES_SIV_CMAC_384 = 16
AEAD_AES_SIV_CMAC_512 = 17
_KEY_LENGTHS = {
    AEAD_AES_SIV_CMAC_256: 32,
    AEAD_AES_SIV_CMAC_384: 48,
    AEAD_AES_SIV_CMAC_512: 64,
}
EXPORTER_LABEL = b"EXPORTER-network-time-security"  # RFC 8915 sec. 5.1


class AuthenticationError(ValueError):
    """Authentication or decryption failed, or the AEAD algorithm is not supported."""


def key_length(aead_id: int) -> int:
    """K_LEN of a supported AEAD algorithm (RFC 5297 sec. 6.1 to 6.3)."""
    try:
        return _KEY_LENGTHS[aead_id]
    except KeyError:
        raise AuthenticationError(f"unsupported AEAD algorithm {aead_id}") from None


@dataclass(frozen=True)
class Negotiated:
    """What NTS-KE yields and a cookie carries: the AEAD id and the two keys (RFC 8915 sec. 5.1)."""

    aead_id: int
    c2s_key: bytes = field(repr=False)
    s2c_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        length = key_length(self.aead_id)
        if len(self.c2s_key) != length or len(self.s2c_key) != length:
            raise AuthenticationError(f"keys for AEAD {self.aead_id} are {length} octets")


def exporter_context(aead_id: int, *, s2c: bool) -> bytes:
    """The five-octet TLS exporter context for NTPv4 (RFC 8915 sec. 5.1).

    Two zero octets (Protocol ID 0), the AEAD id in network order, then 0x00 for the C2S key
    or 0x01 for the S2C key. Use it with ``EXPORTER_LABEL`` and a TLS exporter, which this
    package cannot supply.
    """
    return b"\x00\x00" + aead_id.to_bytes(2, "big") + (b"\x01" if s2c else b"\x00")


def _siv(key: bytes, aead_id: int):
    if len(key) != key_length(aead_id):
        raise AuthenticationError(f"AEAD {aead_id} needs a {key_length(aead_id)} octet key")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise AuthenticationError(
            "AES-SIV needs the cryptography package: pip install ntspy[crypto]"
        ) from error
    return AESSIV(key)


def siv_seal(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"", *, aead_id: int = 15
) -> bytes:
    """AEAD_AES_SIV_CMAC encrypt: the 16-octet SIV tag followed by the ciphertext.

    The associated data vector is ``[aad, nonce]`` (``[nonce]`` when ``aad`` is empty and the
    protocol says "no associated data"), because RFC 5297 sec. 3 makes the final component
    the nonce.
    """
    vector = [aad, nonce] if aad else [nonce]
    return _siv(key, aead_id).encrypt(plaintext, vector)


def siv_open(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"", *, aead_id: int = 15
) -> bytes:
    """Reverse ``siv_seal``; raises ``AuthenticationError`` when the tag does not verify."""
    vector = [aad, nonce] if aad else [nonce]
    try:
        return _siv(key, aead_id).decrypt(ciphertext, vector)
    except AuthenticationError:
        raise
    except Exception as error:
        raise AuthenticationError("AEAD authentication failed") from error


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF with SHA-256 (RFC 5869 sec. 2), on the standard library only."""
    if not 0 < length <= 255 * 32:
        raise ValueError("HKDF output length out of range")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]
