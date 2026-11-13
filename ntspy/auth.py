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
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from .packet import Mac, NtpPacket, encode_packet

__all__ = [
    "AEAD_AES_SIV_CMAC_256",
    "AEAD_AES_SIV_CMAC_384",
    "AEAD_AES_SIV_CMAC_512",
    "CMAC_KEY_LENGTH",
    "CMAC_TAG_LENGTH",
    "EXPORTER_LABEL",
    "AuthenticationError",
    "Negotiated",
    "aes_cmac",
    "exporter_context",
    "hkdf_sha256",
    "key_length",
    "sign_mac",
    "siv_open",
    "siv_seal",
    "verify_mac",
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


# --- symmetric-key MAC with AES-CMAC (RFC 8573) ---------------------------------------------

CMAC_KEY_LENGTH = 16
"""RFC 8573 sec. 3: "The MAC key for NTP MUST be an AES-128 key that is 128 bits in length"."""
CMAC_TAG_LENGTH = 16
"""RFC 8573 sec. 3: the tag "MUST be at least 128 bits"; AES-CMAC produces exactly 128."""


def aes_cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC (RFC 4493) of ``data`` under a 128-bit key, from ``cryptography``.

    RFC 8573 sec. 3 wants a 16-octet key; any other length is refused here instead of being
    accepted as AES-192 or AES-256, which RFC 8573 does not allow for NTP.
    """
    if len(key) != CMAC_KEY_LENGTH:
        raise AuthenticationError(
            f"an NTP AES-CMAC key is {CMAC_KEY_LENGTH} octets (RFC 8573 sec. 3)"
        )
    try:
        from cryptography.hazmat.primitives import cmac
        from cryptography.hazmat.primitives.ciphers import algorithms
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise AuthenticationError(
            "AES-CMAC needs the cryptography package: pip install ntspy[crypto]"
        ) from error
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(data)
    return mac.finalize()


def _mac_input(packet: NtpPacket) -> bytes:
    """The header and every extension field as they would be sent, without the MAC (RFC 8573 sec. 3)."""
    header = encode_packet(replace(packet, extensions=(), mac=None, raw=b""))
    return header + b"".join(e.encode() for e in packet.extensions)


def sign_mac(packet: NtpPacket, key_id: int, key: bytes) -> NtpPacket:
    """Append the RFC 8573 MAC: the 4-octet key identifier and the AES-CMAC of the packet.

    "AES-CMAC ... MUST be computed over all fields in the NTP header and any extension fields
    that are present". The key identifier is not part of the input (it is the MAC's own header, as
    in RFC 5905 sec. 7.3 where the digest follows it). Returns the packet with ``mac`` set and
    ``raw`` re-encoded.
    """
    if packet.mac is not None:
        raise ValueError("the packet already carries a MAC")
    if not 0 <= key_id <= 0xFFFFFFFF:
        raise ValueError("key identifier does not fit 32 bits")
    tag = aes_cmac(key, _mac_input(packet))
    signed = replace(packet, mac=Mac(key_id, tag), raw=b"")
    return replace(signed, raw=encode_packet(signed))


def verify_mac(packet: NtpPacket, keys: Mapping[int, bytes]) -> bool:
    """True when the packet's MAC is the AES-CMAC under the key its identifier names.

    ``keys`` maps key identifiers to 16-octet AES-CMAC keys. A packet with no MAC, an identifier
    with no key, a digest that is not the 16-octet CMAC tag (a 20-octet digest is an MD5 or SHA-1
    shape, which this check never accepts) or a wrong tag is simply ``False``. The comparison is
    constant time. The MAC is checked over the octets as received when ``raw`` is present.
    """
    mac = packet.mac
    if mac is None or len(mac.digest) != CMAC_TAG_LENGTH:
        return False
    key = keys.get(mac.key_id)
    if key is None or len(key) != CMAC_KEY_LENGTH:
        return False
    if packet.raw:
        signed = packet.raw[: len(packet.raw) - 4 - CMAC_TAG_LENGTH]
    else:
        signed = _mac_input(packet)
    return hmac.compare_digest(aes_cmac(key, signed), mac.digest)
