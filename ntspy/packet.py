"""NTPv4 header, extension fields and timestamp arithmetic (RFC 5905, RFC 9748).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    NtpPacket = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_packet",
    "encode_packet",
]


def decode_packet(raw: bytes) -> NtpPacket:
    """Pending behaviour defined by RFC 5905 sec. 7.3, sec. 7.5.

    Not implemented yet. See the ``packet.decode_packet()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_packet() is not implemented: RFC 5905 sec. 7.3, sec. 7.5")


def encode_packet(packet: NtpPacket) -> bytes:
    """Pending behaviour defined by RFC 5905 sec. 7.3, sec. 7.5.

    Not implemented yet. See the ``packet.encode_packet()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_packet() is not implemented: RFC 5905 sec. 7.3, sec. 7.5")
