"""the NTS authenticator and unique identifier fields (RFC 8915).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Negotiated = Any  # placeholder: give it a real type in the milestone that needs it
    NtpPacket = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "authenticate",
    "verify",
]


def authenticate(packet: NtpPacket, context: Negotiated) -> NtpPacket:
    """Pending behaviour defined by RFC 8915.

    Not implemented yet. See the ``extension.authenticate()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("authenticate() is not implemented: RFC 8915")


def verify(packet: NtpPacket, context: Negotiated) -> bool:
    """Pending behaviour defined by RFC 8915.

    Not implemented yet. See the ``extension.verify()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify() is not implemented: RFC 8915")
