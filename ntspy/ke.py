"""key establishment records and notifications (RFC 8915).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    KeRecord = Any  # placeholder: give it a real type in the milestone that needs it
    Negotiated = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "encode_record",
    "establish",
]


def encode_record(record: KeRecord) -> bytes:
    """Pending behaviour defined by RFC 8915 sec. 4.1.

    Not implemented yet. See the ``ke.encode_record()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_record() is not implemented: RFC 8915 sec. 4.1")


async def establish(server: str, port: int) -> Negotiated:
    """Pending behaviour defined by RFC 8915 sec. 4.

    Not implemented yet. See the ``ke.establish()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("establish() is not implemented: RFC 8915 sec. 4")
