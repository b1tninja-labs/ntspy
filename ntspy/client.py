"""the asyncio client: establish, query, verify, re-establish.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Sample = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "synchronize",
]


async def synchronize(servers: list, attempts: int) -> Sample:
    """Pending behaviour defined by RFC 8915, RFC 8633.

    Not implemented yet. See the ``client.synchronize()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("synchronize() is not implemented: RFC 8915, RFC 8633")
