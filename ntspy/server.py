"""the server half: accept, mint cookies, authenticate responses.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ServerConfig = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "serve",
]


async def serve(config: ServerConfig) -> None:
    """Pending behaviour defined by RFC 8915.

    Not implemented yet. See the ``server.serve()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("serve() is not implemented: RFC 8915")
