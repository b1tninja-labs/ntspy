"""issue, validate, cache and renew (RFC 8915).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Negotiated = Any  # placeholder: give it a real type in the milestone that needs it
    ServerState = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "mint",
    "validate",
]


def mint(state: ServerState, aead_key: bytes) -> bytes:
    """Pending behaviour defined by RFC 8915.

    Not implemented yet. See the ``cookies.mint()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("mint() is not implemented: RFC 8915")


def validate(cookie: bytes, state: ServerState) -> Negotiated:
    """Pending behaviour defined by RFC 8915.

    Not implemented yet. See the ``cookies.validate()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("validate() is not implemented: RFC 8915")
