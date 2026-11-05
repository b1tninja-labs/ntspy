"""ntspy -- Network Time Security on asyncio.

Authenticated time is a solved problem on paper and absent in Python.
"""

from __future__ import annotations

from . import apps, auth, cli, client, cookies, extension, ke, packet, server, trust
from .client import synchronize
from .cookies import mint, validate
from .extension import authenticate, verify
from .ke import encode_record, establish
from .packet import decode_packet, encode_packet
from .server import serve

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "auth",
    "authenticate",
    "cli",
    "client",
    "cookies",
    "decode_packet",
    "encode_packet",
    "encode_record",
    "establish",
    "extension",
    "ke",
    "mint",
    "packet",
    "serve",
    "server",
    "synchronize",
    "trust",
    "validate",
    "verify",
]
