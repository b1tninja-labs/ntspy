"""The on-wire arithmetic of RFC 5905 sec. 8: offset, delay, and the response sanity checks.

``offset_and_delay`` computes theta and delta from the four timestamps T1 to T4 with the
first-order differences taken in 64-bit integer arithmetic and the second-order sum in floating
point, which sec. 8 para 13 and 14 say restores the unambiguous range from 34 to 68 years.
``check_response`` applies the checks a client makes before it trusts a server reply:
the origin timestamp must match what the client sent (the "bogus" test of sec. 8 para 8), a
duplicate transmit timestamp is a replay, the mode must be 4, and an unsynchronized or
kiss-code server is refused.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from .packet import NtpPacket, NtpTimestamp
from .trust import LeapIndicator

__all__ = [
    "MAXSTRAT",
    "Offset",
    "ResponseCheck",
    "check_response",
    "offset_and_delay",
]

MAXSTRAT = 16  # RFC 5905 sec. 7.3 Figure 11: stratum 16 is "unsynchronized"
MODE_SERVER = 4
_WRAP = 1 << 64
_HALF = 1 << 63
_SCALE = 1 << 32


def _signed_difference(later: NtpTimestamp, earlier: NtpTimestamp) -> int:
    """``later - earlier`` in units of 2**-32 seconds, as a signed 64-bit quantity (sec. 8 para 13).

    The two 64-bit unsigned timestamps subtract modulo 2**64 and the result is read as signed, so
    a difference across the era boundary of 2036 is still right when the true value is within 68
    years.
    """
    raw = (later.to_int() - earlier.to_int()) % _WRAP
    return raw - _WRAP if raw >= _HALF else raw


@dataclass(frozen=True, slots=True)
class Offset:
    """Offset (theta) and round-trip delay (delta), in seconds (RFC 5905 sec. 8 para 9 to 12)."""

    offset: float
    delay: float


def offset_and_delay(
    t1: NtpTimestamp,
    t2: NtpTimestamp,
    t3: NtpTimestamp,
    t4: NtpTimestamp,
    *,
    precision: float = 0.0,
) -> Offset:
    """theta = ((T2 - T1) + (T3 - T4)) / 2 and delta = (T4 - T1) - (T3 - T2) (sec. 8 para 10, 12).

    T1 is the client's transmit time, T2 the server's receive time, T3 the server's transmit time
    and T4 the client's receive time. Negative delay "is misleading in subsequent computations", so
    sec. 8 para 15 says to clamp it to no less than the system precision rho (``precision``, in
    seconds); with the default of zero it is clamped at zero.
    """
    d21 = _signed_difference(t2, t1) / _SCALE
    d34 = _signed_difference(t3, t4) / _SCALE
    d41 = _signed_difference(t4, t1) / _SCALE
    d32 = _signed_difference(t3, t2) / _SCALE
    return Offset((d21 + d34) / 2, max(d41 - d32, precision))


class ResponseCheck(enum.Enum):
    """The outcome of ``check_response``: ``OK`` or why the reply is not to be used."""

    OK = enum.auto()
    NOT_A_SERVER_REPLY = enum.auto()  # mode is not 4
    BOGUS = enum.auto()  # origin timestamp differs from the one the client sent (sec. 8 para 8)
    DUPLICATE = enum.auto()  # the transmit timestamp matches the last one seen: a replay
    KISS_OF_DEATH = enum.auto()  # stratum 0: see ``extension.classify_kod``
    UNSYNCHRONIZED = enum.auto()  # LI 3 or stratum 16 or more: the server's clock is not set


def check_response(
    packet: NtpPacket,
    *,
    sent_transmit: NtpTimestamp,
    last_transmit: NtpTimestamp | None = None,
) -> ResponseCheck:
    """The sanity checks of RFC 5905 sec. 8 para 8 and sec. 7.3 on a server reply.

    ``sent_transmit`` is the transmit timestamp of the request (the client's T1) and must equal the
    reply's origin timestamp, else the reply is "bogus". ``last_transmit`` is the transmit
    timestamp of the previous accepted reply: a repeat is a duplicate or replay (verified erratum
    4121 clears up that the comparison is with the org state variable, which the caller keeps). A
    zero transmit timestamp is refused as unsynchronized-shaped (sec. 8 leaves it undefined). A
    kiss-o'-death packet (stratum 0) has undefined receive and transmit timestamps that "MUST be
    discarded" (sec. 7.4 para 8), so it is reported before any timestamp is trusted.
    """
    if packet.mode != MODE_SERVER:
        return ResponseCheck.NOT_A_SERVER_REPLY
    if packet.stratum == 0:
        return ResponseCheck.KISS_OF_DEATH
    if packet.origin != sent_transmit:
        return ResponseCheck.BOGUS
    if last_transmit is not None and packet.transmit == last_transmit:
        return ResponseCheck.DUPLICATE
    if (
        packet.leap == LeapIndicator.UNSYNCHRONIZED
        or packet.stratum >= MAXSTRAT
        or packet.transmit.is_zero
    ):
        return ResponseCheck.UNSYNCHRONIZED
    return ResponseCheck.OK
