"""The leap indicator and the flags a client must not silently ignore (RFC 5905 sec. 7.3).

The local trust store this module was named for is not built: NTS-KE server verification is the
TLS context's (``ke.tls_context``). What is here is the two-bit leap indicator, read with verified
erratum 4504, and the small policy functions over it. ROADMAP.md row ``trust.leap-and-stride-flags``
says what is done; the "stride" half of that row name has no text in RFC 5905 or RFC 8915 that
this project could find, and is recorded there as unresolved.
"""

from __future__ import annotations

import enum

from .packet import NtpPacket

__all__ = [
    "LeapIndicator",
    "leap_indicator",
    "leap_second_pending",
    "usable_for_synchronization",
]


class LeapIndicator(enum.IntEnum):
    """The two-bit LI field (RFC 5905 sec. 7.3, Figure 9) read with erratum 4504.

    Verified erratum 4504 corrects the text before Figure 9: the warning is about "the last
    minute of the current day" (the figure said day; the paragraph said month). So a value of 1 or
    2 announces a leap second at the end of the current UTC day, not at some point in the month.
    """

    NO_WARNING = 0
    LAST_MINUTE_HAS_61_SECONDS = 1
    LAST_MINUTE_HAS_59_SECONDS = 2
    UNSYNCHRONIZED = 3  # "unknown (clock unsynchronized)"


def leap_indicator(packet: NtpPacket) -> LeapIndicator:
    """The packet's LI as a ``LeapIndicator``; a 2-bit value is always one of the four."""
    return LeapIndicator(packet.leap)


def leap_second_pending(packet: NtpPacket) -> int:
    """``+1`` when the last minute of the day has 61 seconds, ``-1`` for 59, else ``0``.

    LI 3 says nothing about a leap second, only that the server's clock is not synchronized, so
    it is ``0`` here: ``usable_for_synchronization`` is the check that refuses such a server.
    """
    return {
        LeapIndicator.LAST_MINUTE_HAS_61_SECONDS: 1,
        LeapIndicator.LAST_MINUTE_HAS_59_SECONDS: -1,
    }.get(leap_indicator(packet), 0)


def usable_for_synchronization(packet: NtpPacket) -> bool:
    """False when the leap indicator is 3 ("clock unsynchronized") or the stratum is 0 or 16 and up.

    A server in the alarm condition must not be used as a time source, and the leap value 1 or 2
    must not be silently dropped either: callers read ``leap_second_pending`` for those.
    """
    return packet.leap != LeapIndicator.UNSYNCHRONIZED and 1 <= packet.stratum < 16
