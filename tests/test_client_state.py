"""The client's cookie cache and NTS NAK handling (RFC 8915 sec. 5.7), and the leap flags (RFC 5905 sec. 7.3).

Provenance: the counts follow sec. 5.7 para 3 to 5 directly (``N = 8 - u`` placeholders for ``u``
unused cookies, at most seven) and the NAK steps follow para 13 to 17; there is no RFC example to
copy. Packets are built here with the package's own codec and, for the KoD, hand-set stratum 0 and
reference identifier fields as sec. 7.4 describes.
"""

from __future__ import annotations

import pytest

from ntspy.auth import Negotiated
from ntspy.cookies import CookieError, CookieJar, NeedKeyEstablishment
from ntspy.extension import (
    COOKIE,
    NTS_AUTHENTICATOR,
    KodAction,
    KodDiscardError,
    NakAction,
    NakTracker,
    classify_kod,
    unique_identifier_field,
)
from ntspy.packet import ExtensionField, NtpPacket, NtpTimestamp
from ntspy.trust import (
    LeapIndicator,
    leap_indicator,
    leap_second_pending,
    usable_for_synchronization,
)

KEYS = Negotiated(15, bytes(range(32)), bytes(range(32, 64)))
NEW_KEYS = Negotiated(15, bytes(range(64, 96)), bytes(range(96, 128)))
Z = NtpTimestamp()


def cookies(n, tag=b"c"):
    return [tag + bytes([i]) * 7 for i in range(n)]


def test_client_cache_and_renewal():
    jar = CookieJar(KEYS, cookies(8), server="ntp.example", port=123)
    assert jar.unused == 8
    # eight held: send one, no placeholders needed (7 + 1 stays eight after one comes back)
    plan = jar.plan_request()
    assert plan.cookie == cookies(8)[0]  # the oldest first
    assert plan.placeholders == 0
    assert jar.unused == 7
    jar.accept([b"n" * 8], plan)  # the server returned N + 1 = 1 cookie
    assert jar.unused == 8
    # placeholders make up lost cookies: with 3 unused, send 1, add 5, expect 6 back, hold 8
    small = CookieJar(KEYS, cookies(3))
    plan = small.plan_request()
    assert plan.placeholders == 5
    small.accept(cookies(6, b"x"), plan)
    assert small.unused == 8
    # never more than seven placeholders, and fewer on request (fragmentation, sec. 5.7 para 5)
    one = CookieJar(KEYS, cookies(1))
    plan = one.plan_request()
    assert plan.placeholders == 7
    assert CookieJar(KEYS, cookies(1)).plan_request(max_placeholders=2).placeholders == 2
    # more cookies back than placeholders + 1 is a server error and is not stored
    with pytest.raises(CookieError, match="more cookies"):
        one.accept(cookies(9), plan)
    assert one.unused == 0
    # with none unused the client reruns NTS-KE (sec. 5.7 para 3), unless it allows reuse
    assert one.needs_key_establishment()
    with pytest.raises(NeedKeyEstablishment):
        one.plan_request()
    reuse = CookieJar(KEYS, cookies(1), allow_reuse=True)
    first = reuse.plan_request()
    assert not reuse.needs_key_establishment()
    assert reuse.plan_request().cookie == first.cookie  # resilience over unlinkability
    # a successful NTS-KE replaces keys, parameters and cookies wholesale (sec. 5.7 para 16)
    reuse.renew(NEW_KEYS, cookies(8, b"z"), server="other.example", port=124)
    assert reuse.negotiated is NEW_KEYS
    assert (reuse.server, reuse.port, reuse.unused) == ("other.example", 124, 8)
    assert reuse.plan_request().cookie == cookies(8, b"z")[0]
    with pytest.raises(TypeError):
        reuse.renew(NEW_KEYS, [], bogus=1)


def test_cookie_state_survives_a_restart():
    jar = CookieJar(KEYS, cookies(4), server="ntp.example", port=123)
    jar.plan_request()
    saved = jar.snapshot()  # sec. 5.7 para 17: keep unused cookies, keys, AEAD and parameters
    restored = CookieJar.restore(saved)
    assert restored.unused == 3
    assert restored.negotiated == KEYS
    assert (restored.server, restored.port) == ("ntp.example", 123)
    assert restored.plan_request().cookie == cookies(4)[1]
    empty = CookieJar(KEYS, [])
    with pytest.raises(NeedKeyEstablishment):
        empty.snapshot()
    for broken in ({}, {**saved, "c2s_key": "zz"}, {**saved, "cookies": 5}):
        with pytest.raises(CookieError, match="malformed"):
            CookieJar.restore(broken)


def kod(code: bytes, *extensions, mode=4, stratum=0):
    return NtpPacket(3, 4, mode, stratum, 0, 0, 0, 0, code, Z, Z, Z, Z, tuple(extensions))


UID = unique_identifier_field(bytes(range(40)))


def test_nts_nak_and_kiss_codes():
    outstanding = [UID.value]
    nak = classify_kod(kod(b"NTSN", UID), outstanding=outstanding, previously_authentic=True)
    assert (nak.code, nak.action, nak.uid_matched) == ("NTSN", KodAction.NTS_NAK, True)
    # the NAK itself MUST NOT carry a cookie or an authenticator (sec. 5.7 para 13)
    for banned in (COOKIE, NTS_AUTHENTICATOR):
        with pytest.raises(KodDiscardError, match="carries no Cookie"):
            classify_kod(
                kod(b"NTSN", UID, ExtensionField(banned, b"\x00" * 32)),
                outstanding=outstanding,
                previously_authentic=True,
            )
    # after authentic replies a KoD must carry the Unique Identifier of an outstanding request
    with pytest.raises(KodDiscardError, match="matching Unique Identifier"):
        classify_kod(kod(b"NTSN"), outstanding=outstanding, previously_authentic=True)
    # a UID matching nothing is discarded in either case
    other = unique_identifier_field(bytes(range(1, 41)))
    with pytest.raises(KodDiscardError, match="matches no outstanding"):
        classify_kod(kod(b"NTSN", other), outstanding=outstanding, previously_authentic=False)
    # before any authentic reply a bare NAK is classified but not marked as matched
    bare = classify_kod(kod(b"NTSN"), outstanding=outstanding, previously_authentic=False)
    assert bare.action is KodAction.NTS_NAK
    assert not bare.uid_matched
    # RFC 5905 sec. 7.4: DENY and RSTR demobilize, RATE slows (erratum 3007), others are inspected
    for code, action in (
        (b"DENY", KodAction.DEMOBILIZE),
        (b"RSTR", KodAction.DEMOBILIZE),
        (b"RATE", KodAction.SLOW_DOWN),
        (b"XFOO", KodAction.IGNORE),  # unregistered experimentation codes MUST be ignored
        (b"INIT", KodAction.IGNORE),  # no protocol significance: discarded after inspection
    ):
        result = classify_kod(kod(code), outstanding=outstanding, previously_authentic=False)
        assert result.action is action
        assert result.code == code.decode()
    # not a KoD at all
    for not_kod in (kod(b"NTSN", stratum=2), kod(b"NTSN", mode=3)):
        with pytest.raises(KodDiscardError, match="not a server"):
            classify_kod(not_kod, outstanding=outstanding, previously_authentic=False)


def test_nak_then_poll_then_rerun_ke():
    tracker = NakTracker()
    assert tracker.on_poll(valid_nts_response=False) is NakAction.NOTHING
    tracker.on_nak()
    # wait one poll; a valid NTS response ends the episode with the cookies still good
    assert tracker.on_poll(valid_nts_response=True) is NakAction.NOTHING
    tracker.on_nak()
    assert (
        tracker.on_poll(valid_nts_response=False) is NakAction.WAIT
    )  # keep polling with what we hold
    assert tracker.on_poll(valid_nts_response=False) is NakAction.RERUN_KE
    assert (
        tracker.on_poll(valid_nts_response=False) is NakAction.RERUN_KE
    )  # until the handshake succeeds
    tracker.on_ke_succeeded()
    assert tracker.on_poll(valid_nts_response=False) is NakAction.NOTHING


def packet(leap, stratum=2):
    return NtpPacket(leap, 4, 4, stratum, 0, 0, 0, 0, b"\0" * 4, Z, Z, Z, NtpTimestamp(5, 5))


def test_leap_and_stride_flags():
    assert leap_indicator(packet(0)) is LeapIndicator.NO_WARNING
    assert leap_indicator(packet(1)) is LeapIndicator.LAST_MINUTE_HAS_61_SECONDS
    assert leap_indicator(packet(2)) is LeapIndicator.LAST_MINUTE_HAS_59_SECONDS
    assert leap_indicator(packet(3)) is LeapIndicator.UNSYNCHRONIZED
    # erratum 4504: the warning concerns the last minute of the current day
    assert [leap_second_pending(packet(n)) for n in range(4)] == [0, 1, -1, 0]
    assert usable_for_synchronization(packet(0))
    assert usable_for_synchronization(packet(1))  # a pending leap second is not a reason to refuse
    assert not usable_for_synchronization(packet(3))  # the alarm condition
    assert not usable_for_synchronization(packet(0, stratum=16))
    assert not usable_for_synchronization(packet(0, stratum=0))
