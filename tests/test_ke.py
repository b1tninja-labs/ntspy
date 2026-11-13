"""NTS-KE records, request and response rules, ALPN and retry intervals (RFC 8915 sec. 3, 4).

Provenance: RFC 8915 prints no encoded NTS-KE message, so every octet string here is assembled
by hand from Figure 2 (the critical bit is the top bit of the first octet, the next 15 bits the
type, then a 16-bit body length) and the record rules of sec. 4.1. The ALPN test runs a real TLS 1.3
handshake over a socket pair with a certificate minted by ``cryptography``. No vendor capture.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading

import pytest

from ntspy.ke import (
    ALPN_NTSKE,
    KeBackoff,
    KeError,
    KeRecord,
    RecordType,
    build_request,
    decode_records,
    encode_record,
    parse_response,
    retry_interval,
    tls_context,
)

EOM = bytes.fromhex("80000000")
NPN_NTPV4 = bytes.fromhex("8001 0002 0000")
AEAD_15 = bytes.fromhex("0004 0002 000f")
COOKIE_A = bytes.fromhex("0005 0004") + b"\x01\x02\x03\x04"
COOKIE_B = bytes.fromhex("0005 0003") + b"\xaa\xbb\xcc"  # bodies need not be word aligned


def test_encode_record():
    assert encode_record(KeRecord(RecordType.END_OF_MESSAGE, critical=True)) == EOM
    assert (
        encode_record(KeRecord(RecordType.NEXT_PROTOCOL, b"\x00\x00", critical=True)) == NPN_NTPV4
    )
    # the critical bit is the most significant bit of the first octet; the type fills the other 15
    assert encode_record(KeRecord(0x7FFF, b"x", critical=True)) == bytes.fromhex("ffff 0001 78")
    assert encode_record(KeRecord(0x1234, b"", critical=False)) == bytes.fromhex("1234 0000")
    with pytest.raises(KeError):
        KeRecord(0x8000)
    with pytest.raises(KeError):
        KeRecord(1, b"\x00" * 0x10000)


def test_decode_records():
    data = NPN_NTPV4 + AEAD_15 + COOKIE_A + COOKIE_B + EOM
    records = decode_records(data)
    assert [r.record_type for r in records] == [1, 4, 5, 5, 0]
    assert [r.critical for r in records] == [True, False, False, False, True]
    assert records[3].body == b"\xaa\xbb\xcc"
    assert b"".join(encode_record(r) for r in records) == data  # the codec round-trips
    for bad in (
        b"",  # nothing, not even End of Message
        NPN_NTPV4,  # no End of Message
        NPN_NTPV4 + bytes.fromhex("8000 0001 00"),  # End of Message with a body
        NPN_NTPV4 + bytes.fromhex("0000 0000"),  # End of Message without the critical bit
        NPN_NTPV4 + EOM + b"\x00",  # octets after the End of Message
        bytes.fromhex("8001 0004 0000"),  # a body that runs past the data
        bytes.fromhex("8001 00"),  # a truncated header
    ):
        with pytest.raises(KeError):
            decode_records(bad)
    with pytest.raises(KeError, match="limit"):
        decode_records(NPN_NTPV4 + EOM, max_octets=8)


def test_request_follows_the_client_rules():
    request = build_request()
    assert request == NPN_NTPV4 + AEAD_15 + EOM
    records = decode_records(request)
    kinds = [r.record_type for r in records]
    # exactly one NPN, one AEAD (protocol 0 offered), and nothing a client MUST NOT send
    assert kinds == [RecordType.NEXT_PROTOCOL, RecordType.AEAD_ALGORITHM, RecordType.END_OF_MESSAGE]
    assert not {RecordType.ERROR, RecordType.WARNING, RecordType.NEW_COOKIE} & set(kinds)
    full = decode_records(build_request(aead=(17, 15), server="time.example.org", port=123))
    assert full[1].body == bytes.fromhex("0011 000f")  # preference order is kept
    assert full[2].body == b"time.example.org"
    assert full[3].body == bytes.fromhex("007b")
    assert not full[2].critical
    assert not full[3].critical  # clients SHOULD NOT set it (sec. 4.1.7, 4.1.8)
    assert decode_records(build_request(server="2001:db8::1"))[2].body == b"2001:db8::1"
    assert len(build_request(server="a" * 200)) < 1024  # servers MUST accept at least 1024 octets
    for bad in (
        {"protocols": ()},
        {"aead": ()},  # protocol 0 needs the AEAD record
        {"server": ""},
        {"server": "zeitä.example"},  # must be an A-label
        {"port": 0},
        {"port": 70000},
    ):
        with pytest.raises(KeError):
            build_request(**bad)


def response(*parts: bytes) -> bytes:
    return b"".join(parts) + EOM


def test_response_validation():
    ok = parse_response(response(NPN_NTPV4, AEAD_15, COOKIE_A, COOKIE_B))
    assert ok.protocols == (0,)
    assert ok.aead == 15
    assert ok.cookies == (b"\x01\x02\x03\x04", b"\xaa\xbb\xcc")
    assert ok.server is None
    assert ok.port is None
    withextra = parse_response(
        response(
            NPN_NTPV4,
            AEAD_15,
            bytes.fromhex("0006 0007") + b"ntp.foo",
            bytes.fromhex("0007 0002 007c"),
            COOKIE_A,
            bytes.fromhex("1234 0001 00"),  # unrecognized, non-critical: ignored
        )
    )
    assert (withextra.server, withextra.port, withextra.ignored) == ("ntp.foo", 124, (0x1234,))
    # an empty AEAD record and an empty protocol list mean the server accepts nothing (sec. 4.1)
    assert (
        parse_response(response(bytes.fromhex("8001 0000"), bytes.fromhex("0004 0000"))).protocols
        == ()
    )
    empty_aead = parse_response(response(NPN_NTPV4, bytes.fromhex("0004 0000")))
    assert empty_aead.aead is None
    assert empty_aead.cookies == ()
    for message, why in (
        (response(bytes.fromhex("8002 0002 0001")), "bad request"),  # Error 1
        (response(bytes.fromhex("8002 0002 0002")), "internal server error"),
        (response(bytes.fromhex("8002 0001 00")), "two octets"),
        (response(bytes.fromhex("8003 0002 0000"), NPN_NTPV4, AEAD_15, COOKIE_A), "Warning"),
        (response(AEAD_15, COOKIE_A), "no Next Protocol"),
        (response(NPN_NTPV4, NPN_NTPV4, AEAD_15, COOKIE_A), "two Next Protocol"),
        (response(bytes.fromhex("0001 0002 0000"), AEAD_15, COOKIE_A), "must be critical"),
        (response(NPN_NTPV4, AEAD_15, AEAD_15, COOKIE_A), "two AEAD"),
        (response(NPN_NTPV4, AEAD_15), "no New Cookie"),
        (response(NPN_NTPV4, COOKIE_A), "no AEAD Algorithm record"),
        (response(bytes.fromhex("8001 0002 0001"), AEAD_15, COOKIE_A), "did not offer"),
        (response(NPN_NTPV4, bytes.fromhex("0004 0002 0011"), COOKIE_A), "did not offer"),
        (response(NPN_NTPV4, bytes.fromhex("0004 0004 000f 0011"), COOKIE_A), "more than one"),
        (response(NPN_NTPV4, AEAD_15, COOKIE_A, bytes.fromhex("8123 0000")), "critical"),
        (
            response(
                NPN_NTPV4,
                AEAD_15,
                COOKIE_A,
                bytes.fromhex("0006 0001 41"),
                bytes.fromhex("0006 0001 42"),
            ),
            "two NTPv4 Server",
        ),
        (response(NPN_NTPV4, AEAD_15, COOKIE_A, bytes.fromhex("0007 0001 00")), "two octets"),
        (response(NPN_NTPV4, AEAD_15, COOKIE_A, bytes.fromhex("0006 0005") + b"fe80%"), "zone"),
    ):
        with pytest.raises(KeError, match=why):
            parse_response(message)


def test_retry_interval_and_backoff():
    # sec. 4.2: t = min(10 * 1.5^(n-1), 432000)
    assert retry_interval(1) == 10
    assert retry_interval(2) == 15
    assert retry_interval(3) == 22.5
    assert retry_interval(60) == 432000  # five days
    with pytest.raises(ValueError, match="from 1"):
        retry_interval(0)
    backoff = KeBackoff()
    assert [backoff.failed() for _ in range(3)] == [10, 15, 22.5]
    backoff.ke_succeeded()  # a handshake alone does not reset the interval
    backoff.next_protocol_succeeded()  # ... successful use of the next protocol does
    assert backoff.attempts == 0
    backoff.failed()
    backoff.next_protocol_succeeded()  # no successful KE this round: nothing resets
    assert backoff.attempts == 1
    backoff.ke_succeeded()
    assert backoff.failed() == 15  # a failure after the handshake restarts the proof


def test_tls_context_is_tls13_with_the_ntske_alpn_and_negotiates_it():
    context = tls_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    crypto = pytest.importorskip("cryptography")
    assert crypto
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nts.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("nts.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    import pathlib
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        cert_path = pathlib.Path(directory, "c.pem")
        key_path = pathlib.Path(directory, "k.pem")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
        server_ctx.set_alpn_protocols([ALPN_NTSKE])
        client_ctx = tls_context(cafile=str(cert_path))
        a, b = socket.socketpair()
        seen = {}

        def serve():
            with server_ctx.wrap_socket(a, server_side=True) as s:
                seen["alpn"] = s.selected_alpn_protocol()
                seen["data"] = s.recv(4096)
                s.sendall(response(NPN_NTPV4, AEAD_15, COOKIE_A))

        thread = threading.Thread(target=serve)
        thread.start()
        with client_ctx.wrap_socket(b, server_hostname="nts.example") as c:
            assert c.version() == "TLSv1.3"
            assert c.selected_alpn_protocol() == "ntske/1"
            c.sendall(build_request())
            reply = c.recv(4096)
        thread.join(10)
    assert seen["alpn"] == "ntske/1"
    assert seen["data"] == build_request()
    assert parse_response(reply).cookies == (b"\x01\x02\x03\x04",)
