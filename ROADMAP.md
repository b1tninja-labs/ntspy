# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation ntspy could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `packet.decode_packet()` | RFC 5905 sec. 7.3, RFC 7822 sec. 3 | `[ok]` | `tests/test_packet.py::test_decode_server_response_vector` | M1 |
| `packet.encode_packet()` | RFC 5905 sec. 7.3, RFC 7822 sec. 3 | `[ok]` | `tests/test_packet.py::test_round_trip_is_byte_identical` | M1 |
| `packet.parse_extension_fields()` | RFC 8915 sec. 5.6 (short encrypted fields), RFC 7822 sec. 3 | `[ok]` | `tests/test_extension.py::test_encrypted_extension_fields_come_back_decrypted` | M1 |
| `packet.ntp_short_to_seconds()` | RFC 5905 sec. 7.3 | `[ok]` | `tests/test_packet.py::test_decode_server_response_vector` | M1 |
| `packet.tail-split-mac-vs-extension` | RFC 7822 sec. 3 (7.5.1.3, 7.5.1.4): under 28 octets remaining, a 20 or 24 octet tail is a MAC | `[ok]` | `tests/test_packet.py::test_a_24_octet_tail_is_a_mac_not_a_short_field` | M1 |
| `packet.fuzz-hostile-input` | RFC 7822 sec. 3 | `[ok]` | `tests/test_packet.py::test_fuzz_random_buffers_never_raise_anything_but_packet_error` | M1 |
| `auth.siv_seal()` | RFC 5297 sec. 3, 6.1 via `cryptography.AESSIV` | `[ok]` | `tests/test_auth.py::test_rfc5297_a2_nonce_based_vector_through_cryptography` | M2 |
| `auth.siv_open()` | RFC 5297 sec. 2.7, 3 | `[ok]` | `tests/test_auth.py::test_siv_open_rejects_tampering_and_wrong_key` | M2 |
| `auth.hkdf_sha256()` | RFC 5869 sec. 2, A.1 | `[ok]` | `tests/test_auth.py::test_hkdf_rfc5869_a1` | M4 |
| `auth.exporter_context()` | RFC 8915 sec. 5.1 (context value only; the exporter itself is `[no]`, below) | `[ok]` | `tests/test_auth.py::test_exporter_context_is_five_octets_rfc8915_5_1` | M3 |
| `extension.authenticate()` | RFC 8915 sec. 5.6 | `[ok]` | `tests/test_extension.py::test_authenticate_then_verify_round_trip_through_the_wire` | M2 |
| `extension.verify()` | RFC 8915 sec. 5.6 | `[ok]` | `tests/test_extension.py::test_tampering_with_header_or_authenticated_field_fails` | M2 |
| `extension.open_authenticator()` | RFC 8915 sec. 5.6 | `[ok]` | `tests/test_extension.py::test_encrypted_extension_fields_come_back_decrypted` | M2 |
| `extension.unique_identifier_field()` | RFC 8915 sec. 5.3 | `[ok]` | `tests/test_extension.py::test_unique_identifier_is_at_least_32_random_octets` | M2 |
| `extension.placeholder_field()` | RFC 8915 sec. 5.5 | `[ok]` | `tests/test_extension.py::test_placeholder_has_the_same_body_length_as_the_cookie` | M2 |
| `extension.additional-padding` | RFC 8915 sec. 5.6: verify enforces N_REQ; `authenticate` emits 16 octet nonces only and never pads for a shorter one | `[part]` | `tests/test_extension.py::test_short_nonce_in_a_client_packet_needs_additional_padding` | M2 |
| `extension.nts-nak-kod` | RFC 8915 sec. 5.7 para 13 to 16 and RFC 5905 sec. 7.4: `classify_kod` (NTSN carries no cookie or authenticator, a KoD after authentic replies needs a matching Unique Identifier, DENY/RSTR demobilize, RATE slows, X codes ignored) and `NakTracker` (wait one poll, then rerun NTS-KE). Not done: discarding the unauthenticated extension fields of a response (para 11), which belongs with a receive path | `[part]` | `tests/test_client_state.py::test_nts_nak_and_kiss_codes`, `tests/test_client_state.py::test_nak_then_poll_then_rerun_ke` | M5 |
| `extension.discard-unauthenticated` | RFC 8915 sec. 5.7 para 7 and 11: a server or client MUST discard extension fields that are neither authenticated nor encrypted; a receive path that returns only the authenticated fields | `[ ]` | `tests/test_extension.py::test_unauthenticated_fields_are_dropped` (to be written) | M5 |
| `client.rate-slow-down` | RFC 5905 sec. 7.4 b with verified erratum 3007: on every RATE kiss code the client increases its polling interval (the printed text says reduce); the poll scheduler that acts on `KodAction.SLOW_DOWN` is not written | `[ ]` | `tests/test_client.py::test_rate_increases_the_poll_interval` (to be written) | M3 |
| `cookies.mint()` | RFC 8915 sec. 5.4, sec. 6 (suggested format, 4 octet id, 16 octet nonce) | `[ok]` | `tests/test_cookies.py::test_cookie_layout_is_id_nonce_ciphertext` | M4 |
| `cookies.validate()` | RFC 8915 sec. 5.4, sec. 6 | `[ok]` | `tests/test_cookies.py::test_mint_then_validate_recovers_the_negotiated_keys` | M4 |
| `cookies.ratchet()` | RFC 8915 sec. 6 with RFC 5869 | `[part]` | `tests/test_cookies.py::test_old_cookie_still_validates_after_rotation_until_erased` (no independent vector for the ratchet; HKDF itself is pinned by RFC 5869 A.1) | M4 |
| `cookies.client-cache-and-renewal` | RFC 8915 sec. 5.7 para 3 to 5, 9, 16, 17: `CookieJar` (one cookie per request, `8 - u` placeholders capped at seven, more cookies back than placeholders plus one refused, rerun NTS-KE when none is unused, renewal discards everything, a snapshot for session restart) | `[ok]` | `tests/test_client_state.py::test_client_cache_and_renewal`, `tests/test_client_state.py::test_cookie_state_survives_a_restart` | M4 |
| `ke.encode_record()` | RFC 8915 sec. 4.1 | `[ok]` | `tests/test_ke.py::test_encode_record` | M3 |
| `ke.decode-records` | RFC 8915 sec. 4 (critical bit, 15-bit type, 16-bit body length, exactly one critical empty End of Message that ends the message) | `[ok]` | `tests/test_ke.py::test_decode_records` | M3 |
| `ke.request-build` | RFC 8915 sec. 4 and 4.1.2, 4.1.5, 4.1.7, 4.1.8: the client request (NPN critical, AEAD for protocol 0, optional server and port, nothing a client MUST NOT send) | `[ok]` | `tests/test_ke.py::test_request_follows_the_client_rules` | M3 |
| `ke.response-validate` | RFC 8915 sec. 4.1.1 to 4.1.8: Error and Warning records are errors, an unrecognized critical record is an error and a non-critical one ignored, one NPN, a subset of the offered protocols, at most one AEAD, a cookie when NTPv4 is negotiated | `[ok]` | `tests/test_ke.py::test_response_validation` | M3 |
| `ke.retry-interval` | RFC 8915 sec. 4.2: `min(10 * 1.5**(n-1), 432000)`, and no reset until a successful handshake is followed by successful use of the next protocol | `[ok]` | `tests/test_ke.py::test_retry_interval_and_backoff` | M3 |
| `ke.server-side` | the NTS-KE server half: parse a request, answer with Error 0 for an unrecognized critical record and Error 1 for a malformed one (sec. 4.1.3), choose the AEAD, mint cookies, send eight (sec. 4.1.6); the keys again need the exporter, so the key-dependent part is blocked | `[ ]` | `tests/test_ke.py::test_server_answers_errors` (to be written) | M5 |
| `ke.server-record-semantics` | RFC 8915 sec. 4.1.7: the recipient treats a domain name as a FQDN (ends with a dot), A-labels for internationalized names, IPv6 without a zone. Parsing checks ASCII and the zone; nothing normalizes the FQDN | `[part]` | `tests/test_ke.py::test_response_validation` | M3 |
| `ke.establish()` | RFC 8915 sec. 4 | `[ ]` | `tests/test_obligations.py::test_establish` (to be written) | M3 |
| `ke.tls-exporter` | RFC 8915 sec. 5.1, RFC 5705 / RFC 8446 sec. 7.5 (now RFC 9846): Python `ssl` has no exporter | `[no]` | no standard-library or `cryptography` path; PORTFOLIO sec. 9 item 15; revisit if CPython adds `export_keying_material` | M3 |
| `ke.alpn-ntske1` | RFC 8915 sec. 3 and 4 (ALPN identifier `ntske/1`, TLS 1.3 minimum, port 4460): `ke.tls_context`, shown negotiating over a real handshake | `[ok]` | `tests/test_ke.py::test_tls_context_is_tls13_with_the_ntske_alpn_and_negotiates_it` | M3 |
| `timing.offset-and-delay` | RFC 5905 sec. 8 para 9 to 15 (t1..t4 arithmetic: 64-bit first-order differences modulo 2**64, floating second order, delay clamped to the precision) | `[ok]` | `tests/test_mac_and_timing.py::test_offset_and_delay` | M3 |
| `timing.response-checks` | RFC 5905 sec. 8 para 8 and sec. 7.4 para 8: mode, KoD before timestamps are trusted, the bogus (origin) test, duplicate or replay, unsynchronized (LI 3, stratum 16 or more, zero transmit) | `[ok]` | `tests/test_mac_and_timing.py::test_response_sanity_checks` | M3 |
| `trust.leap-and-stride-flags` | RFC 5905 sec. 7.3, erratum 4504 (leap indicator is about the last minute of the day): `LeapIndicator`, `leap_second_pending`, `usable_for_synchronization`. The "stride" in the row name has no source: neither RFC 5905 nor RFC 8915 mentions a stride flag (searched 2026-11-13), so that half is unresolved | `[part]` | `tests/test_client_state.py::test_leap_and_stride_flags` | M3 |
| `client.synchronize()` | RFC 8915, RFC 8633 | `[ ]` | `tests/test_obligations.py::test_synchronize` (to be written) | M3 |
| `client.port-randomisation` | RFC 9109 (client source port) | `[ ]` | (to be written) | M3 |
| `server.serve()` | RFC 8915; client/server mode only, not a full RFC 5905 server | `[ ]` | `tests/test_obligations.py::test_serve` (to be written) | M5 |
| `packet.interleaved-modes` | RFC 9769 | `[no]` | named as a non-goal in the README until a document needs it | - |
| `auth.aes-cmac-mac` | RFC 8573 sec. 3 with RFC 4493 sec. 4 vectors: `aes_cmac`, `sign_mac`, `verify_mac` over the header and extension fields, 16-octet key, 16-octet tag, key identifier outside the input, constant-time compare | `[ok]` | `tests/test_mac_and_timing.py::test_aes_cmac_rfc4493_vectors`, `tests/test_mac_and_timing.py::test_aes_cmac_mac` | M2 |
| `auth.cmac-key-file` | RFC 8573 sec. 3: a key is the triplet of ID, type and key and all three must match; a loader for an ntp.keys-style file with the type column and a refusal of MD5 keys (sec. 2 deprecates MD5) | `[ ]` | `tests/test_auth.py::test_key_triplet_must_match` (to be written) | M2 |
| `auth.cmac-key-id-input` | RFC 8573 sec. 3 says the CMAC covers "all fields in the NTP header and any extension fields" and is silent on the key identifier; this library leaves it out (the identifier is the MAC's own header). Confirm against ntpd or chrony output before 0.1.0 | `[ ]` | `tests/test_mac_and_timing.py::test_against_a_reference_implementation` (to be written) | M6 |

## 2. Milestones

- M1 packet and timestamp layer with the RFC 5905 errata applied
- M2 extension field authenticator, sign and verify
- M3 NTS-KE client against a public NTS server
- M4 cookie lifecycle including renewal under load
- M5 server side plus a loopback interoperability test
- M6 publication: 0.1.0

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 5905 carries 15 verified errata, the heaviest errata load in this portfolio, and is updated by RFC 7822, RFC 8573, RFC 9109, RFC 9748 and RFC 9769. The packet layer is written against the errata, not the 2010 text.
- RFC 8915 and RFC 9748 have no errata on file as of the 2026-10-29 errata feed (rfclib, read 2026-11-06). Re-check at the M1 freeze.
- Verified errata read for the wire layer (rfclib 2026-11-13): 4504 (7.3: leap indicator concerns the last minute of the day) and 5104 (Figure 8 names the field Message Digest). RFC 5905 has 15 verified errata in all; those in the appendix algorithms are not yet read row by row.
- RFC 7822 (updated by RFC 9748), RFC 8573, RFC 9109, RFC 9769, RFC 5297, RFC 4493 and RFC 5869 have no verified errata on file (RFC 5869: one on file, none verified). RFC 5705 has one verified erratum, not yet read. RFC 8446, which RFC 8915 cites for the exporter, is obsoleted by RFC 9846.
- RFC 5297 sec. 3: the nonce is the final associated-data component, so the AEAD call is `[A, N]`, and `[N]` where the protocol says no associated data (the cookie, RFC 8915 sec. 6). Pinned by RFC 5297 A.2 in `tests/test_auth.py`.
- `pyproject.toml` pinned `cryptography>50.0.2`, which excludes 50.0.2 itself and which the working environment (46.0.7) did not satisfy; the floor is now 37.0.0, where `AESSIV` appeared, and the suite ran on 46.0.7.

- Round 2 (2026-11-13), all read through rfclib: RFC 5905 verified erratum 3007 (sec. 7.4: on RATE the client must *increase* its polling interval, the text says reduce) is the reading `KodAction.SLOW_DOWN` follows; verified erratum 4504 (LI is about the last minute of the current day) is in `trust.LeapIndicator`; verified erratum 4121 (replay test compares with the org state variable) is in `timing.check_response`. RFC 8915 and RFC 8573 have no errata on file. RFC 8915 sec. 4.1.5 says the AEAD record's critical bit MAY be set and sec. 4.1.6 that the cookie record SHOULD NOT have it, so neither is enforced on receipt. RFC 8573 sec. 5 points at RFC 4493 sec. 4 for its test vectors, which `tests/test_mac_and_timing.py` uses.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| kernel clock discipline, slewing or PPS: measuring offset is in scope, steering the clock is not | `[no]` | a named document requires it |
| a complete RFC 5905 server: broadcast, manycast and interleaved modes come later if ever | `[no]` | a named document requires it |
| PTP and IEEE 1588, which is a different engineering world | `[no]` | a named document requires it |

## 5. Open questions

- how much of RFC 5905 is in scope once the errata and RFC 9748 registry changes apply
- NTS-KE needs a TLS exporter that Python's `ssl` lacks (row `ke.tls-exporter`, `[no]`): an NTS-KE client waits on that decision or on CPython adding the API. The cookie and authenticator layers do not.
- NTS-KE endpoint evidence: no public server is named yet; plan a recorded exchange fixture plus an opt-in live test.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
