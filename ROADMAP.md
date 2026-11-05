# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation ntspy could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `packet.decode_packet()` | RFC 5905 | `[ ]` | `tests/test_obligations.py::decode_packet` |
| `packet.encode_packet()` | RFC 5905 | `[ ]` | `tests/test_obligations.py::encode_packet` |
| `ke.encode_record()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::encode_record` |
| `ke.establish()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::establish` |
| `cookies.mint()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::mint` |
| `cookies.validate()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::validate` |
| `extension.authenticate()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::authenticate` |
| `extension.verify()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::verify` |
| `client.synchronize()` | RFC 8915, RFC 8633 | `[ ]` | `tests/test_obligations.py::synchronize` |
| `server.serve()` | RFC 8915 | `[ ]` | `tests/test_obligations.py::serve` |

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
- Re-check the errata pages for RFC 8915 and RFC 9748 before the M1 freeze rather than trusting what is written here.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| kernel clock discipline, slewing or PPS: measuring offset is in scope, steering the clock is not | `[no]` | a named document requires it |
| a complete RFC 5905 server: broadcast, manycast and interleaved modes come later if ever | `[no]` | a named document requires it |
| PTP and IEEE 1588, which is a different engineering world | `[no]` | a named document requires it |

## 5. Open questions

- how much of RFC 5905 is in scope once the errata and RFC 9748 registry changes apply

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
