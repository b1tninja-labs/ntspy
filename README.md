# ntspy

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

ntspy -- Network Time Security on asyncio

Authenticated time is a solved problem on paper and absent in Python. RFC 8915 defines NTS: a TLS key establishment exchange that hands the client cookies, then an authenticator in every NTP packet. Nothing on PyPI implements any of it, and the NTP clients that do exist are either stale (ntplib 0.4.0, 2021-05-28) or plain unauthenticated (pyntp 0.1.1, 2026-03-20). The gap is NTS, not NTP: nts, nts-ke, ntp-nts and aiontp were all absent when checked on 2026-11-05.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| ntplib | 0.4.0 | 2021-05-28 | unauthenticated NTP client, unmaintained |
| pyntp | 0.1.1 | 2026-03-20 | active but unauthenticated; the opposite half of the problem |
| nts, nts-ke, ntp-nts, aiontp | - | - | absent from PyPI (2026-11-05); nts is an unrelated note-taking package |

What this project intends to add:

- the NTS-KE exchange over TLS with application layer protocol negotiation and ALTS-style record framing
- cookie issue, cache, renewal and the critical-path rule that a stale cookie must not break time
- the NTP extension field authenticator and its truncated MAC discipline
- a server side, because an authenticated client with nothing to talk to measures nothing
- AES-SIV-CMAC from the `cryptography` extra (the standard library has no AES). The TLS exporter NTS-KE needs is not offered by Python's `ssl` or by `cryptography`, so NTS-KE is on hold (ROADMAP row `ke.tls-exporter`, `[no]`)

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 8915 | Proposed Standard | 2020-09 | NTS: key establishment, cookies, the extension field |
| RFC 5905 | Proposed Standard | 2010-06 | NTPv4 packet format and the modes NTS rides on |
| RFC 9748 | Proposed Standard | 2025-02 | the refreshed NTP registries: modes, extension field types |
| RFC 8633 | Best Current Practice | 2019-07 | operating rules an NTS client should respect |
| RFC 9523 | Informational | 2024-02 | Khronos, the alternative approach; a roadmap comparison, not a dependency |

### Errata watch

- RFC 5905 carries 15 verified errata, the heaviest errata load in this portfolio, and is updated by RFC 7822, RFC 8573, RFC 9109, RFC 9748 and RFC 9769. The packet layer is written against the errata, not the 2010 text.
- RFC 8915 and RFC 9748 have no errata on file as of the 2026-10-29 errata feed (rfclib, read 2026-11-06). Re-check at the M1 freeze.

## Module layout

| Module | Responsibility |
|---|---|
| `packet` | NTPv4 header, extension fields and timestamp arithmetic (RFC 5905, RFC 9748) |
| `ke` | key establishment records and notifications (RFC 8915) |
| `cookies` | issue, validate, cache and renew (RFC 8915) |
| `extension` | the NTS authenticator and unique identifier fields (RFC 8915) |
| `auth` | derive, sign and verify with truncated MACs (RFC 8915) |
| `client` | the asyncio client: establish, query, verify, re-establish |
| `server` | the server half: accept, mint cookies, authenticate responses |
| `trust` | local trust store and the leap second and stride flags it must not silently ignore |

## What it does not do

- kernel clock discipline, slewing or PPS: measuring offset is in scope, steering the clock is not
- a complete RFC 5905 server: broadcast, manycast and interleaved modes come later if ever
- PTP and IEEE 1588, which is a different engineering world


## Install

```bash
git clone https://github.com/b1tninja/ntspy.git
cd ntspy
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy ntspy tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
