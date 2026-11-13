# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 8915 | Proposed Standard | 2020-09 | 2026-11-05 |
| RFC 5905 | Proposed Standard | 2010-06 | 2026-11-05 |
| RFC 9748 | Proposed Standard | 2025-02 | 2026-11-05 |
| RFC 8633 | Best Current Practice | 2019-07 | 2026-11-05 |
| RFC 9523 | Informational | 2024-02 | 2026-11-05 |
| RFC 7822 | Proposed Standard; updates RFC 5905 (extension fields and MACs); updated by RFC 9748 | 2016-03 | 2026-11-13 |
| RFC 8573 | Proposed Standard; updates RFC 5905 (AES-CMAC MAC, deprecates MD5); updated by RFC 9748 | 2019-06 | 2026-11-13 |
| RFC 9109 | Proposed Standard; updates RFC 5905 (port randomisation) | 2021-08 | 2026-11-13 |
| RFC 9769 | Proposed Standard; updates RFC 5905 (interleaved modes) | 2025-05 | 2026-11-13 |
| RFC 5297 | Informational (AES-SIV; A.2 is the nonce-based test vector used here) | 2008-10 | 2026-11-13 |
| RFC 5705 | Proposed Standard (TLS exporters); updated by RFC 8446, RFC 8447, RFC 9846; 1 verified erratum | 2010-03 | 2026-11-13 |
| RFC 4493 | Informational (AES-CMAC) | 2006-06 | 2026-11-13 |
| RFC 5869 | Informational (HKDF; A.1 is the test vector used here) | 2010-05 | 2026-11-13 |
| RFC 8446 | Proposed Standard (TLS 1.3); obsoleted by RFC 9846 per rfclib, though RFC 8915 cites it | 2018-08 | 2026-11-13 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
