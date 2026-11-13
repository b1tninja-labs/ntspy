# Strategy

The completeness matrix is [../ROADMAP.md](../ROADMAP.md). This document is *why* the rows
are ordered the way they are, and the rules that order has to respect.

## The constitution

1. **The core is the specification implementation.** `ntspy/` holds codecs, state machines
   and the vocabulary of ntspy. New core code appears when a document defines the
   behaviour, or when an ordering rule with no document earns an explicit convention label.
2. **Sans-IO before sockets.** Anything decidable from data plus a clock is implemented
   without touching a socket, so every timeout, retry and rollover is testable without
   sleeping or networking.
3. **Dependency-free by default.** An exception needs a sentence in README.md explaining why
   the rule was broken, and a floor with no ceiling.
4. **Positioning is correctness and legibility, not throughput.** The incumbents in this
   corner are usually stale, untyped, or welded to a product. This is the implementation that
   says how it knows what it claims.
5. **Every answer carries its provenance.** Verified or cached, which document, refused or
   believed. An answer without provenance is a guess with a confident type.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `ntspy/` | codecs, state machines, policy objects | RFC-cited or convention-labelled |
| Apps | `ntspy/apps/` | reusable assemblies that compose core | no new protocol surface |
| Examples | `examples/` | one runnable script per use case | configures; never restates logic |

## Interface grammar

One engine, three drives, never parallel implementations:

- **await** -- the native asyncio surface.
- **blocking** -- a facade owning a private loop, so a call from inside a caller's running
  loop works instead of deadlocking.
- **callback** -- plain callables, no third-party promise type.

## Naming

One string everywhere: the distribution, the import and the console script. A name that
means one thing in the installer, in `import` and on `PATH` is the only arrangement that
cannot surprise anyone, and it is also why this project does not sit one edit away from a
project that already exists.

## Dependency: cryptography (2026-11-13)

The standard library has no AES, so AEAD_AES_SIV_CMAC_256 (the algorithm RFC 8915 sec. 4.1.5 makes
mandatory) and AES-CMAC (RFC 8573) cannot be written on it. The owner's rule allows the
`cryptography` package for primitives. `cryptography.hazmat.primitives.ciphers.aead.AESSIV` (added in
37.0.0; documented at https://cryptography.io/en/latest/hazmat/primitives/aead/) implements RFC 5297,
and `tests/test_auth.py` pins it to the RFC 5297 A.2 vector. It is the optional `crypto` extra, imported
on first use, so the packet codec needs nothing. HKDF is done here on `hmac` (RFC 5869 A.1 vector). It
does not provide a TLS exporter, which is why NTS-KE is `[no]` for now.
