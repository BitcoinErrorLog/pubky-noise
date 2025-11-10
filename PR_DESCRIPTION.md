# PR: Harden pubky-noise for Paykit + Locks (HKDF, suite binding, expiry, monotonic epochs, session binding)

## Summary

Hardens `pubky-noise` for production Paykit and Locks flows while staying aligned with Pubky:

- Deterministic per-device, per-epoch X25519 statics via **HKDF-SHA512** (clamped).
- PKARR signature **binds the ciphersuite** in addition to epoch and static pubkey.
- Optional **expiry enforcement** on PKARR (`verify_pkarr_binding_with_time`).
- Server-side **monotonic client-epoch cache** to reject regressions/replays.
- **Session binding tag** exported for Paykit receipts / Locks capabilities.
- Tight **zeroization** and **dynamic buffers** in handshake.
- Deterministic identity payload semantics (signature over a fixed-order BLAKE2s digest).

## Why

- Paykit and Locks need channel binding and clean rotation semantics. This ties app-layer auth to Noise while keeping Ring cold and PKARR authoritative.
- Prevents suite-swap footguns and stale-record issues; adds cheap replay dampening in production.

## What changed

- HKDF derivation in `kdf.rs`.
- PKARR verifier in `pkarr.rs` now binds `suite` and supports optional expiry.
- Client/Server updated to zeroize statics after handing to Snow; dynamic handshake buffers.
- Server tracks highest client epoch seen to reject regressions.
- Transport exposes `export_session_tag()` for app-layer binding.
- README expanded with deterministic encoding, zeroization, and integration notes.
