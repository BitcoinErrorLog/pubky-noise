# pubky-noise

Direct pubky-client ↔ pubky-server Noise sessions.
- Ring-cold device statics (derived on demand).
- Direct-by-default: XX for first contact, IK once server static is pinned.
- Optional PKARR: `--features pkarr` adds OOB metadata only; transport stays direct.

Noise: rev 34 via `snow`. Suites: `Noise_XX_25519_ChaChaPoly_BLAKE2s`, `Noise_IK_25519_ChaChaPoly_BLAKE2s`.

Defenses: reject all-zero X25519 shared secret; deterministic identity-binding digest; secrets scoped with `Zeroizing`. Optional `secure-mem` for servers.

See `src/datalink_adapter.rs` and `tests/invalid_peer.rs`.
