# pubky-noise

Direct **pubky-client ↔ pubky-server** Noise sessions, aligned with Pubky:
- **Ring-cold**: device statics are derived on demand; Ring can recreate/rotate without the app ever storing secrets.
- **Direct-by-default**: no PKARR dependency. First-contact via **XX** + TOFU/OOB token, then **IK** with a pinned server static.
- **Optional PKARR**: enable `--features pkarr` to fetch/verify server statics + rotation counters out-of-band (metadata only).

## Noise spec, suites, and assumptions
Implements Noise patterns via `snow` (Noise rev 34). Suites:
- `Noise_XX_25519_ChaChaPoly_BLAKE2s` (first-contact without trusted static)
- `Noise_IK_25519_ChaChaPoly_BLAKE2s` (pinned/static known)  
Security assumptions: X25519 DH, ChaCha20-Poly1305 AEAD, BLAKE2s hash (standard Noise invariants).

## Keys and memory hygiene
- Secrets are scoped with `with_device_x25519(...)` which derives inside a closure and passes directly to Snow using `secrecy::Zeroizing<[u8;32]>`.
- All-zero shared-secrets are **rejected** to mitigate low-order remote public keys.
- Optional `secure-mem` feature: best-effort page pinning and DONTDUMP on supported OSes.

## Identity binding
First encrypted payload (IK flow) proves Ed25519 control over the Noise keys and context:
- `sig = Sign_ed25519(BLAKE2s("pubky-noise-bind:v1" || pattern || prologue || ed25519_pub || local_noise_pk || remote_noise_pk? || epoch || role || hint?))`
- Deterministic: signature computed over a fixed-order digest; JSON is transport only.

## API (high level)
- `NoiseClient::build_initiator_xx_tofu(hint)` → first-contact channel.
- `NoiseClient::build_initiator_ik_direct(server_static_pub, epoch, hint)` → direct IK with pinned static.
- `NoiseServer::build_responder_read_xx(first_msg)` and `build_responder_read_ik(first_msg)`.
- `NoiseTransport::export_session_tag(&HandshakeState)` → 32-byte tag for Paykit/Locks binding.

### Optional PKARR
Enable `pkarr` feature to use signed PKARR metadata out-of-band; transport remains direct. Clients verify the record and then run IK.

## Defensive checks
- Reject zero X25519 shared secrets (after DH with peer’s static).
- Enforce rotation counters/epochs (direct or via PKARR when enabled).
- Strict signature verification and deterministic binding inputs.

## DataLink adapter (drop-in)
See `src/datalink_adapter.rs` for a tiny adapter that looks like a minimal `DataLinkEncryptor`:
- `NoiseLink::new_from_hs(hs)` → wraps the transport
- `encrypt(&mut self, plaintext)` / `decrypt(&mut self, ciphertext)`

Helpers:
- `client_start_ik_direct(...) -> (NoiseLink, epoch)`
- `server_accept_ik(...) -> (NoiseLink, IdentityPayload)`

These are stubs; adjust to match your exact interface names.

## Quick start
```bash
cargo build
cargo test
# optional logs (no secrets):
cargo test --features trace -- --nocapture
```

## License
MIT
