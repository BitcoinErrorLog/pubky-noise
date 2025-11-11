# pubky-noise

Pubky identity + Noise (snow) integration that keeps **Ring cold** after setup, using **deterministic per-device, per-epoch X25519 statics**, explicit **identity binding**, and **PKARR epoch** for rotation and revoke.

- **No custom crypto.** Uses `snow` for Noise, `x25519-dalek`, `ed25519-dalek`.
- **Deterministic device statics.** Derived from the Pubky Ed25519 seed with domain separation, device_id, and epoch.
- **Cold Ring.** Device stores the current epoch’s static; Ring can recreate and rotate at any time.
- **Revocation.** Homeservers/peers enforce the current `epoch` from PKARR; bumping epoch revokes old statics.
- **Identity binding.** First encrypted payload proves Ed25519 control over the Noise keys and context.

## Quick start

```bash
cargo build
cargo test

# Optional debug logs (no secrets logged):
cargo test --features trace -- --nocapture
```

The tests use a `DummyRing` and `DummyPkarr` to perform full IK handshakes, including negative cases.

## Concepts

### Deterministic device static

Let `K_root` be the Ring‑held Ed25519 seed. For device `device_id` and rotation `epoch`, we derive via **HKDF-SHA512**:

```
salt = "pubky-noise-x25519:v1"
info = device_id || epoch_le
okm = HKDF_SHA512(salt, K_root, info)[0..32]
X_sk = clamp(okm)      # X25519 clamping
X_pk = X25519(X_sk)
```

Ring derives this on demand; the device may cache `X_sk` until rotation.

### PKARR record (server/public)

```
noise_v1 = {
  suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s",
  epoch: <u32>,
  static_x25519_pub: <[u8;32]>,
  ed25519_sig: Sign_ed25519("pubky-noise-v1" || suite || epoch_le || static_x25519_pub),
  expires_at: <u64|null>
}
```

Clients must verify `ed25519_sig` before IK. An optional `verify_pkarr_binding_with_time` helper enforces `expires_at`.

### Identity-binding payload (first encrypted message)

JSON payload (AEAD-protected) includes:

```json
{
  "ed25519_pub": "<32 bytes>",
  "noise_x25519_pub": "<32 bytes>",
  "epoch": 123,
  "role": "Client" | "Server",
  "server_hint": "optional string",
  "sig": "<64 bytes ed25519 signature>"
}
```

Signature covers a BLAKE2s binding over: domain tag, pattern, prologue, ed25519 pub, both Noise pubs (if known), epoch, role, and optional hint.

### Deterministic encoding

To avoid cross-language ambiguity, encode the payload deterministically:

- Keep JSON but compute signatures over a fixed-order BLAKE2s digest (as above), not serialized bytes; or switch to deterministic CBOR.
- The signature is over the digest fields in fixed order, so it’s robust to JSON key ordering/whitespace.

### Zeroization and buffers

- Temporary X25519 statics are **zeroized** immediately after passing to `snow::Builder::local_private_key`.
- Handshake buffers use `payload_len + overhead` sizing.

## API

### `ring::RingKeyProvider`

Implement this against Pubky Ring (or a cached device store).

```rust
pub trait RingKeyProvider {
    fn derive_device_x25519(&self, kid: &str, device_id: &[u8], epoch: u32)
        -> Result<[u8; 32], NoiseError>;

    fn ed25519_pubkey(&self, kid: &str) -> Result<[u8; 32], NoiseError>;

    fn sign_ed25519(&self, kid: &str, msg: &[u8]) -> Result<[u8; 64], NoiseError>;
}
```

- **Online Ring:** derive + sign with Ring.
- **Cold Ring:** use a delegated Ed25519 device key for `sign_ed25519`, and return the current epoch’s `x25519_sk` from local secure storage. Ring can recreate it.

### Client

- Verifies PKARR signature (binds suite + epoch + static pub) and obtains `epoch`.
- Builds IK using `local_private_key(x_sk)` and `remote_public_key(x_pk_srv)`.
- Sends identity payload with `epoch` and signature over the binding hash.

### Server

- Builds responder using its own device+epoch static.
- Decrypts first message, verifies the payload signature, and enforces **client epoch** via PKARR/directory.
- Optional: reject **monotonic regressions** using a small in-memory cache.

## Hardening notes

- Deterministic statics via **HKDF-SHA512** (salted + per-device info).
- PKARR signature **binds the ciphersuite** as well as epoch and static pubkey.
- Optional **monotonic client-epoch cache** to reject regressions.
- Optional **time-aware PKARR expiry** check (`verify_pkarr_binding_with_time`).

## License

MIT
