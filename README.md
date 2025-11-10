# pubky-noise

Pubky identity + Noise (snow) integration that keeps **Ring cold** after setup, using **deterministic per‑device, per‑epoch X25519 statics**, explicit **identity binding**, and **PKARR epoch** for rotation and revoke.

- **No custom crypto.** Uses `snow` for Noise, `x25519-dalek`, `ed25519-dalek`.
- **Deterministic device statics.** Derived from the Pubky Ed25519 seed with domain separation, device_id, and epoch.
- **Cold keys via Pubky Ring.** Device stores the current epoch’s static; Ring can recreate and rotate at any time.
- **Revocation.** Homeservers/peers enforce the current `epoch` from PKARR; bumping epoch revokes old statics.
- **Identity binding.** First encrypted payload proves Ed25519 control over the Noise keys and context.

## Crate status

- Library only. Provides traits and helpers.
- Includes a `DummyRing` and `DummyPkarr` for tests and examples.
- Works with `Noise_IK_25519_ChaChaPoly_BLAKE2s` and `Noise_XX_25519_ChaChaPoly_BLAKE2s`.

## Concepts

### Deterministic device static

Let `K_root` be the Ring‑held Ed25519 seed. For device `device_id` and rotation `epoch`:

```
X_sk = clamp( SHA512( "pubky-noise-x25519:v1" || device_id || epoch_le || K_root )[0..32] )
X_pk = X25519(X_sk)
```

Ring derives this on demand; the device may cache `X_sk` until rotation.

### PKARR record (server/public)

```
noise_v1 = {
  suite: "Noise_IK_25519_ChaChaPoly_BLAKE2s",
  epoch: <u32>,
  static_x25519_pub: <[u8;32]>,
  ed25519_sig: Sign_ed25519("pubky-noise-v1" || epoch_le || static_x25519_pub),
  expires_at: <u64|null>
}
```

Clients must verify `ed25519_sig` before using IK.

### Identity-binding payload (first encrypted message)

Payload (JSON for convenience):

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
- **Cold Ring:** use a delegated Ed25519 device key (cached) for `sign_ed25519`, and return the current epoch’s `x25519_sk` from local secure storage. Ring can recreate it.

### Client

- Verifies PKARR signature and obtains `epoch`.
- Builds IK using `local_private_key(x_sk)` and `remote_public_key(x_pk_srv)`.
- Sends identity payload with `epoch` and signature over the binding hash.

### Server

- Builds responder using its own device+epoch keys.
- Decrypts first message, verifies the identity payload signature and epoch policy.

See the inline docs in `src/client.rs` and `src/server.rs`.

## Migration

If you were using the 0.1 version:

- Publish PKARR with `epoch` and a signature over `"pubky-noise-v1" || epoch_le || static_x25519_pub`.
- Add `epoch` to your handshake payload and binding hash.
- Derive device statics per device_id + epoch. Cache locally and rotate by epoch bump in PKARR.

## Examples and tests

Run the included unit test:

```bash
cargo test
```

For runnable apps, see the demo repos:
- `pubky-noise-demo` (CLI TCP echo)
- `pubky-noise-webchat` (browser GUI via WASM)

## Security notes

- Never export the Ed25519 signing key from Ring in production.
- Zeroize temporary secrets promptly.
- Enforce epoch from PKARR for new handshakes; expire capability tokens for APIs at the homeserver.

## License

MIT


## Quick start

Build and run tests:

```bash
git clone https://github.com/synonymdev/pubky-noise.git
cd pubky-noise
cargo build
cargo test
```

The tests use a DummyRing and DummyPkarr to perform a full IK round trip with an epoch.


### Tracing

Enable lightweight debug logs (never logs secrets) by building with the `trace` feature:

```bash
cargo test --features trace -- --nocapture
```
