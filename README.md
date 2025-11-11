# pubky-noise

Direct client↔server Noise sessions for Pubky using `snow`. Default build is direct-only. PKARR is optional metadata behind a feature flag and is not in the transport hot path.

## Goals

* Direct transport first: XX for first contact, IK when the server static is pinned or delivered OOB.
* Keep Ring keys cold: device statics are derived on demand and passed directly to `snow` without living in app buffers.
* Simple integration: tiny DataLink-style adapter with `encrypt` and `decrypt`.
* App-layer binding: export a session tag to bind Paykit and Locks messages to the live channel.
* Footgun defenses: reject invalid peer statics that would yield an all-zero X25519 shared secret.

## What this crate is

* A thin, conservative wrapper around `snow` with Pubky ergonomics.
* A closure-based key feed so secrets do not leak into general app memory.
* A set of helpers for XX and IK patterns, identity binding, and a minimal adapter.

## What this crate is not

* Not a reimplementation of Noise.
* Not a messaging protocol or a full RPC layer.
* Not a PKARR transport. PKARR is optional out-of-band metadata only.

## Specs and suites

* Noise revision: 34 (as implemented by current `snow`).
* Suites: `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
* Hash: BLAKE2s. AEAD: ChaCha20-Poly1305. DH: X25519.

## Features

* `default = []`: direct-only, no PKARR.
* `pkarr`: optional signed metadata fetch and verification for server static and epoch. Transport remains direct.
* `trace`: opt-in `tracing` and `hex` for non-sensitive logs.
* `secure-mem`: opt-in best-effort page pinning and DONTDUMP on supported OSes (server side).

## Key handling model

* Device X25519 static is derived per device and per epoch using HKDF and a seed available to Ring. The secret is created inside a closure and passed directly to `snow::Builder::local_private_key` via `secrecy::Zeroizing<[u8;32]>`.
* The app never stores the raw secret beyond the closure scope. No logs, no clones, no return of the secret to caller code.
* Rotation is achieved by bumping epoch. Ring can recreate the same statics for a device and epoch. Homeserver can revoke by policy.

## Footgun defenses

* Reject peers that would yield an all-zero X25519 shared secret. This mitigates low-order or malformed remote statics. Enforced both on the client before initiating IK and on the server after reading the client payload.
* Deterministic identity binding over fixed fields. The first encrypted payload in IK binds Ed25519 identity and context. Signature is over a digest, not over JSON.
* Server policy struct is present for rate limiting and epoch checks. Extend it for your deployment.

## Handshake flows

### First contact (TOFU or OOB token)

* Pattern: `XX`.
* Client: `NoiseClient::build_initiator_xx_tofu(hint) -> (HandshakeState, first_msg)`.
* Server: `NoiseServer::build_responder_read_xx(first_msg) -> HandshakeState`.
* Caller pins the server static post-handshake through an out-of-band path, then uses IK for future connections.

### Pinned server static

* Pattern: `IK`.
* Client: `NoiseClient::build_initiator_ik_direct(server_static_pub, epoch, hint) -> (HandshakeState, first_msg, epoch)`.
* Server: `NoiseServer::build_responder_read_ik(first_msg) -> (HandshakeState, IdentityPayload)`.

### Identity binding payload (first encrypted message of IK)

Digest fields:

```
tag = "IK"
digest = BLAKE2s(
  "pubky-noise-bind:v1" ||
  tag ||
  prologue ||
  ed25519_pub ||
  local_noise_x25519_pub ||
  remote_noise_x25519_pub ||
  epoch_le ||
  role_string ||
  optional_server_hint
)
sig = Sign_ed25519(digest)
```

Verifier recomputes the digest with the same field order and checks the signature against `ed25519_pub`.

## Session tag for app-layer binding

* `NoiseTransport::export_session_tag(&HandshakeState) -> [u8;32]`.
* Use this tag to bind Paykit and Locks messages to the live channel. Compare in constant time at the app layer.

## Minimal adapter

`src/datalink_adapter.rs` provides a tiny adapter similar to `DataLinkEncryptor`.

* `NoiseLink::new_from_hs(hs) -> NoiseLink`.
* `encrypt(plaintext) -> ciphertext`.
* `decrypt(ciphertext) -> plaintext`.
* Helpers:

```
client_start_ik_direct(client, server_static_pub, epoch, hint) -> (NoiseLink, used_epoch, first_msg)
server_accept_ik(server, first_msg) -> (NoiseLink, IdentityPayload)
```

Rename these to match your exact interface.

## Quick start

### Build and test

```
cargo build
cargo test
```

### Add to an app (direct-only)

```rust
use std::sync::Arc;
use pubky_noise::{NoiseClient, NoiseServer, DummyRing};
use pubky_noise::datalink_adapter::{client_start_ik_direct, server_accept_ik};

let ring_client = Arc::new(DummyRing::new([1u8;32], "kid"));
let ring_server = Arc::new(DummyRing::new([2u8;32], "kid"));

let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server, 3);

// assume you have the server static pinned OOB as `server_static_pk`
let server_static_pk: [u8;32] = /* pinned value */ unimplemented!();

// client creates first message
let (mut c_link, used_epoch, first_msg) = client_start_ik_direct(&client, &server_static_pk, 3, None)?;

// server accepts and returns a transport link and client identity payload
let (mut s_link, client_id) = server_accept_ik(&server, &first_msg)?;

// send data
let ct = c_link.encrypt(b"hello")?;
let pt = s_link.decrypt(&ct)?;
assert_eq!(&pt, b"hello");
# Ok::<(), pubky_noise::NoiseError>(())
```

### Enable PKARR metadata (optional)

```
cargo build --features pkarr
```

You provide a `PkarrResolver` that returns a signed record for the server static and epoch. The client validates the record out-of-band and still connects directly using IK.

## Tests

* `tests/invalid_peer.rs` ensures clients reject all-zero shared secrets for peer statics. Expects `NoiseError::InvalidPeerKey`.
* `tests/adapter_demo.rs` compiles and links the adapter and server/client types. Extend with real round-trip if you wire IO.

## Integration checklist (copy into your issue)

* Transport is direct-only in default build. PKARR is optional behind a feature flag.
* Ring key handling uses closure-based feed with `Zeroizing`, no secrets in app buffers.
* Enforced all-zero shared secret rejection on both sides.
* Identity binding uses deterministic digest over fixed fields.
* Session tag exported and consumed in app layer with constant-time compare.
* Server epoch policy wired to your credentialing path.
* Logs contain no sensitive data. Errors are actionable.
* Tests pass in CI with default features.

## Security notes

* `Zeroizing` reduces lifetime of secrets in memory but cannot guarantee full eradication across OS subsystems. For servers, enable `secure-mem` and run under minimal privileges.
* Enforce input size caps and rate limits in your network layer to avoid trivial DoS.
* Keep `snow` up to date. If suites change, bump minor version of this crate and update README.

## Versioning

* `0.y.z` until the adapter surface and identity binding are stable across SDKs.
* Bump minor when you change field order or digest binding.
* Bump patch for internal refactors and tests.

## Troubleshooting

* `InvalidPeerKey`: your pinned server static is wrong or the peer sent an invalid static that leads to zero shared secret. Verify OOB pinning and regenerate statics.
* Handshake stalls: check that both sides use the same suite and prologue. Ensure the client used IK with a pinned static and not XX by mistake.
* App cannot find the key: confirm Ring can derive the device static for the expected device_id and epoch. Do not pass secrets through app buffers.
