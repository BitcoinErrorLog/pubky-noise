# pubky-noise

Direct client↔server Noise sessions for Pubky using `snow`. Default build is direct-only. PKARR is optional metadata behind a feature flag.

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
* Not a PKARR transport (PKARR is optional out-of-band metadata only).

## Specs and suites

* Noise revision: 34 (as implemented by current `snow`).
* Suites: `Noise_XX_25519_ChaChaPoly_BLAKE2s`, `Noise_IK_25519_ChaChaPoly_BLAKE2s`, and `Noise_NN_25519_ChaChaPoly_BLAKE2s`.
* Hash: BLAKE2s. AEAD: ChaCha20-Poly1305. DH: X25519.

## Features

* `default = []`: direct-only, no PKARR, no extra dependencies.
* `pkarr`: optional signed metadata fetch and verification for server static and epoch.
* `trace`: opt-in `tracing` for non-sensitive logs.
* `secure-mem`: Best-effort memory hardening using platform mlock. Use `LockedBytes<N>` wrapper for sensitive key material.
* `pubky-sdk`: Convenience wrapper for `RingKeyProvider` using Pubky SDK `Keypair`.
* `storage-queue`: Support for storage-backed messaging using Pubky storage as a queue (requires `pubky` and `async-trait`).

## Key handling model

* Device X25519 static is derived per device (and an internal epoch) using HKDF and a seed available to Ring. The secret is created inside a closure and passed directly to `snow::Builder::local_private_key` via `zeroize::Zeroizing<[u8;32]>`.
* The app never stores the raw secret beyond the closure scope. No logs, no clones, no return of the secret to caller code.
* Epoch rotation is not implemented yet (epoch is currently fixed to 0); applications should use fresh device IDs (or a new seed) to rotate until explicit epoch rotation is added.

## Session Management

### Session ID
Each session has a unique `SessionId` derived from the handshake state. This can be used to track sessions at the application layer.

```rust
let session_id = transport.session_id();
println!("Session ID: {}", session_id);

// SessionId is serializable for persistence
let bytes = session_id.to_bytes();
let restored = SessionId::from_bytes(bytes);
```

### Multi-Session Management
The `NoiseSessionManager` allows managing multiple concurrent sessions.

```rust
let mut manager = NoiseSessionManager::new_client(client);
manager.add_session(session_id, link);

// For thread-safe access (important for mobile apps)
use pubky_noise::ThreadSafeSessionManager;
let safe_manager = ThreadSafeSessionManager::new_client(client);
```

### Mobile-Optimized Manager
For mobile applications, use `NoiseManager` for full lifecycle management:

```rust
use pubky_noise::{NoiseManager, MobileConfig};

let config = MobileConfig::default(); // Auto-reconnect, mobile-friendly settings
let mut manager = NoiseManager::new_client(client, config);

// 3-step handshake
let (temp_id, first_msg) = manager.initiate_connection(&server_pk, None)?;
// ... send first_msg to server, receive response ...
let session_id = manager.complete_connection(&temp_id, &response)?;

// Save state before app suspension
let state = manager.save_state(&session_id)?;
// ... persist state ...

// Restore after app resume
manager.restore_state(state)?;
```

See [docs/MOBILE_INTEGRATION.md](docs/MOBILE_INTEGRATION.md) for complete mobile integration guide.

### Streaming / Chunking
For messages larger than the Noise packet limit, use `StreamingNoiseLink` to automatically split and reassemble chunks.

```rust
let mut streaming = StreamingNoiseLink::new_with_default_chunk_size(link);
let chunks = streaming.encrypt_streaming(large_data)?;
```

## Storage-Backed Messaging (Optional)

When direct connection is not possible or asynchronous messaging is required, you can use `StorageBackedMessaging` (requires `storage-queue` feature). This uses Noise for encryption but Pubky storage as a message queue.

This implementation follows the **Outbox Pattern**: senders write to their own repository (authenticated write), and receivers poll the sender's repository (public read).

### Usage with State Resumption

It is critical to persist the read/write counters to avoid data loss or message replay across application restarts.

```rust
// Write to your own storage, read from peer's storage
let mut queue = StorageBackedMessaging::new(
    link, 
    session, 
    public_client, 
    "/pub/me/outbox".to_string(), 
    "pubky://peer_pk/pub/peer/outbox".to_string()
).with_counters(saved_write_counter, saved_read_counter); // Resume from saved state

queue.send_message(b"hello async world").await?;
let msgs = queue.receive_messages(Some(10)).await?;

// Save new counters (critical for production!)
let write_counter = queue.write_counter();
let read_counter = queue.read_counter();
save_state(write_counter, read_counter);
```

### Network Resilience

Configure retry logic for mobile networks:

```rust
use pubky_noise::RetryConfig;

let retry_config = RetryConfig {
    max_retries: 3,
    initial_backoff_ms: 100,
    max_backoff_ms: 5000,
    operation_timeout_ms: 30000,
};

queue = queue.with_retry_config(retry_config);
```

## Handshake flows

### IK Pattern: Pinned server static (recommended)

When you already know the server's static key (from a previous XX handshake or out-of-band):

* Pattern: `IK`.
* Client: `NoiseClient::build_initiator_ik_direct(server_static_pub, hint) -> (HandshakeState, first_msg)`.
* Server: `NoiseServer::build_responder_read_ik(first_msg) -> (HandshakeState, IdentityPayload)`.

### XX Pattern: First contact (TOFU)

For first contact when the server's static key is unknown:

* Pattern: `XX`.
* Client: `NoiseClient::build_initiator_xx_tofu(hint) -> (HandshakeState, first_msg, hint)`.
* Server: `NoiseServer::build_responder_xx(first_msg) -> (HandshakeState, response, server_pk)`.
* Client: `NoiseClient::complete_initiator_xx(hs, response, hint) -> (HandshakeState, final_msg, server_identity, server_pk)`.
* Server: `NoiseServer::complete_responder_xx(hs, final_msg, server_pk) -> (HandshakeState, client_identity)`.
* **After handshake**: Pin the learned `server_pk` and use IK for future connections.

```rust
use pubky_noise::datalink_adapter::{
    client_start_xx_tofu, server_accept_xx, client_complete_xx, server_complete_xx
};

// Step 1: Client initiates (no server key needed)
let init = client_start_xx_tofu(&client, Some("server.example.com"))?;

// Step 2: Server accepts and responds with identity
let (s_hs, response, server_pk) = server_accept_xx(&server, &init.first_msg)?;

// Step 3a: Client completes and learns server's key
let (result, final_msg) = client_complete_xx(&client, init.hs, &response, init.server_hint.as_deref())?;

// Step 3b: Server completes
let (s_link, client_id) = server_complete_xx(&server, s_hs, &final_msg, &server_pk)?;

// Pin server_pk for future IK connections!
save_pinned_key(result.server_static_pk);
```

### NN Pattern: Ephemeral-only (NO AUTHENTICATION)

> ⚠️ **Security Warning**: The NN pattern provides **forward secrecy only** with NO identity binding. An active attacker can trivially MITM this connection. Use ONLY when:
> - The transport layer provides authentication (e.g., TLS with pinned certs)
> - You are building a higher-level authenticated protocol on top
> - You explicitly accept the MITM risk for your use case

* Pattern: `NN`.
* Client: `NoiseClient::build_initiator_nn() -> (HandshakeState, first_msg)`.
* Server: `NoiseServer::build_responder_nn(first_msg) -> (HandshakeState, response)`.
* Client: `NoiseClient::complete_initiator_nn(hs, response) -> HandshakeState`.

```rust
use pubky_noise::datalink_adapter::{client_start_nn, server_accept_nn, client_complete_nn, server_complete_nn};

// WARNING: NO AUTHENTICATION!
let (c_hs, first_msg) = client_start_nn(&client)?;
let (s_hs, response) = server_accept_nn(&server, &first_msg)?;
let c_link = client_complete_nn(&client, c_hs, &response)?;
let s_link = server_complete_nn(s_hs)?;
// DANGER: You have NO cryptographic proof of who you're talking to!
```

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
use pubky_noise::datalink_adapter::{
    client_start_ik_direct, server_accept_ik, client_complete_ik, server_complete_ik
};

let ring_client = Arc::new(DummyRing::new([1u8;32], "kid"));
let ring_server = Arc::new(DummyRing::new([2u8;32], "kid"));

let client = NoiseClient::<_, ()>::new_direct("kid", b"dev-client", ring_client);
let server = NoiseServer::<_, ()>::new_direct("kid", b"dev-server", ring_server);

// assume you have the server static pinned OOB as `server_static_pk`
let server_static_pk: [u8;32] = [0; 32]; // mocked

// 3-step handshake
// Step 1: Client creates first message
let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk, None)?;

// Step 2: Server accepts and returns response
let (s_hs, client_id, response) = server_accept_ik(&server, &first_msg)?;

// Step 3: Both complete handshake
let mut c_link = client_complete_ik(c_hs, &response)?;
let mut s_link = server_complete_ik(s_hs)?;

// send data
let ct = c_link.encrypt(b"hello")?;
let pt = s_link.decrypt(&ct)?;
assert_eq!(&pt, b"hello");
```

## Error Handling

Structured error codes for mobile/FFI integration:

```rust
use pubky_noise::{NoiseError, NoiseErrorCode};

match result {
    Err(e) => {
        let code = e.code(); // NoiseErrorCode enum
        let message = e.message(); // Owned String for FFI
        // Map to platform-specific errors
    }
    Ok(data) => { /* success */ }
}
```

## Security notes

* `Zeroizing` reduces lifetime of secrets in memory but cannot guarantee full eradication across OS subsystems. Run under minimal privileges and treat host memory as potentially observable in crash/forensics scenarios.
* Enforce input size caps and rate limits in your network layer to avoid trivial DoS.
* Keep `snow` up to date. If suites change, bump minor version of this crate.
* For mobile apps: Always persist session state and counters before suspension to avoid data loss.

## Mobile Integration

This crate is designed for production mobile apps (iOS/Android) with:

* **Lifecycle management**: `NoiseManager` handles session persistence and restoration
* **Thread safety**: `ThreadSafeSessionManager` for concurrent access
* **Network resilience**: Automatic retry with exponential backoff
* **Battery optimization**: Configurable aggressive/conservative modes
* **Error codes**: FFI-friendly structured errors

**Complete Guide**: See [docs/MOBILE_INTEGRATION.md](docs/MOBILE_INTEGRATION.md) for:
- State persistence patterns
- Thread safety guidelines
- Platform-specific considerations (iOS/Android)
- Network resilience best practices
- Memory management tips

## Security Testing

This crate includes fuzz targets and concurrency tests:

```bash
# Run fuzz tests (requires nightly)
cd fuzz
cargo +nightly fuzz run fuzz_handshake -- -max_total_time=60

# Run loom concurrency tests
RUSTFLAGS="--cfg loom" cargo test --test loom_tests --release
```

## Versioning

* `0.7.x`: Mobile-optimized manager, thread-safe wrappers, simplified API, fuzz targets.
* `0.6.x`: Session management, streaming, and storage queue features.
* Bump minor for API changes, patch for internal refactors and tests.
