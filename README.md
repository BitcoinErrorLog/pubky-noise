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
* Suites: `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
* Hash: BLAKE2s. AEAD: ChaCha20-Poly1305. DH: X25519.

## Features

* `default = []`: direct-only, no PKARR, no extra dependencies.
* `pkarr`: optional signed metadata fetch and verification for server static and epoch.
* `trace`: opt-in `tracing` and `hex` for non-sensitive logs.
* `secure-mem`: opt-in best-effort page pinning and DONTDUMP on supported OSes (server side).
* `pubky-sdk`: Convenience wrapper for `RingKeyProvider` using Pubky SDK `Keypair`.
* `storage-queue`: Support for storage-backed messaging using Pubky storage as a queue (requires `pubky` and `async-trait`).

## Key handling model

* Device X25519 static is derived per device and per epoch using HKDF and a seed available to Ring. The secret is created inside a closure and passed directly to `snow::Builder::local_private_key` via `secrecy::Zeroizing<[u8;32]>`.
* The app never stores the raw secret beyond the closure scope. No logs, no clones, no return of the secret to caller code.
* Rotation is achieved by bumping epoch. Ring can recreate the same statics for a device and epoch. Homeserver can revoke by policy.

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

// Connect and track sessions
let session_id = manager.connect_client(&server_pk, epoch, None).await?;

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

### First contact (TOFU or OOB token)

* Pattern: `XX`.
* Client: `NoiseClient::build_initiator_xx_tofu(hint) -> (HandshakeState, first_msg)`.
* Server: `NoiseServer::build_responder_read_xx(first_msg) -> HandshakeState`.
* Caller pins the server static post-handshake through an out-of-band path, then uses IK for future connections.

### Pinned server static

* Pattern: `IK`.
* Client: `NoiseClient::build_initiator_ik_direct(server_static_pub, epoch, hint) -> (HandshakeState, first_msg, epoch)`.
* Server: `NoiseServer::build_responder_read_ik(first_msg) -> (HandshakeState, IdentityPayload)`.

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
let server_static_pk: [u8;32] = [0; 32]; // mocked

// client creates first message
let (mut c_link, used_epoch, first_msg) = client_start_ik_direct(&client, &server_static_pk, 3, None)?;

// server accepts and returns a transport link and client identity payload
let (mut s_link, client_id) = server_accept_ik(&server, &first_msg)?;

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

* `Zeroizing` reduces lifetime of secrets in memory but cannot guarantee full eradication across OS subsystems. For servers, enable `secure-mem` and run under minimal privileges.
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

## Versioning

* `0.7.x`: Added mobile-optimized manager, thread-safe wrappers, retry logic, and structured error codes.
* `0.6.x`: Added session management, streaming, and storage queue features.
* `0.y.z`: Bump minor when you change field order or digest binding.
* Bump patch for internal refactors and tests.
