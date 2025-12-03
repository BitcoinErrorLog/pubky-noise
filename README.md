# pubky-noise

Direct client↔server Noise sessions for Pubky using `snow`. Minimal, direct-only transport layer.

## Goals

* Direct transport first: XX for first contact, IK when the server static is pinned or delivered OOB.
* Keep keys cold: X25519 statics are derived on demand and passed directly to `snow` without living in app buffers.
* Simple integration: tiny DataLink-style adapter with `encrypt` and `decrypt`.
* App-layer binding: export a session tag to bind Paykit and Locks messages to the live channel.
* Footgun defenses: reject invalid peer statics that would yield an all-zero X25519 shared secret.

## What this crate is

* A thin, conservative wrapper around `snow` with Pubky ergonomics.
* **Two API options**: Raw-key API (`NoiseSender`/`NoiseReceiver`) or Ring-based API (`NoiseClient`/`NoiseServer`).
* A set of helpers for XX and IK patterns, identity binding, and a minimal adapter.

## What this crate is not

* Not a reimplementation of Noise.
* Not a messaging protocol or a full RPC layer.
* Not a key discovery/PKARR transport - applications handle key exchange out-of-band.

## Specs and suites

* Noise revision: 34 (as implemented by current `snow`).
* Suites: `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
* Hash: BLAKE2s. AEAD: ChaCha20-Poly1305. DH: X25519.

## Features

* `default = []`: direct-only, no extra dependencies.
* `trace`: opt-in `tracing` and `hex` for non-sensitive logs.
* `secure-mem`: opt-in best-effort page pinning and DONTDUMP on supported OSes (server side).
* `pubky-sdk`: Convenience wrapper for `RingKeyProvider` using Pubky SDK `Keypair`.
* `storage-queue`: Support for storage-backed messaging using Pubky storage as a queue (requires `pubky` and `async-trait`).

## Key handling model

* Device X25519 static is derived per device using HKDF and a seed available to Ring. The secret is created inside a closure and passed directly to `snow::Builder::local_private_key` via `secrecy::Zeroizing<[u8;32]>`.
* The app never stores the raw secret beyond the closure scope. No logs, no clones, no return of the secret to caller code.
* Key rotation is handled at the application layer (e.g., via PKARR key updates). The library itself is stateless.

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

// Connect with 3-step handshake
let (session_id, first_msg) = manager.initiate_connection(&server_pk)?;
// Send first_msg over transport, receive response...
let session_id = manager.complete_connection(&session_id, &response)?;

// Save state before app suspension
let state = manager.save_state(&session_id)?;
// ... persist state ...

// Restore after app resume
manager.restore_state(state)?;
```

See [docs/MOBILE_INTEGRATION.md](docs/MOBILE_INTEGRATION.md) for complete mobile integration guide.

### Streaming / Chunking
For messages larger than the Noise packet limit, use `StreamingNoiseSession` to automatically split and reassemble chunks.

```rust
let mut streaming = StreamingNoiseSession::new_with_default_chunk_size(session);

// Framed mode (recommended) - handles length-prefix framing automatically
let framed_bytes = streaming.encrypt_framed(large_data)?;
// Send framed_bytes over transport...
let plaintext = streaming.decrypt_framed(&received_bytes)?;

// Legacy mode - returns separate chunks (caller handles framing)
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

## Handshake Flows

### First contact (TOFU or OOB token)

* Pattern: `XX`.
* Client: `NoiseClient::build_initiator_xx_tofu() -> (HandshakeState, first_msg)`.
* Server: `NoiseServer::build_responder_read_xx(first_msg) -> HandshakeState`.
* Caller pins the server static post-handshake through an out-of-band path, then uses IK for future connections.

### Pinned server static

* Pattern: `IK`.
* Client: `NoiseClient::build_initiator_ik_direct(server_static_pub) -> (HandshakeState, first_msg)`.
* Server: `NoiseServer::build_responder_read_ik(first_msg) -> (HandshakeState, IdentityPayload)`.

### Raw-Key API

* Client: `NoiseSender::initiate_ik(x25519_sk, ed25519_pub, server_pk, sign_fn) -> (HandshakeState, first_msg)`.
* Server: `NoiseReceiver::respond_ik(x25519_sk, first_msg) -> (HandshakeState, IdentityPayload, response)`.

## Cold Key Architecture (pkarr Integration)

For scenarios where Ed25519 identity keys are kept cold (offline), pubky-noise supports patterns that don't require handshake-time signing. Identity binding is provided externally via pkarr.

### How It Works

1. **Publish X25519 key via pkarr** (one-time, offline signing):
   - Sign pkarr record with cold Ed25519: "My Noise X25519: [key]"
   - Publish to DHT

2. **Connect using raw IK pattern** (no handshake signing):
   - Look up peer's X25519 from pkarr (already authenticated by Ed25519 signature)
   - Use `initiate_ik_raw()` - identity already proven by pkarr

### Pattern Selection Guide

| Pattern | Use Case | Identity Binding | Ed25519 Access |
|---------|----------|------------------|----------------|
| **IK** | Hot keys, real-time sessions | In handshake | Required at handshake |
| **IK-raw** | Cold keys + pkarr | Via pkarr (pre-signed) | Not required |
| **N** | Anonymous client, known server | Server only (via pkarr) | Not required |
| **NN** | Post-handshake auth | External (application layer) | Not required |
| **XX** | Trust-on-first-use | Both parties during handshake | Optional |

### Cold Key Example

```rust
use pubky_noise::{NoiseSender, NoiseReceiver, NoiseSession, kdf, datalink_adapter};
use zeroize::Zeroizing;

// === COLD KEY SCENARIO ===
// Ed25519 key is cold - only used once to sign pkarr record
// X25519 key is derived and published via pkarr

// Client: Look up server's X25519 from pkarr (already Ed25519-signed)
let server_pk = lookup_pkarr("server_pubkey"); // [u8; 32] from pkarr

// Derive local X25519 key
let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&seed, b"device"));

// Initiate IK-raw (no Ed25519 signing needed!)
let (hs, first_msg) = datalink_adapter::start_ik_raw(&x25519_sk, &server_pk)?;

// Server: Accept IK-raw
let server_sk = Zeroizing::new(kdf::derive_x25519_static(&server_seed, b"server"));
let (s_hs, response) = datalink_adapter::accept_ik_raw(&server_sk, &first_msg)?;

// Complete handshakes
let client_session = datalink_adapter::complete_raw(hs, &response)?;
let server_session = NoiseSession::from_handshake(s_hs)?;
```

### Using RawNoiseManager

For applications using cold keys, `RawNoiseManager` provides pattern selection:

```rust
use pubky_noise::{RawNoiseManager, NoisePattern, MobileConfig, kdf};
use zeroize::Zeroizing;

let mut manager = RawNoiseManager::new(MobileConfig::default());

// Connect with IK-raw pattern (cold key scenario)
let x25519_sk = Zeroizing::new(kdf::derive_x25519_static(&seed, b"device"));
let server_pk = [0u8; 32]; // From pkarr

let (session_id, first_msg) = manager.initiate_connection_with_pattern(
    Some(&x25519_sk),
    Some(&server_pk),
    NoisePattern::IKRaw,
)?;

// Or use NN for fully anonymous with post-handshake attestation
let (session_id, first_msg) = manager.initiate_connection_with_pattern(
    None,  // No local key for NN
    None,  // No server key for NN
    NoisePattern::NN,
)?;
```

## Quick Start

### Build and test

```bash
cargo build
cargo test
```

### Raw-Key API (Recommended)

The new raw-key API gives you full control over key derivation at the application layer:

```rust
use pubky_noise::{NoiseSender, NoiseReceiver, NoiseSession, kdf};
use zeroize::Zeroizing;

// === CLIENT SIDE ===
// App derives keys from Ed25519 seed
let client_seed = [1u8; 32]; // Your Ed25519 seed
let client_x25519_sk = Zeroizing::new(
    kdf::derive_x25519_static(&client_seed, b"device-id")
);
let client_ed25519_pk = kdf::derive_ed25519_public(&client_seed);
let server_pk = [0u8; 32]; // Server's X25519 public key (from pinning)

// Initiate IK handshake
let sender = NoiseSender::new();
let (client_hs, first_msg) = sender.initiate_ik(
    &client_x25519_sk,
    &client_ed25519_pk,
    &server_pk,
    |binding_msg| {
        // Sign binding message with your Ed25519 key
        // (Use your app's signing mechanism)
        ed25519_sign(&client_seed, binding_msg)
    },
)?;

// Send first_msg to server, receive response...

// === SERVER SIDE ===
let server_seed = [2u8; 32];
let server_x25519_sk = Zeroizing::new(
    kdf::derive_x25519_static(&server_seed, b"server-device")
);

let receiver = NoiseReceiver::new();
let (mut server_hs, client_identity, response) = receiver.respond_ik(&server_x25519_sk, &first_msg)?;

// Verify client identity
println!("Client Ed25519: {:?}", client_identity.ed25519_pub);

// Convert to transport sessions
let mut client_session = NoiseSession::from_handshake(client_hs)?;
let mut server_session = NoiseSession::from_handshake(server_hs)?;

// Encrypt/decrypt
let ct = client_session.write(b"hello")?;
let pt = server_session.read(&ct)?;
```

### Legacy Ring-Based API

For applications using `RingKeyProvider` for key management:

```rust
use std::sync::Arc;
use pubky_noise::{NoiseClient, NoiseServer, DummyRing};
use pubky_noise::datalink_adapter::{client_start_ik_direct, server_accept_ik, client_complete_ik, server_complete_ik};

let ring_client = Arc::new(DummyRing::new([1u8; 32], "kid"));
let ring_server = Arc::new(DummyRing::new([2u8; 32], "kid"));

let client = NoiseClient::<_>::new_direct("kid", b"dev-client", ring_client);
let server = NoiseServer::<_>::new_direct("kid", b"dev-server", ring_server.clone());

// Server static key (from pinning or OOB)
let server_sk = ring_server.derive_device_x25519("kid", b"dev-server").unwrap();
let server_static_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

// 3-step handshake
// Step 1: Client initiates
let (c_hs, first_msg) = client_start_ik_direct(&client, &server_static_pk)?;

// Step 2: Server accepts and responds
let (s_hs, client_id, response) = server_accept_ik(&server, &first_msg)?;

// Step 3: Both complete
let mut c_session = client_complete_ik(c_hs, &response)?;
let mut s_session = server_complete_ik(s_hs)?;

// Encrypt/decrypt
let ct = c_session.encrypt(b"hello")?;
let pt = s_session.decrypt(&ct)?;
```

## Migration Guide

### From 0.7.x to 0.8.x

**API Changes:**

1. **`server_hint` and `epoch` removed**: These parameters have been removed from all APIs. Noise's built-in replay protection is sufficient.

   ```rust
   // OLD
   client.build_initiator_ik_direct(&server_pk)?;
   
   // NEW - same, epoch is no longer needed
   client.build_initiator_ik_direct(&server_pk)?;
   ```

2. **`NoiseTransport` renamed to `NoiseSession`**: The old name is still available as a deprecated alias.

   ```rust
   // OLD
   use pubky_noise::NoiseTransport;
   
   // NEW (recommended)
   use pubky_noise::NoiseSession;
   ```

3. **New raw-key API**: `NoiseSender`/`NoiseReceiver` provide a simpler API when you manage keys yourself.

4. **Framed streaming**: Use `encrypt_framed`/`decrypt_framed` instead of `encrypt_streaming`/`decrypt_streaming` for automatic length-prefix framing.

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

* `0.8.x`: Added raw-key API (`NoiseSender`/`NoiseReceiver`), renamed `NoiseTransport` to `NoiseSession`, removed `server_hint`, added framed streaming.
* `0.7.x`: Added mobile-optimized manager, thread-safe wrappers, retry logic, and structured error codes.
* `0.6.x`: Added session management, streaming, and storage queue features.
* `0.y.z`: Bump minor when you change field order or digest binding.
* Bump patch for internal refactors and tests.
