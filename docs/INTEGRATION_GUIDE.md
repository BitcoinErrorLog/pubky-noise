# Pubky Noise Integration Guide

This guide covers integrating the Pubky Noise library into your application for secure, authenticated communication.

## Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pubky-noise = "0.7"
```

### Basic Usage

```rust
use pubky_noise::prelude::*;
use std::sync::Arc;

// Create key providers
let client_ring = Arc::new(DummyRing::new([1u8; 32], "client_kid"));
let server_ring = Arc::new(DummyRing::new([2u8; 32], "server_kid"));

// Create client and server
let client = NoiseClient::<_, ()>::new_direct("client_kid", b"device", client_ring);
let server = NoiseServer::<_, ()>::new_direct("server_kid", b"device", server_ring);
```

## Core Concepts

### Key Providers

The `RingKeyProvider` trait provides cryptographic keys for the Noise handshake:

```rust
pub trait RingKeyProvider: Send + Sync {
    fn get_private_key(&self) -> Result<[u8; 32], NoiseError>;
    fn get_public_key(&self) -> Result<[u8; 32], NoiseError>;
    fn get_key_id(&self) -> &str;
}
```

For testing, use `DummyRing`. For production, implement this trait with secure key storage.

### Handshake Patterns

**IK Pattern** (known server key):
- Client already knows the server's static public key
- Faster handshake (2 messages instead of 3)
- Use when connecting to known servers

**XX Pattern** (trust-on-first-use):
- Neither party knows the other's key in advance
- 3-message handshake
- Use for peer-to-peer connections

### Error Handling

All errors are typed and include error codes for FFI compatibility:

```rust
use pubky_noise::{NoiseError, NoiseErrorCode};

match result {
    Err(e) => {
        let code = e.code();  // For FFI/mobile
        let msg = e.message(); // Human-readable
        
        if e.is_retryable() {
            if let Some(delay) = e.retry_after_ms() {
                // Wait and retry
            }
        }
    }
    Ok(value) => { /* success */ }
}
```

### Rate Limiting

Protect your server from DoS attacks:

```rust
use pubky_noise::{RateLimiter, RateLimiterConfig};

// Use default config or customize
let limiter = RateLimiter::new(RateLimiterConfig::default());

// Or use predefined configs
let strict = RateLimiter::new(RateLimiterConfig::strict());
let lenient = RateLimiter::new(RateLimiterConfig::lenient());

// Check before accepting connections
let client_ip = "192.168.1.1".parse().unwrap();
if limiter.check_and_record(&client_ip) {
    // Accept connection
} else {
    // Reject - rate limited
}
```

## Mobile Integration

### Using NoiseManager

The `NoiseManager` provides a high-level API for mobile applications:

```rust
use pubky_noise::{NoiseManager, MobileConfig, ConnectionStatus};

let config = MobileConfig {
    auto_reconnect: true,
    reconnect_interval_ms: 5000,
    max_reconnect_attempts: 10,
    // ...
};

let manager = NoiseManager::new(config, key_provider);
```

### FFI Bindings

Enable UniFFI bindings with the `uniffi_macros` feature:

```toml
[dependencies]
pubky-noise = { version = "0.7", features = ["uniffi_macros"] }
```

## Session Management

### Session IDs

Sessions are identified by a unique 64-bit ID:

```rust
use pubky_noise::SessionId;

let session = SessionId::new();
println!("Session: {}", session.id());
```

### Thread-Safe Session Manager

For multi-threaded applications:

```rust
use pubky_noise::{ThreadSafeSessionManager, NoiseRole};
use std::sync::Arc;

let manager = Arc::new(ThreadSafeSessionManager::new());

// Add a session
manager.add_session(session_id, noise_link, NoiseRole::Initiator);

// Get and use a session
if let Some(session) = manager.get_session(&session_id) {
    // Use the session
}
```

## Storage-Backed Messaging

For reliable message delivery with persistence (requires `storage-queue` feature):

```rust
use pubky_noise::{StorageBackedMessaging, MessageQueue, RetryConfig};

let queue = MessageQueue::new(storage_backend);
let retry_config = RetryConfig {
    max_retries: 5,
    base_delay_ms: 1000,
    max_delay_ms: 30000,
};
```

## Security Considerations

1. **Key Storage**: Never hardcode private keys. Use secure storage (Keychain/Keystore).

2. **Rate Limiting**: Always enable rate limiting on servers.

3. **Session Expiry**: Configure appropriate session timeouts.

4. **Error Messages**: Don't expose internal error details to clients.

## Examples

See the `examples/` directory for complete working examples:

- `basic_handshake.rs` - Simple client-server handshake
- `xx_pattern.rs` - XX pattern handshake
- `streaming.rs` - Streaming data over Noise
- `server_example.rs` - Production server setup
- `mobile_manager.rs` - Mobile app integration
- `storage_queue.rs` - Reliable messaging with storage

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `RateLimited` | Too many connection attempts | Wait and retry with backoff |
| `IdentityVerify` | Key verification failed | Check keys match expected |
| `Timeout` | Connection timed out | Check network, increase timeout |
| `RemoteStaticMissing` | Server key not available | Use XX pattern or fetch key first |

### Debug Logging

Enable tracing for debugging:

```rust
// Add tracing subscriber in your app
tracing_subscriber::fmt::init();
```

## API Reference

See the [API documentation](https://docs.rs/pubky-noise) for complete reference.
