# src

Rust crate implementation for `pubky-noise`.

High-level modules:

- `client.rs` / `server.rs`: Noise handshake logic and session establishment.
- `session_manager.rs` / `mobile_manager.rs`: Session lifecycle helpers for multi-session and mobile usage.
- `kdf.rs` / `ring.rs`: Key derivation and key-provider abstractions.
- `ffi/`: UniFFI-exposed APIs and types.
- `storage_queue.rs`: Optional storage-backed messaging (feature-gated).
- `transport.rs` / `streaming.rs`: Transport adapters and streaming/chunking helpers.


