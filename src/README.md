# Source Code Structure

This directory contains the core `pubky-noise` library source code.

## Modules

### Core API

| Module | Description |
|--------|-------------|
| `lib.rs` | Crate root with public exports |
| `sender.rs` | `NoiseSender` - Raw-key client/initiator API (recommended) |
| `receiver.rs` | `NoiseReceiver` - Raw-key server/responder API (recommended) |
| `client.rs` | `NoiseClient` - Legacy Ring-based client API |
| `server.rs` | `NoiseServer` - Legacy Ring-based server API |

### Session Management

| Module | Description |
|--------|-------------|
| `transport.rs` | `NoiseSession` - Transport-mode encrypted session |
| `session_id.rs` | `SessionId` - Unique session identifier |
| `session_manager.rs` | `NoiseSessionManager` - Multi-session management |
| `mobile_manager.rs` | `NoiseManager`, `RawNoiseManager` - Mobile-optimized managers |
| `streaming.rs` | `StreamingNoiseSession` - Chunked message streaming |

### Cryptography

| Module | Description |
|--------|-------------|
| `kdf.rs` | Key derivation functions (HKDF-SHA512) |
| `identity_payload.rs` | Ed25519 identity binding for handshakes |
| `ring.rs` | `RingKeyProvider` trait and `DummyRing` implementation |
| `pubky_ring.rs` | `PubkyRingProvider` (requires `pubky-sdk` feature) |

### Adapters & Utilities

| Module | Description |
|--------|-------------|
| `datalink_adapter.rs` | Convenience functions for handshakes |
| `errors.rs` | `NoiseError` and `NoiseErrorCode` types |
| `storage_queue.rs` | `StorageBackedMessaging` (requires `storage-queue` feature) |

### FFI

| Module | Description |
|--------|-------------|
| `ffi/` | Foreign Function Interface bindings |
| `pubky_noise.udl` | UniFFI interface definition |

## Feature Flags

- `default = []` - Core library only
- `trace` - Enable tracing/logging
- `secure-mem` - Page locking for sensitive memory
- `pubky-sdk` - Pubky SDK integration (`PubkyRingProvider`)
- `storage-queue` - Async storage-backed messaging
- `uniffi_macros` - FFI binding generation

