# Test Suite

This directory contains integration and unit tests for `pubky-noise`.

## Test Files

### Core Protocol Tests

| Test File | Description |
|-----------|-------------|
| `sender_receiver.rs` | Raw-key API (`NoiseSender`/`NoiseReceiver`) |
| `adapter_demo.rs` | `datalink_adapter` convenience functions |
| `cold_key_patterns.rs` | IK-raw, N, NN patterns for cold keys |
| `invalid_peer.rs` | Invalid/weak key rejection |
| `session_id.rs` | Session ID derivation and uniqueness |

### Identity & Cryptography

| Test File | Description |
|-----------|-------------|
| `identity_payload.rs` | Identity binding and signatures |
| `identity_payload_tests.rs` | Identity payload edge cases |
| `property_tests.rs` | Property-based crypto tests |
| `kdf_tests.rs` | Key derivation function tests |

### Session Management

| Test File | Description |
|-----------|-------------|
| `mobile_integration.rs` | Mobile-optimized manager tests |
| `storage_queue.rs` | Storage-backed messaging |
| `storage_queue_comprehensive.rs` | Comprehensive queue tests |

### FFI Layer

| Test File | Description |
|-----------|-------------|
| `ffi_smoke.rs` | Basic FFI sanity checks |
| `ffi_integration.rs` | FFI integration tests |
| `ffi_comprehensive.rs` | Comprehensive FFI tests |

## Running Tests

```bash
# Run all tests
cargo test --all

# Run specific test file
cargo test --test cold_key_patterns

# Run with all features
cargo test --all-features

# Run doc tests only
cargo test --doc
```

## Test Coverage

- **140+ unit tests**
- **42 doc tests**
- **100% pass rate required**

## Notes

- Tests use `DummyRing` for key management (not production keys)
- FFI tests require `uniffi_macros` feature
- Storage tests require `storage-queue` feature

